package caddy_waf_t1k

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/chaitin/t1k-go"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

func TestClassifyConnectionError(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		expected string
	}{
		{"connection refused", errors.New("dial tcp 10.0.0.1:8000: connect: connection refused"), reasonConnectionRefused},
		{"dial timeout", errors.New("dial tcp 10.0.0.1:8000: i/o timeout"), reasonDialTimeout},
		{"broken pipe", errors.New("write: broken pipe"), reasonBrokenPipe},
		{"max active reached", errors.New("max active connections reached"), reasonMaxActiveReached},
		{"pool closed", errors.New("pool is closed"), reasonPoolClosed},
		{"client error", errors.New("context canceled"), reasonClientError},
		{"other engine error", errors.New("something unexpected"), reasonOther},
		{"nil error", nil, reasonOther},
		{"client body connection reset", errors.New("read request body: read tcp 1.2.3.4:443->5.6.7.8:12345: read: connection reset by peer"), reasonClientError},
		{"engine-side connection reset", errors.New("read tcp 192.0.2.1:56702->198.51.100.10:8000: read: connection reset by peer"), reasonOther},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := classifyConnectionError(tt.err)
			if got != tt.expected {
				t.Errorf("classifyConnectionError(%v) = %q, want %q", tt.err, got, tt.expected)
			}
		})
	}
}

// testMetricsEngine builds an Engine backed by a dial-free idle Connection pool
// (InitialCap 0 dials nothing) so update() can read real pool stats in tests.
func testMetricsEngine(addr string) *Engine {
	pool, err := t1k.NewChannelPool(&t1k.PoolConfig{
		InitialCap:  0,
		MaxIdle:     1,
		MaxCap:      1,
		Factory:     &t1k.TcpFactory{Addr: addr},
		IdleTimeout: 30 * time.Second,
	})
	if err != nil {
		panic(err)
	}
	return &Engine{pool: pool, addr: addr, maxFails: 1, failDuration: 30 * time.Second}
}

func testMetricsEngineConstructor(addr string) caddy.Constructor {
	return func() (caddy.Destructor, error) { return testMetricsEngine(addr), nil }
}

// cleanupEngineSeries removes every gauge and counter series a test may have
// created for the given Engine addresses so later tests never see stale series.
func cleanupEngineSeries(t *testing.T, addrs ...string) {
	t.Helper()
	for _, addr := range addrs {
		labels := prometheus.Labels{"engine": addr}
		wafMetrics.enginesHealthy.DeletePartialMatch(labels)
		wafMetrics.poolIdleConns.DeletePartialMatch(labels)
		wafMetrics.poolActiveConns.DeletePartialMatch(labels)
		wafMetrics.poolMaxConns.DeletePartialMatch(labels)
		wafMetrics.poolWaitingReqs.DeletePartialMatch(labels)
		wafMetrics.connectionErrors.DeletePartialMatch(labels)
		wafMetrics.poolEvents.DeletePartialMatch(labels)
	}
}

func TestMetricsUpdaterSyncPoolEvents(t *testing.T) {
	registry := prometheus.NewRegistry()
	initWAFMetrics(registry)
	t.Cleanup(func() { cleanupEngineSeries(t, "127.0.0.1:8001") })

	engine := testEngine("127.0.0.1:8001")
	updater := &globalMetricsUpdater{eventState: make(map[*Engine]*enginePoolEventState)}

	stats := t1k.PoolStats{
		DialFailed:    2,
		IdleExpired:   1,
		PingFailed:    3,
		PoolFullClose: 4,
		MaxActiveHit:  5,
	}

	updater.syncPoolEvents(engine, stats)
	state := updater.eventState[engine]
	if state == nil {
		t.Fatal("no event state recorded for the Engine")
	}
	if state.last != [poolEventReasons]uint64{2, 1, 3, 4, 5} {
		t.Fatalf("unexpected state after first sync: %+v", state.last)
	}

	// A second sync with unchanged counters adds no extra pool events.
	updater.syncPoolEvents(engine, stats)
	want := [poolEventReasons]float64{2, 1, 3, 4, 5}
	for i, reason := range poolEventReasonNames {
		if got := testutil.ToFloat64(wafMetrics.poolEvents.WithLabelValues("127.0.0.1:8001", reason)); got != want[i] {
			t.Errorf("pool_events_total %s = %v, want %v", reason, got, want[i])
		}
	}

	// Advancing one counter increments that reason once.
	stats.DialFailed = 3
	updater.syncPoolEvents(engine, stats)
	if state.last[0] != 3 {
		t.Errorf("DialFailed last = %d, want 3", state.last[0])
	}
	if got := testutil.ToFloat64(wafMetrics.poolEvents.WithLabelValues("127.0.0.1:8001", "dial_failed")); got != 3 {
		t.Errorf("pool_events_total dial_failed = %v, want 3", got)
	}
}

func TestMetricsUpdaterPoolEventsAccumulateAcrossEngines(t *testing.T) {
	registry := prometheus.NewRegistry()
	initWAFMetrics(registry)
	const addr = "127.0.0.1:8007"
	t.Cleanup(func() { cleanupEngineSeries(t, addr) })

	// Two independent Engines (config-diff isolation) share one address; their
	// pool events accumulate into the same per-address series.
	e1 := testEngine(addr)
	e2 := testEngine(addr)
	updater := &globalMetricsUpdater{eventState: make(map[*Engine]*enginePoolEventState)}

	updater.syncPoolEvents(e1, t1k.PoolStats{DialFailed: 1})
	updater.syncPoolEvents(e2, t1k.PoolStats{DialFailed: 1})

	if got := testutil.ToFloat64(wafMetrics.poolEvents.WithLabelValues(addr, "dial_failed")); got != 2 {
		t.Fatalf("pool_events_total dial_failed = %v, want 2 (accumulated across Engines)", got)
	}
}

func TestRecordConnectionErrorSharedEngineSingleCounter(t *testing.T) {
	registry := prometheus.NewRegistry()
	initWAFMetrics(registry)
	const addr = "127.0.0.1:8004"
	t.Cleanup(func() { cleanupEngineSeries(t, addr) })

	// A shared Engine failing on two requests (across instances) increments one
	// counter for that Engine address and reason.
	recordConnectionError(addr, reasonConnectionRefused)
	recordConnectionError(addr, reasonConnectionRefused)
	recordConnectionError(addr, reasonBrokenPipe)

	expected := strings.NewReader(`
		# HELP caddy_waf_connection_errors_total Total number of WAF detection connection errors by reason.
		# TYPE caddy_waf_connection_errors_total counter
		caddy_waf_connection_errors_total{engine="127.0.0.1:8004",reason="broken_pipe"} 1
		caddy_waf_connection_errors_total{engine="127.0.0.1:8004",reason="connection_refused"} 2
	`)
	if err := testutil.GatherAndCompare(registry, expected, "caddy_waf_connection_errors_total"); err != nil {
		t.Fatalf("GatherAndCompare: %v", err)
	}
}

func TestMetricsUpdaterSharedEngineSingleSeries(t *testing.T) {
	registry := prometheus.NewRegistry()
	initWAFMetrics(registry)
	const addr = "127.0.0.1:8003"
	t.Cleanup(func() { cleanupEngineSeries(t, addr) })

	// Two instances with identical address+config acquire the same Engine.
	key := testEngineKey(addr)
	e1, _, err := acquireEngine(key, testMetricsEngineConstructor(addr))
	if err != nil {
		t.Fatalf("first acquire: %v", err)
	}
	defer func() { _, _ = releaseEngine(key) }()
	e2, _, err := acquireEngine(key, testMetricsEngineConstructor(addr))
	if err != nil {
		t.Fatalf("second acquire: %v", err)
	}
	defer func() { _, _ = releaseEngine(key) }()
	if e1 != e2 {
		t.Fatal("identical address+config must share one Engine")
	}

	updater := &globalMetricsUpdater{eventState: make(map[*Engine]*enginePoolEventState)}
	updater.update()

	expected := strings.NewReader(`
		# HELP caddy_waf_engines_healthy Health status of WAF engines.
		# TYPE caddy_waf_engines_healthy gauge
		caddy_waf_engines_healthy{engine="127.0.0.1:8003"} 1
		# HELP caddy_waf_pool_active_conns Number of active connections in the WAF engine pool.
		# TYPE caddy_waf_pool_active_conns gauge
		caddy_waf_pool_active_conns{engine="127.0.0.1:8003"} 0
		# HELP caddy_waf_pool_idle_conns Number of idle connections in the WAF engine pool.
		# TYPE caddy_waf_pool_idle_conns gauge
		caddy_waf_pool_idle_conns{engine="127.0.0.1:8003"} 0
		# HELP caddy_waf_pool_max_conns Maximum number of connections allowed in the WAF engine pool.
		# TYPE caddy_waf_pool_max_conns gauge
		caddy_waf_pool_max_conns{engine="127.0.0.1:8003"} 1
		# HELP caddy_waf_pool_waiting_requests Number of requests waiting for an available WAF engine connection.
		# TYPE caddy_waf_pool_waiting_requests gauge
		caddy_waf_pool_waiting_requests{engine="127.0.0.1:8003"} 0
	`)
	if err := testutil.GatherAndCompare(registry, expected,
		"caddy_waf_engines_healthy",
		"caddy_waf_pool_active_conns",
		"caddy_waf_pool_idle_conns",
		"caddy_waf_pool_max_conns",
		"caddy_waf_pool_waiting_requests",
	); err != nil {
		t.Fatalf("GatherAndCompare: %v", err)
	}

	// Exactly one series per Engine address: deleting it leaves nothing.
	if deleted := wafMetrics.enginesHealthy.DeletePartialMatch(prometheus.Labels{"engine": addr}); deleted != 1 {
		t.Fatalf("engines_healthy series = %d, want exactly 1 for a shared Engine", deleted)
	}
	if deleted := wafMetrics.enginesHealthy.DeletePartialMatch(prometheus.Labels{"engine": addr}); deleted != 0 {
		t.Fatalf("engines_healthy still reports %d series after deleting the single one", deleted)
	}
}

func TestMetricsUpdaterOneSeriesPerEngine(t *testing.T) {
	registry := prometheus.NewRegistry()
	initWAFMetrics(registry)

	keys := []engineKey{
		testEngineKey("127.0.0.1:8005"),
		testEngineKey("127.0.0.1:8006"),
	}
	// Register the release before acquiring so an acquire failure cannot leak
	// already-acquired Engines into the process-wide registry; release only
	// keys that were actually acquired.
	var acquired []engineKey
	t.Cleanup(func() {
		for _, key := range acquired {
			if _, err := releaseEngine(key); err != nil {
				t.Errorf("release %s: %v", key.addr, err)
			}
		}
	})
	for _, key := range keys {
		if _, _, err := acquireEngine(key, testMetricsEngineConstructor(key.addr)); err != nil {
			t.Fatalf("acquire %s: %v", key.addr, err)
		}
		acquired = append(acquired, key)
	}
	t.Cleanup(func() { cleanupEngineSeries(t, "127.0.0.1:8005", "127.0.0.1:8006") })

	updater := &globalMetricsUpdater{eventState: make(map[*Engine]*enginePoolEventState)}
	updater.update()

	expected := strings.NewReader(`
		# HELP caddy_waf_engines_healthy Health status of WAF engines.
		# TYPE caddy_waf_engines_healthy gauge
		caddy_waf_engines_healthy{engine="127.0.0.1:8005"} 1
		caddy_waf_engines_healthy{engine="127.0.0.1:8006"} 1
	`)
	if err := testutil.GatherAndCompare(registry, expected, "caddy_waf_engines_healthy"); err != nil {
		t.Fatalf("GatherAndCompare: %v", err)
	}
}

func TestWAFMetricsRegistration(t *testing.T) {
	registry := prometheus.NewRegistry()
	initWAFMetrics(registry)
	t.Cleanup(func() { cleanupEngineSeries(t, "127.0.0.1:8000") })

	wafMetrics.requestsTotal.WithLabelValues("passed").Inc()
	wafMetrics.detectDuration.WithLabelValues("127.0.0.1:8000").Observe(0.01)
	wafMetrics.enginesHealthy.WithLabelValues("127.0.0.1:8000").Set(1)
	wafMetrics.poolIdleConns.WithLabelValues("127.0.0.1:8000").Set(2)
	wafMetrics.poolActiveConns.WithLabelValues("127.0.0.1:8000").Set(4)
	wafMetrics.poolMaxConns.WithLabelValues("127.0.0.1:8000").Set(8)
	wafMetrics.poolWaitingReqs.WithLabelValues("127.0.0.1:8000").Set(0)
	recordConnectionError("127.0.0.1:8000", reasonConnectionRefused)
	wafMetrics.poolEvents.WithLabelValues("127.0.0.1:8000", "dial_failed").Inc()
	wafMetrics.oversizeRequests.Inc()

	expected := strings.NewReader(`
		# HELP caddy_waf_connection_errors_total Total number of WAF detection connection errors by reason.
		# TYPE caddy_waf_connection_errors_total counter
		caddy_waf_connection_errors_total{engine="127.0.0.1:8000",reason="connection_refused"} 1
		# HELP caddy_waf_engines_healthy Health status of WAF engines.
		# TYPE caddy_waf_engines_healthy gauge
		caddy_waf_engines_healthy{engine="127.0.0.1:8000"} 1
		# HELP caddy_waf_oversize_requests_total Total requests whose body was truncated for WAF detection.
		# TYPE caddy_waf_oversize_requests_total counter
		caddy_waf_oversize_requests_total 1
		# HELP caddy_waf_pool_active_conns Number of active connections in the WAF engine pool.
		# TYPE caddy_waf_pool_active_conns gauge
		caddy_waf_pool_active_conns{engine="127.0.0.1:8000"} 4
		# HELP caddy_waf_pool_idle_conns Number of idle connections in the WAF engine pool.
		# TYPE caddy_waf_pool_idle_conns gauge
		caddy_waf_pool_idle_conns{engine="127.0.0.1:8000"} 2
		# HELP caddy_waf_pool_max_conns Maximum number of connections allowed in the WAF engine pool.
		# TYPE caddy_waf_pool_max_conns gauge
		caddy_waf_pool_max_conns{engine="127.0.0.1:8000"} 8
		# HELP caddy_waf_pool_waiting_requests Number of requests waiting for an available WAF engine connection.
		# TYPE caddy_waf_pool_waiting_requests gauge
		caddy_waf_pool_waiting_requests{engine="127.0.0.1:8000"} 0
		# HELP caddy_waf_requests_total Total number of requests processed by the WAF.
		# TYPE caddy_waf_requests_total counter
		caddy_waf_requests_total{action="passed"} 1
	`)

	if err := testutil.GatherAndCompare(registry, expected,
		"caddy_waf_connection_errors_total",
		"caddy_waf_engines_healthy",
		"caddy_waf_oversize_requests_total",
		"caddy_waf_pool_active_conns",
		"caddy_waf_pool_idle_conns",
		"caddy_waf_pool_max_conns",
		"caddy_waf_pool_waiting_requests",
		"caddy_waf_requests_total",
	); err != nil {
		t.Fatalf("GatherAndCompare: %v", err)
	}

	if got := testutil.ToFloat64(wafMetrics.poolEvents.WithLabelValues("127.0.0.1:8000", "dial_failed")); got < 1 {
		t.Fatalf("pool_events_total dial_failed = %v, want >= 1", got)
	}
}

// TestReportEngineSkipsDestroyedEngine proves the updater does not recreate a
// gauge series for an Engine whose Destruct already removed it (the teardown /
// updater race). The series deleted by Destruct stays deleted.
func TestReportEngineSkipsDestroyedEngine(t *testing.T) {
	registry := prometheus.NewRegistry()
	initWAFMetrics(registry)
	addr := "127.0.0.1:8010"
	t.Cleanup(func() { cleanupEngineSeries(t, addr) })

	e := testMetricsEngine(addr)
	updater := &globalMetricsUpdater{eventState: make(map[*Engine]*enginePoolEventState)}

	// A live Engine reports its series.
	updater.reportEngine(e)
	if got := testutil.ToFloat64(wafMetrics.enginesHealthy.WithLabelValues(addr)); got != 1 {
		t.Fatalf("live Engine health = %v, want 1", got)
	}

	// After Destruct the series are gone; a late reportEngine must not recreate
	// them.
	if err := e.Destruct(); err != nil {
		t.Fatalf("Destruct: %v", err)
	}
	if deleted := wafMetrics.enginesHealthy.DeletePartialMatch(prometheus.Labels{"engine": addr}); deleted != 0 {
		t.Fatalf("series not removed by Destruct (found %d), want 0", deleted)
	}
	updater.reportEngine(e)
	if got := testutil.ToFloat64(wafMetrics.enginesHealthy.WithLabelValues(addr)); got != 0 {
		t.Fatalf("destroyed Engine health = %v, want 0 (series must stay deleted)", got)
	}
}

// TestPoolStatsNilPoolIsSafe proves a nil Connection pool (test-only injection)
// yields an empty snapshot instead of panicking, so the metrics updater never
// crashes on it.
func TestPoolStatsNilPoolIsSafe(t *testing.T) {
	e := &Engine{addr: "127.0.0.1:8011", maxFails: 1}
	stats := e.poolStats()
	if stats.ActiveConns != 0 || stats.MaxActive != 0 {
		t.Fatalf("nil-pool stats = %+v, want zero snapshot", stats)
	}
}
