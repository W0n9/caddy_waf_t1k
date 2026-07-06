package caddy_waf_t1k

import (
	"errors"
	"strings"
	"testing"

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

func TestMetricsPoolUpdaterSyncPoolEvents(t *testing.T) {
	registry := prometheus.NewRegistry()
	initWAFMetrics(registry)

	updater := &metricsPoolUpdater{eventState: make(map[string]*enginePoolEventState)}

	stats := t1k.PoolStats{
		DialFailed:    2,
		IdleExpired:   1,
		PingFailed:    3,
		PoolFullClose: 4,
		MaxActiveHit:  5,
	}

	updater.syncPoolEvents("127.0.0.1:8000", stats)
	state := updater.eventState["127.0.0.1:8000"]
	if state.last[0] != 2 || state.last[1] != 1 || state.last[2] != 3 || state.last[4] != 5 {
		t.Fatalf("unexpected state after first sync: %+v", state.last)
	}

	updater.syncPoolEvents("127.0.0.1:8000", stats)

	stats.DialFailed = 3
	updater.syncPoolEvents("127.0.0.1:8000", stats)
	if state.last[0] != 3 {
		t.Errorf("DialFailed last = %d, want 3", state.last[0])
	}
}

func TestWAFMetricsRegistration(t *testing.T) {
	registry := prometheus.NewRegistry()
	initWAFMetrics(registry)

	wafMetrics.requestsTotal.WithLabelValues("passed").Inc()
	wafMetrics.detectDuration.WithLabelValues("127.0.0.1:8000").Observe(0.01)
	wafMetrics.enginesHealthy.WithLabelValues("127.0.0.1:8000").Set(1)
	wafMetrics.poolIdleConns.WithLabelValues("127.0.0.1:8000").Set(2)
	wafMetrics.poolActiveConns.WithLabelValues("127.0.0.1:8000").Set(4)
	wafMetrics.poolMaxConns.WithLabelValues("127.0.0.1:8000").Set(8)
	wafMetrics.poolWaitingReqs.WithLabelValues("127.0.0.1:8000").Set(0)
	recordConnectionError("127.0.0.1:8000", reasonConnectionRefused)
	wafMetrics.poolEvents.WithLabelValues("127.0.0.1:8000", "dial_failed").Inc()

	expected := strings.NewReader(`
		# HELP caddy_waf_connection_errors_total Total number of WAF detection connection errors by reason.
		# TYPE caddy_waf_connection_errors_total counter
		caddy_waf_connection_errors_total{engine="127.0.0.1:8000",reason="connection_refused"} 1
		# HELP caddy_waf_engines_healthy Health status of WAF engines.
		# TYPE caddy_waf_engines_healthy gauge
		caddy_waf_engines_healthy{engine="127.0.0.1:8000"} 1
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
