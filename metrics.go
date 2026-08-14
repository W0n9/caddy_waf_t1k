package caddy_waf_t1k

import (
	"errors"
	"runtime/debug"
	"sync"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/chaitin/t1k-go"
	"github.com/prometheus/client_golang/prometheus"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

const poolEventReasons = 5

var poolEventReasonNames = [poolEventReasons]string{
	"dial_failed",
	"idle_expired",
	"ping_failed",
	"pool_full_close",
	"max_active_hit",
}

var wafMetrics = struct {
	once             sync.Once
	requestsTotal    *prometheus.CounterVec
	detectDuration   *prometheus.HistogramVec
	enginesHealthy   *prometheus.GaugeVec
	poolIdleConns    *prometheus.GaugeVec
	poolActiveConns  *prometheus.GaugeVec
	poolMaxConns     *prometheus.GaugeVec
	poolWaitingReqs  *prometheus.GaugeVec
	connectionErrors *prometheus.CounterVec
	poolEvents       *prometheus.CounterVec
	oversizeRequests prometheus.Counter
}{}

func initWAFMetrics(registry *prometheus.Registry) {
	const ns, sub = "caddy", "waf"

	wafMetrics.once.Do(func() {
		wafMetrics.requestsTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: ns,
			Subsystem: sub,
			Name:      "requests_total",
			Help:      "Total number of requests processed by the WAF.",
		}, []string{"action"})

		wafMetrics.detectDuration = prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Namespace: ns,
			Subsystem: sub,
			Name:      "detect_duration_seconds",
			Help:      "Duration of WAF detection requests.",
			Buckets:   prometheus.DefBuckets,
		}, []string{"engine"})

		wafMetrics.enginesHealthy = prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: ns,
			Subsystem: sub,
			Name:      "engines_healthy",
			Help:      "Health status of WAF engines.",
		}, []string{"engine"})

		wafMetrics.poolIdleConns = prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: ns,
			Subsystem: sub,
			Name:      "pool_idle_conns",
			Help:      "Number of idle connections in the WAF engine pool.",
		}, []string{"engine"})

		wafMetrics.poolActiveConns = prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: ns,
			Subsystem: sub,
			Name:      "pool_active_conns",
			Help:      "Number of active connections in the WAF engine pool.",
		}, []string{"engine"})

		wafMetrics.poolMaxConns = prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: ns,
			Subsystem: sub,
			Name:      "pool_max_conns",
			Help:      "Maximum number of connections allowed in the WAF engine pool.",
		}, []string{"engine"})

		wafMetrics.poolWaitingReqs = prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: ns,
			Subsystem: sub,
			Name:      "pool_waiting_requests",
			Help:      "Number of requests waiting for an available WAF engine connection.",
		}, []string{"engine"})

		wafMetrics.connectionErrors = prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: ns,
			Subsystem: sub,
			Name:      "connection_errors_total",
			Help:      "Total number of WAF detection connection errors by reason.",
		}, []string{"engine", "reason"})

		wafMetrics.poolEvents = prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: ns,
			Subsystem: sub,
			Name:      "pool_events_total",
			Help:      "Total number of WAF engine pool lifecycle events by reason.",
		}, []string{"engine", "reason"})

		wafMetrics.oversizeRequests = prometheus.NewCounter(prometheus.CounterOpts{
			Namespace: ns,
			Subsystem: sub,
			Name:      "oversize_requests_total",
			Help:      "Total requests whose body was truncated for WAF detection.",
		})
	})

	logger := caddy.Log().Named("waf.metrics")
	for _, metric := range []struct {
		name      string
		collector prometheus.Collector
	}{
		{name: "requests_total", collector: wafMetrics.requestsTotal},
		{name: "detect_duration_seconds", collector: wafMetrics.detectDuration},
		{name: "engines_healthy", collector: wafMetrics.enginesHealthy},
		{name: "pool_idle_conns", collector: wafMetrics.poolIdleConns},
		{name: "pool_active_conns", collector: wafMetrics.poolActiveConns},
		{name: "pool_max_conns", collector: wafMetrics.poolMaxConns},
		{name: "pool_waiting_requests", collector: wafMetrics.poolWaitingReqs},
		{name: "connection_errors_total", collector: wafMetrics.connectionErrors},
		{name: "pool_events_total", collector: wafMetrics.poolEvents},
		{name: "oversize_requests_total", collector: wafMetrics.oversizeRequests},
	} {
		if err := registry.Register(metric.collector); err != nil {
			var alreadyRegisteredErr prometheus.AlreadyRegisteredError
			if errors.As(err, &alreadyRegisteredErr) {
				continue
			}

			if c := logger.Check(zap.WarnLevel, "failed to register WAF metric collector"); c != nil {
				c.Write(
					zap.String("metric", metric.name),
					zap.Error(err),
				)
			}
		}
	}
}

type enginePoolEventState struct {
	last [poolEventReasons]uint64
}

// globalMetricsUpdater is the single process-wide updater for pool and health
// metrics. It reports every Engine in the registry on a 10s cadence, so series
// are labeled by Engine address only and a shared Engine yields exactly one
// series. Pool-event counters accumulate per Engine across all instances.
type globalMetricsUpdater struct {
	mu         sync.Mutex
	logger     *zap.Logger
	eventState map[*Engine]*enginePoolEventState
}

var (
	globalPoolMetricsUpdater = &globalMetricsUpdater{
		eventState: make(map[*Engine]*enginePoolEventState),
	}
	// startMetricsUpdaterOnce starts the updater goroutine exactly once, for
	// the process lifetime.
	startMetricsUpdaterOnce sync.Once
)

// startGlobalMetricsUpdater starts the single process-wide metrics updater
// goroutine. Provision calls it for every WAF instance; sync.Once guarantees
// exactly one goroutine for the process lifetime. The updater iterates the
// process-wide registry, so it covers every instance regardless of which one
// started it; after a config reload the same goroutine simply reports the new
// Engines, and once every Engine is released it becomes a no-op on an empty
// registry.
func startGlobalMetricsUpdater(logger *zap.Logger) {
	startMetricsUpdaterOnce.Do(func() {
		globalPoolMetricsUpdater.logger = logger
		go globalPoolMetricsUpdater.loop()
	})
}

func (u *globalMetricsUpdater) loop() {
	u.safeUpdate()

	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		u.safeUpdate()
	}
}

// safeUpdate runs one update pass, containing any panic so the 10s cadence
// survives a single bad scan. A panic in one iteration (e.g. a malformed
// registry entry) must not take the updater goroutine down for the process
// lifetime — startMetricsUpdaterOnce cannot restart it.
func (u *globalMetricsUpdater) safeUpdate() {
	defer func() {
		if err := recover(); err != nil {
			if u.logger != nil {
				if c := u.logger.Check(zapcore.ErrorLevel, "pool metrics updater panicked"); c != nil {
					c.Write(
						zap.Any("error", err),
						zap.ByteString("stack", debug.Stack()),
					)
				}
			}
		}
	}()

	u.update()
}

// update reports every Engine currently in the registry. It runs inside the
// updater goroutine on the 10s cadence and is called directly by tests.
func (u *globalMetricsUpdater) update() {
	seen := make(map[*Engine]struct{})
	engineRegistry.Range(func(_, value any) bool {
		engine, ok := value.(*Engine)
		if !ok {
			return true
		}
		seen[engine] = struct{}{}
		u.reportEngine(engine)
		return true
	})

	// Drop pool-event state for Engines that left the registry, so a fresh
	// Engine for the same address starts counting its own events from zero.
	u.mu.Lock()
	for engine := range u.eventState {
		if _, ok := seen[engine]; !ok {
			delete(u.eventState, engine)
		}
	}
	u.mu.Unlock()
}

func (u *globalMetricsUpdater) reportEngine(engine *Engine) {
	// Skip an Engine that left the registry mid-scan: its Destruct already
	// released the pool and removed its gauge series, and recreating them here
	// would leak a dead series.
	if engine.destroyed.Load() {
		return
	}
	healthy := 0.0
	if engine.Available() {
		healthy = 1.0
	}
	labels := prometheus.Labels{"engine": engine.addr}
	wafMetrics.enginesHealthy.With(labels).Set(healthy)

	stats := engine.poolStats()
	wafMetrics.poolIdleConns.With(labels).Set(float64(stats.IdleConns))
	wafMetrics.poolActiveConns.With(labels).Set(float64(stats.ActiveConns))
	wafMetrics.poolMaxConns.With(labels).Set(float64(stats.MaxActive))
	wafMetrics.poolWaitingReqs.With(labels).Set(float64(stats.WaitingReqs))

	u.syncPoolEvents(engine, stats)
}

// syncPoolEvents advances pool_events_total by the delta between the last
// observed and current cumulative Connection-pool counters for one Engine.
// Counters are cumulative per Engine, so deltas accumulate into the series for
// the Engine address no matter how many instances share it.
func (u *globalMetricsUpdater) syncPoolEvents(engine *Engine, stats t1k.PoolStats) {
	u.mu.Lock()
	defer u.mu.Unlock()

	state, ok := u.eventState[engine]
	if !ok {
		state = &enginePoolEventState{}
		u.eventState[engine] = state
	}

	current := [poolEventReasons]uint64{
		stats.DialFailed,
		stats.IdleExpired,
		stats.PingFailed,
		stats.PoolFullClose,
		stats.MaxActiveHit,
	}

	for i, reason := range poolEventReasonNames {
		if current[i] <= state.last[i] {
			continue
		}
		delta := float64(current[i] - state.last[i])
		wafMetrics.poolEvents.With(prometheus.Labels{
			"engine": engine.addr,
			"reason": reason,
		}).Add(delta)
		state.last[i] = current[i]
	}
}

// recordConnectionError increments the per-Engine connection-error counter for
// reason. A shared Engine counts once per address regardless of which instance
// the request passed through.
func recordConnectionError(engine, reason string) {
	wafMetrics.connectionErrors.With(prometheus.Labels{
		"engine": engine,
		"reason": reason,
	}).Inc()
}
