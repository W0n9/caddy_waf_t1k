package caddy_waf_t1k

import (
	"context"
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

type metricsPoolUpdater struct {
	engines    EnginePool
	ctx        context.Context
	logger     *zap.Logger
	eventState map[string]*enginePoolEventState
}

func newMetricsPoolUpdater(engines EnginePool, ctx context.Context) *metricsPoolUpdater {
	return &metricsPoolUpdater{
		engines:    engines,
		ctx:        ctx,
		logger:     caddy.Log().Named("waf.metrics"),
		eventState: make(map[string]*enginePoolEventState, len(engines)),
	}
}

func (u *metricsPoolUpdater) start() {
	go func() {
		defer func() {
			if err := recover(); err != nil {
				if c := u.logger.Check(zapcore.ErrorLevel, "pool metrics updater panicked"); c != nil {
					c.Write(
						zap.Any("error", err),
						zap.ByteString("stack", debug.Stack()),
					)
				}
			}
		}()

		u.update()

		ticker := time.NewTicker(10 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				u.update()
			case <-u.ctx.Done():
				return
			}
		}
	}()
}

func (u *metricsPoolUpdater) update() {
	for _, engine := range u.engines {
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

		u.syncPoolEvents(engine.addr, stats)
	}
}

func (u *metricsPoolUpdater) syncPoolEvents(addr string, stats t1k.PoolStats) {
	state, ok := u.eventState[addr]
	if !ok {
		state = &enginePoolEventState{}
		u.eventState[addr] = state
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
			"engine": addr,
			"reason": reason,
		}).Add(delta)
		state.last[i] = current[i]
	}
}

func recordConnectionError(engine, reason string) {
	wafMetrics.connectionErrors.With(prometheus.Labels{
		"engine": engine,
		"reason": reason,
	}).Inc()
}
