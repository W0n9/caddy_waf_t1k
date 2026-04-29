package caddy_waf_t1k

import (
	"errors"
	"runtime/debug"
	"sync"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/prometheus/client_golang/prometheus"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

var wafMetrics = struct {
	once            sync.Once
	requestsTotal   *prometheus.CounterVec
	detectDuration  *prometheus.HistogramVec
	enginesHealthy  *prometheus.GaugeVec
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
	})

	logger := caddy.Log().Named("waf.metrics")
	for _, metric := range []struct {
		name      string
		collector prometheus.Collector
	}{
		{name: "requests_total", collector: wafMetrics.requestsTotal},
		{name: "detect_duration_seconds", collector: wafMetrics.detectDuration},
		{name: "engines_healthy", collector: wafMetrics.enginesHealthy},
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

type metricsEnginesHealthyUpdater struct {
	engines EnginePool
	ctx     caddy.Context
	logger  *zap.Logger
}

func newMetricsEnginesHealthyUpdater(m *CaddyWAF) *metricsEnginesHealthyUpdater {
	return &metricsEnginesHealthyUpdater{
		engines: m.Engines,
		ctx:     m.ctx,
		logger:  m.logger.Named("waf.metrics"),
	}
}

func (u *metricsEnginesHealthyUpdater) start() {
	go func() {
		defer func() {
			if err := recover(); err != nil {
				if c := u.logger.Check(zapcore.ErrorLevel, "engines healthy metrics updater panicked"); c != nil {
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

func (u *metricsEnginesHealthyUpdater) update() {
	for _, engine := range u.engines {
		val := 0.0
		if engine.Available() {
			val = 1.0
		}
		wafMetrics.enginesHealthy.With(prometheus.Labels{"engine": engine.addr}).Set(val)
	}
}
