package caddy_waf_t1k

import (
	"errors"
	"sync"

	"github.com/prometheus/client_golang/prometheus"
)

var wafMetrics = struct {
	once           sync.Once
	requestsTotal  *prometheus.CounterVec
	detectDuration *prometheus.HistogramVec
	engineHealthy  *prometheus.GaugeVec
}{}

func initWAFMetrics(registry *prometheus.Registry) {
	const ns, sub = "caddy", "waf_chaitin"
	wafMetrics.once.Do(func() {
		wafMetrics.requestsTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: ns,
			Subsystem: sub,
			Name:      "requests_total",
			Help:      "Total WAF-inspected requests by result (allowed, blocked, error, skipped).",
		}, []string{"result"})
		wafMetrics.detectDuration = prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Namespace: ns,
			Subsystem: sub,
			Name:      "detect_duration_seconds",
			Help:      "WAF engine detection round-trip latency.",
			Buckets:   prometheus.DefBuckets,
		}, []string{})
		wafMetrics.engineHealthy = prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: ns,
			Subsystem: sub,
			Name:      "engine_healthy",
			Help:      "WAF engine health status: 1=healthy, 0=unhealthy.",
		}, []string{"addr"})
	})
	for _, c := range []prometheus.Collector{
		wafMetrics.requestsTotal,
		wafMetrics.detectDuration,
		wafMetrics.engineHealthy,
	} {
		if err := registry.Register(c); err != nil {
			var are prometheus.AlreadyRegisteredError
			if !errors.As(err, &are) {
				panic(err)
			}
		}
	}
}

func recordRequest(result string) {
	if wafMetrics.requestsTotal != nil {
		wafMetrics.requestsTotal.WithLabelValues(result).Inc()
	}
}

func recordDetectDuration(seconds float64) {
	if wafMetrics.detectDuration != nil {
		wafMetrics.detectDuration.WithLabelValues().Observe(seconds)
	}
}

func setEngineHealthy(addr string, healthy bool) {
	if wafMetrics.engineHealthy == nil {
		return
	}
	v := 0.0
	if healthy {
		v = 1.0
	}
	wafMetrics.engineHealthy.WithLabelValues(addr).Set(v)
}
