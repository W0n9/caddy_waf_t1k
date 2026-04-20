package caddy_waf_t1k

import (
	"context"
	"fmt"
	"net/http"
	"time"

	t1k "github.com/chaitin/t1k-go"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"

	"go.uber.org/zap"
)

func init() {
	caddy.RegisterModule(CaddyWAF{})
}

// EnginePool is a slice of WAF engine entries.
type EnginePool []*engineEntry

// CaddyWAF implements an HTTP handler for WAF.
type CaddyWAF struct {
	logger *zap.Logger
	cancel context.CancelFunc

	WafEngineAddrs []string `json:"waf_engine_addrs,omitempty"`
	Engines        EnginePool

	LoadBalancing *LoadBalancing `json:"load_balancing,omitempty"`

	InitialCap  int           `json:"initial_cap,omitempty"`
	MaxIdle     int           `json:"max_idle,omitempty"`
	MaxCap      int           `json:"max_cap,omitempty"`
	IdleTimeout time.Duration `json:"idle_timeout,omitempty"`

	// Batch 1: health check config
	HealthCheckInterval caddy.Duration `json:"health_check_interval,omitempty"`
	FailureThreshold    int            `json:"failure_threshold,omitempty"`
	RecoveryThreshold   int            `json:"recovery_threshold,omitempty"`

	// Batch 2: filter + observability
	SkipContentTypes   []string `json:"skip_content_types,omitempty"`
	SkipHeader         string   `json:"skip_header,omitempty"`
	MaxBodyBytes       int64    `json:"max_body_bytes,omitempty"`
	LogBlockedRequests bool     `json:"log_blocked_requests,omitempty"`

	// Batch 3: bot detection
	BotDetect bool `json:"bot_detect,omitempty"`
}

func (CaddyWAF) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.waf_chaitin",
		New: func() caddy.Module { return new(CaddyWAF) },
	}
}

func (m *CaddyWAF) Provision(ctx caddy.Context) error {
	m.logger = ctx.Logger(m)
	m.logger.Info("Provisioning WAF plugin instance")

	if len(m.WafEngineAddrs) == 0 {
		return fmt.Errorf("WAF configuration error: no engine addresses specified")
	}

	if m.InitialCap == 0 {
		m.InitialCap = 1
	}
	if m.MaxIdle == 0 {
		m.MaxIdle = 16
	}
	if m.MaxCap == 0 {
		m.MaxCap = 32
	}
	if m.IdleTimeout == 0 {
		m.IdleTimeout = 30 * time.Second
	}
	if m.HealthCheckInterval == 0 {
		m.HealthCheckInterval = caddy.Duration(10 * time.Second)
	}
	if m.FailureThreshold == 0 {
		m.FailureThreshold = 3
	}
	if m.RecoveryThreshold == 0 {
		m.RecoveryThreshold = 2
	}

	if m.LoadBalancing != nil && m.LoadBalancing.SelectionPolicyRaw != nil {
		mod, err := ctx.LoadModule(m.LoadBalancing, "SelectionPolicyRaw")
		if err != nil {
			return fmt.Errorf("loading load balancing selection policy: %s", err)
		}
		m.LoadBalancing.SelectionPolicy = mod.(Selector)
	}
	if m.LoadBalancing == nil {
		m.LoadBalancing = new(LoadBalancing)
	}
	if m.LoadBalancing.SelectionPolicy == nil {
		m.LoadBalancing.SelectionPolicy = RandomSelection{}
	}

	m.Engines = make(EnginePool, len(m.WafEngineAddrs))
	for i, addr := range m.WafEngineAddrs {
		pc := &t1k.PoolConfig{
			InitialCap:  m.InitialCap,
			MaxIdle:     m.MaxIdle,
			MaxCap:      m.MaxCap,
			Factory:     &t1k.TcpFactory{Addr: addr},
			IdleTimeout: m.IdleTimeout,
		}
		pool, err := t1k.NewChannelPool(pc)
		if err != nil {
			return fmt.Errorf("init detect error for %s: %v", addr, err)
		}
		m.Engines[i] = newEngineEntry(pool, addr)
	}

	hcCtx, cancel := context.WithCancel(context.Background())
	m.cancel = cancel
	for _, e := range m.Engines {
		e.startHealthCheck(
			hcCtx,
			time.Duration(m.HealthCheckInterval),
			int32(m.FailureThreshold),
			int32(m.RecoveryThreshold),
			m.logger,
		)
	}

	initWAFMetrics(ctx.GetMetricsRegistry())

	m.logger.Info("WAF plugin instance Provisioned",
		zap.Strings("engine_addrs", m.WafEngineAddrs))
	return nil
}

func (m CaddyWAF) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	entry := m.LoadBalancing.SelectionPolicy.Select(m.Engines, r, w)
	if entry == nil {
		recordRequest("error")
		return fmt.Errorf("no available WAF engine for request %s %s", r.Method, r.URL.Path)
	}

	fr := checkFilter(r, m.SkipContentTypes, m.SkipHeader, m.MaxBodyBytes)
	if fr == filterSkipAll {
		recordRequest("skipped")
		return next.ServeHTTP(w, r)
	}
	if fr == filterSkipBody {
		rCopy := r.Clone(r.Context())
		rCopy.Body = http.NoBody
		rCopy.ContentLength = 0
		r = rCopy
	}

	start := time.Now()
	result, err := entry.engine.DetectHttpRequest(r)
	elapsed := time.Since(start)
	recordDetectDuration(elapsed.Seconds())

	if err != nil {
		m.logger.Error("DetectHttpRequest error",
			zap.String("engine_addr", entry.addr),
			zap.String("host", r.Host),
			zap.String("path", r.URL.Path),
			zap.String("method", r.Method),
			zap.Error(err))
		recordRequest("error")
		return next.ServeHTTP(w, r)
	}

	if m.BotDetect && result.BotDetected() {
		stripBotCookies(r)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(result.BotBody)
		recordRequest("bot_challenge")
		return nil
	}

	if result.Blocked() {
		if m.LogBlockedRequests {
			m.logger.Warn("WAF blocked request",
				zap.String("event_id", result.EventID()),
				zap.String("remote_addr", r.RemoteAddr),
				zap.String("path", r.URL.Path))
		}
		recordRequest("blocked")
		return m.redirectIntercept(w, result)
	}

	recordRequest("allowed")
	return next.ServeHTTP(w, r)
}

func (m CaddyWAF) Cleanup() error {
	if m.cancel != nil {
		m.cancel()
	}
	for _, e := range m.Engines {
		if e != nil && e.engine != nil {
			if cp, ok := e.engine.(interface{ Release() }); ok {
				cp.Release()
			}
		}
	}
	m.logger.Info("Cleaning up WAF plugin instance")
	return nil
}

var (
	_ caddy.Provisioner           = (*CaddyWAF)(nil)
	_ caddyhttp.MiddlewareHandler = (*CaddyWAF)(nil)
	_ caddyfile.Unmarshaler       = (*CaddyWAF)(nil)
)
