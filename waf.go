package caddy_waf_t1k

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"sync/atomic"
	"time"

	"github.com/chaitin/t1k-go"
	"github.com/chaitin/t1k-go/detection"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"

	"go.uber.org/zap"
)

func init() {
	caddy.RegisterModule(CaddyWAF{})
}

// Engine wraps a t1k.ChannelPool with per-engine health state.
type Engine struct {
	pool     *t1k.ChannelPool
	addr     string
	fails    int64 // atomic: unexpired failure count
	maxFails int
	// detectFn, if set, replaces pool.DetectHttpRequest (tests only).
	detectFn func(*http.Request) (*detection.Result, error)
}

func (e *Engine) DetectHttpRequest(r *http.Request) (*detection.Result, error) {
	if e.detectFn != nil {
		return e.detectFn(r)
	}
	return e.pool.DetectHttpRequest(r)
}

func (e *Engine) Fails() int {
	return int(atomic.LoadInt64(&e.fails))
}

func (e *Engine) countFail(delta int) {
	atomic.AddInt64(&e.fails, int64(delta))
}

func (e *Engine) Available() bool {
	if e.maxFails <= 0 {
		return true
	}
	return e.Fails() < e.maxFails
}

func (e *Engine) poolStats() t1k.PoolStats {
	return e.pool.Stats()
}

type EnginePool []*Engine

// engineUsagePool holds t1k connection pools shared across every waf_chaitin
// handler that resolves to the same engineKey. Reference-counted: the pool is
// built once, reused by all matching handlers, and released only when the last
// handler is cleaned up.
var engineUsagePool = caddy.NewUsagePool()

// engineKey identifies a shareable engine. It must stay comparable (value
// fields only). Every parameter that changes pool behaviour or health state
// is included so that only identically-configured sites share a pool.
type engineKey struct {
	addr        string
	initialCap  int
	maxIdle     int
	maxCap      int
	idleTimeout time.Duration
	maxFails    int            // health threshold; different → separate state machine
	failDur     caddy.Duration // countFailure decay window; keeps m.countFailure consistent across sharers
}

// sharedEngine is the value stored in engineUsagePool. It owns the engine, the
// single metrics updater for that engine, and the cancel func stopping it.
type sharedEngine struct {
	engine  *Engine
	cancel  context.CancelFunc
	updater *metricsPoolUpdater
}

// Destruct is called by UsagePool.Delete when the last reference is released.
func (s *sharedEngine) Destruct() error {
	s.cancel()              // stop the metrics updater first
	s.engine.pool.Release() // then close all TCP connections
	addr := s.engine.addr
	wafMetrics.enginesHealthy.DeleteLabelValues(addr)
	wafMetrics.poolIdleConns.DeleteLabelValues(addr)
	wafMetrics.poolActiveConns.DeleteLabelValues(addr)
	wafMetrics.poolMaxConns.DeleteLabelValues(addr)
	wafMetrics.poolWaitingReqs.DeleteLabelValues(addr)
	return nil
}

// CaddyWAF implements an HTTP handler for WAF.
type CaddyWAF struct {
	logger *zap.Logger
	ctx    caddy.Context

	WafEngineAddrs []string `json:"waf_engine_addrs,omitempty"` // WAF Engine address, expects a URL or IP address

	// Multiple WAF engine pools
	Engines EnginePool
	// engineKeys aligns 1:1 with Engines; used by Cleanup to release refs.
	engineKeys []engineKey

	// Load balancing distributes load/requests between backends.
	LoadBalancing *LoadBalancing `json:"load_balancing,omitempty"`

	InitialCap  int           `json:"initial_cap,omitempty"`
	MaxIdle     int           `json:"max_idle,omitempty"`
	MaxCap      int           `json:"max_cap,omitempty"`
	IdleTimeout time.Duration `json:"idle_timeout,omitempty"`

	HealthFailDuration caddy.Duration `json:"health_fail_duration,omitempty"`
	HealthMaxFails     int            `json:"health_max_fails,omitempty"`
}

// CaddyModule returns the Caddy module information.
func (CaddyWAF) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.waf_chaitin",
		New: func() caddy.Module { return new(CaddyWAF) },
	}
}

// initDetect initializes the WAF engine.
func initDetect(pc *t1k.PoolConfig) (*t1k.ChannelPool, error) {
	server, err := t1k.NewChannelPool(pc)
	if err != nil {
		return nil, err
	}
	return server, nil
}

// Provision sets up the WAF module.
func (m *CaddyWAF) Provision(ctx caddy.Context) error {
	m.logger = ctx.Logger(m)
	m.ctx = ctx
	m.logger.Info("Provisioning WAF plugin instance")

	if len(m.WafEngineAddrs) == 0 {
		return fmt.Errorf("WAF configuration error: no engine addresses specified")
	}

	if m.InitialCap == 0 {
		m.logger.Info("InitialCap is not set, defaulting to 1")
		m.InitialCap = 1
	}

	if m.MaxIdle == 0 {
		m.logger.Info("MaxIdle is not set, defaulting to 16")
		m.MaxIdle = 16
	}

	if m.MaxCap == 0 {
		m.logger.Info("MaxCap is not set, defaulting to 32")
		m.MaxCap = 32
	}

	if m.IdleTimeout == time.Duration(0)*time.Second {
		m.logger.Info("IdleTimeout is not set, defaulting to 30 seconds")
		m.IdleTimeout = 30 * time.Second
	}

	if m.LoadBalancing != nil && m.LoadBalancing.SelectionPolicyRaw != nil {
		mod, err := ctx.LoadModule(m.LoadBalancing, "SelectionPolicyRaw")
		if err != nil {
			return fmt.Errorf("loading load balancing selection policy: %s", err)
		}
		m.LoadBalancing.SelectionPolicy = mod.(Selector)
	}

	// set up load balancing
	if m.LoadBalancing == nil {
		m.LoadBalancing = new(LoadBalancing)
	}
	if m.LoadBalancing.SelectionPolicy == nil {
		m.LoadBalancing.SelectionPolicy = RandomSelection{}
	}

	if m.HealthMaxFails == 0 {
		m.HealthMaxFails = 1
	}

	// Register metrics before constructing shared engines: the updater created
	// inside the constructor references the package-level wafMetrics collectors.
	initWAFMetrics(ctx.GetMetricsRegistry())

	m.Engines = make(EnginePool, len(m.WafEngineAddrs))
	m.engineKeys = make([]engineKey, len(m.WafEngineAddrs))
	for i, addr := range m.WafEngineAddrs {
		key := engineKey{
			addr:        addr,
			initialCap:  m.InitialCap,
			maxIdle:     m.MaxIdle,
			maxCap:      m.MaxCap,
			idleTimeout: m.IdleTimeout,
			maxFails:    m.HealthMaxFails,
			failDur:     m.HealthFailDuration,
		}

		val, _, err := engineUsagePool.LoadOrNew(key, func() (caddy.Destructor, error) {
			pc := &t1k.PoolConfig{
				InitialCap:  key.initialCap,
				MaxIdle:     key.maxIdle,
				MaxCap:      key.maxCap,
				Factory:     &t1k.TcpFactory{Addr: key.addr},
				IdleTimeout: key.idleTimeout,
			}
			pool, err := initDetect(pc)
			if err != nil {
				return nil, fmt.Errorf("init detect error for %s: %v", key.addr, err)
			}
			engine := &Engine{pool: pool, addr: key.addr, maxFails: key.maxFails}
			uctx, cancel := context.WithCancel(context.Background())
			updater := newMetricsPoolUpdater(EnginePool{engine}, uctx)
			updater.start()
			return &sharedEngine{engine: engine, cancel: cancel, updater: updater}, nil
		})
		if err != nil {
			// roll back refs already acquired to avoid leaking shared engines
			for j := 0; j < i; j++ {
				engineUsagePool.Delete(m.engineKeys[j])
			}
			return fmt.Errorf("provision engine %s: %w", addr, err)
		}

		se := val.(*sharedEngine)
		m.Engines[i] = se.engine
		m.engineKeys[i] = key
	}

	m.logger.Info("WAF plugin instance Provisioned")

	return nil
}

// Validate ensures module configuration is valid.
func (m *CaddyWAF) Validate() error {
	if m.LoadBalancing != nil && m.LoadBalancing.Retries < 0 {
		return fmt.Errorf("load_balancing.retries must be >= 0")
	}
	return nil
}

// ServeHTTP processes incoming HTTP requests by utilizing the Caddy WAF engine to detect
// potential threats. If a request is identified as malicious, it redirects the request to
// an intercept handler. Otherwise, it passes the request to the next handler in the chain.
// The method handles detection errors and enforces a timeout for the detection process,
// logging relevant information in each case.
func (m *CaddyWAF) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	retries := 0
	if m.LoadBalancing != nil {
		retries = m.LoadBalancing.Retries
	}
	maxAttempts := 1 + retries
	tried := make(map[*Engine]struct{})

	for attempt := 0; attempt < maxAttempts; attempt++ {
		candidates := excludeEngines(m.Engines, tried)
		engine := m.LoadBalancing.SelectionPolicy.Select(candidates, r, w)
		if engine == nil {
			if len(tried) == 0 {
				m.logger.Warn("all WAF engines unavailable, request passed through",
					zap.String("path", r.URL.Path),
					zap.String("method", r.Method))
				wafMetrics.requestsTotal.WithLabelValues("failopen").Inc()
			} else {
				m.logger.Error("no remaining WAF engines after detect failures, request passed through",
					zap.String("path", r.URL.Path),
					zap.String("method", r.Method),
					zap.Int("tried", len(tried)))
				wafMetrics.requestsTotal.WithLabelValues("error").Inc()
			}
			return next.ServeHTTP(w, r)
		}

		start := time.Now()
		result, err := engine.DetectHttpRequest(r)
		wafMetrics.detectDuration.WithLabelValues(engine.addr).Observe(time.Since(start).Seconds())

		if err == nil {
			if result.Blocked() {
				wafMetrics.requestsTotal.WithLabelValues("blocked").Inc()
				return m.redirectIntercept(w, result)
			}
			wafMetrics.requestsTotal.WithLabelValues("passed").Inc()
			return next.ServeHTTP(w, r)
		}

		recordConnectionError(engine.addr, classifyConnectionError(err))

		if !isEngineError(err) {
			m.logger.Warn("DetectHttpRequest client error",
				zap.String("request", r.Host),
				zap.String("path", r.URL.Path),
				zap.String("method", r.Method),
				zap.Error(err))
			wafMetrics.requestsTotal.WithLabelValues("error").Inc()
			return next.ServeHTTP(w, r)
		}

		m.logger.Error("DetectHttpRequest engine error",
			zap.String("engine", engine.addr),
			zap.String("request", r.Host),
			zap.String("path", r.URL.Path),
			zap.String("method", r.Method),
			zap.Int("attempt", attempt+1),
			zap.Int("max_attempts", maxAttempts),
			zap.Error(err))
		m.countFailure(engine)
		tried[engine] = struct{}{}

		// More attempts allowed and at least one untried engine may remain.
		if attempt+1 < maxAttempts && len(excludeEngines(m.Engines, tried)) > 0 {
			m.logger.Warn("retrying detect on another WAF engine",
				zap.String("failed_engine", engine.addr),
				zap.Int("attempt", attempt+1))
			continue
		}

		wafMetrics.requestsTotal.WithLabelValues("error").Inc()
		return next.ServeHTTP(w, r)
	}

	wafMetrics.requestsTotal.WithLabelValues("error").Inc()
	return next.ServeHTTP(w, r)
}

// Cleans up the WAF plugin instance by closing the WAF engine and logging the cleanup process.
func (m *CaddyWAF) Cleanup() error {
	for _, key := range m.engineKeys {
		if _, err := engineUsagePool.Delete(key); err != nil {
			m.logger.Warn("error releasing shared WAF engine",
				zap.String("engine", key.addr),
				zap.Error(err))
		}
	}
	m.logger.Info("Cleaning up WAF plugin instance")
	return nil
}

var clientErrorPatterns = []string{
	// Body() 客户端读体错误（unexpected EOF / H2 CANCEL / H3 QUIC / connection reset 等）。
	// 引擎侧 TCP reset 不含此前缀，应计为引擎错误并进入被动健康检查。
	"read request body",
	"H3_REQUEST_CANCELLED",
	"H3 error",
	"client disconnected",
	"keepalive limit reached",
	"timeout: no recent network activity",
	"empty hex number for chunk length",
	"context canceled",
	"request canceled",
}

func isEngineError(err error) bool {
	msg := err.Error()
	for _, pattern := range clientErrorPatterns {
		if strings.Contains(msg, pattern) {
			return false
		}
	}
	return true
}

func (m *CaddyWAF) countFailure(engine *Engine) {
	failDuration := time.Duration(m.HealthFailDuration)
	if failDuration == 0 {
		return
	}
	engine.countFail(1)
	go func() {
		timer := time.NewTimer(failDuration)
		<-timer.C
		engine.countFail(-1)
	}()
}

// Interface guards
var (
	_ caddy.Provisioner           = (*CaddyWAF)(nil)
	_ caddy.Validator             = (*CaddyWAF)(nil)
	_ caddy.CleanerUpper          = (*CaddyWAF)(nil)
	_ caddyhttp.MiddlewareHandler = (*CaddyWAF)(nil)
	_ caddyfile.Unmarshaler       = (*CaddyWAF)(nil)
)
