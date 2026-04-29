package caddy_waf_t1k

import (
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
}

func (e *Engine) DetectHttpRequest(r *http.Request) (*detection.Result, error) {
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

type EnginePool []*Engine

// CaddyWAF implements an HTTP handler for WAF.
type CaddyWAF struct {
	logger *zap.Logger
	ctx    caddy.Context

	WafEngineAddrs []string `json:"waf_engine_addrs,omitempty"` // WAF Engine address, expects a URL or IP address

	// Multiple WAF engine pools
	Engines EnginePool

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

	// Initialize multiple engines
	m.Engines = make(EnginePool, len(m.WafEngineAddrs))
	for i, addr := range m.WafEngineAddrs {
		pc := &t1k.PoolConfig{
			InitialCap:  m.InitialCap,
			MaxIdle:     m.MaxIdle,
			MaxCap:      m.MaxCap,
			Factory:     &t1k.TcpFactory{Addr: addr},
			IdleTimeout: m.IdleTimeout,
		}

		engine, err := initDetect(pc)
		if err != nil {
			return fmt.Errorf("init detect error for %s: %v", addr, err)
		}
		m.Engines[i] = &Engine{
			pool:     engine,
			addr:     addr,
			maxFails: m.HealthMaxFails,
		}
	}
	m.logger.Info("WAF plugin instance Provisioned")

	initWAFMetrics(ctx.GetMetricsRegistry())
	newMetricsEnginesHealthyUpdater(m).start()

	return nil
}

// ServeHTTP processes incoming HTTP requests by utilizing the Caddy WAF engine to detect
// potential threats. If a request is identified as malicious, it redirects the request to
// an intercept handler. Otherwise, it passes the request to the next handler in the chain.
// The method handles detection errors and enforces a timeout for the detection process,
// logging relevant information in each case.
func (m *CaddyWAF) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	engine := m.LoadBalancing.SelectionPolicy.Select(m.Engines, r, w)
	if engine == nil {
		m.logger.Warn("all WAF engines unavailable, request passed through",
			zap.String("path", r.URL.Path),
			zap.String("method", r.Method))
		wafMetrics.requestsTotal.WithLabelValues("failopen").Inc()
		return next.ServeHTTP(w, r)
	}

	start := time.Now()
	result, err := engine.DetectHttpRequest(r)
	wafMetrics.detectDuration.WithLabelValues(engine.addr).Observe(time.Since(start).Seconds())

	if err != nil {
		wafMetrics.requestsTotal.WithLabelValues("error").Inc()
		if isEngineError(err) {
			m.logger.Error("DetectHttpRequest engine error",
				zap.String("engine", engine.addr),
				zap.String("request", r.Host),
				zap.String("path", r.URL.Path),
				zap.String("method", r.Method),
				zap.Error(err))
			m.countFailure(engine)
		} else {
			m.logger.Warn("DetectHttpRequest client error",
				zap.String("request", r.Host),
				zap.String("path", r.URL.Path),
				zap.String("method", r.Method),
				zap.Error(err))
		}
		return next.ServeHTTP(w, r)
	}
	if result.Blocked() {
		wafMetrics.requestsTotal.WithLabelValues("blocked").Inc()
		return m.redirectIntercept(w, result)
	}
	wafMetrics.requestsTotal.WithLabelValues("passed").Inc()
	return next.ServeHTTP(w, r)
}

// Cleans up the WAF plugin instance by closing the WAF engine and logging the cleanup process.
func (m *CaddyWAF) Cleanup() error {
	for _, engine := range m.Engines {
		if engine != nil {
			engine.pool.Release()
		}
	}
	m.logger.Info("Cleaning up WAF plugin instance")
	return nil
}

var clientErrorPatterns = []string{
	"H3_REQUEST_CANCELLED",
	"H3 error",
	"client disconnected",
	"keepalive limit reached",
	"connection reset by peer",
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
	_ caddy.CleanerUpper          = (*CaddyWAF)(nil)
	_ caddyhttp.MiddlewareHandler = (*CaddyWAF)(nil)
	_ caddyfile.Unmarshaler       = (*CaddyWAF)(nil)
)
