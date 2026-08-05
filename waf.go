package caddy_waf_t1k

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"time"

	"github.com/chaitin/t1k-go"
	"github.com/chaitin/t1k-go/detection"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/prometheus/client_golang/prometheus"

	"go.uber.org/zap"
)

func init() {
	caddy.RegisterModule(CaddyWAF{})
}

// maxBodySizeLimit is the largest allowed MaxBodySize. It leaves headroom so
// prepareDetectionRequest's io.LimitReader(body, m.MaxBodySize+1) cannot
// overflow int64.
const maxBodySizeLimit = 1<<63 - 2

// Engine wraps a t1k.ChannelPool with per-engine health state. An Engine is
// self-contained: it owns its Passive health check parameters
// (health_max_fails / health_fail_duration) and its own teardown, so
// availability decisions on a shared Engine are unambiguous.
type Engine struct {
	pool         *t1k.ChannelPool
	addr         string
	fails        int64 // atomic: unexpired failure count
	maxFails     int
	failDuration time.Duration
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

// fail counts one detection failure against this Engine's passive health
// window. A zero failDuration disables health checking entirely.
func (e *Engine) fail() {
	d := e.failDuration
	if d <= 0 {
		return
	}
	e.countFail(1)
	time.AfterFunc(d, func() { e.countFail(-1) })
}

// Destruct tears the Engine down: it releases the Connection pool and removes
// this Engine's metric label series. The registry calls it when the last
// reference to the Engine is released.
func (e *Engine) Destruct() error {
	if e.pool != nil {
		e.pool.Release()
	}
	if wafMetrics.enginesHealthy == nil {
		return nil
	}
	// DeletePartialMatch removes every gauge series for this Engine address
	// (the only remaining label). The two counters (pool_events_total,
	// connection_errors_total) are intentionally not deleted: they accumulate
	// per Engine address across all instances and config generations, and
	// Prometheus rates/increases depend on that monotonic history.
	labels := prometheus.Labels{"engine": e.addr}
	wafMetrics.enginesHealthy.DeletePartialMatch(labels)
	wafMetrics.poolIdleConns.DeletePartialMatch(labels)
	wafMetrics.poolActiveConns.DeletePartialMatch(labels)
	wafMetrics.poolMaxConns.DeletePartialMatch(labels)
	wafMetrics.poolWaitingReqs.DeletePartialMatch(labels)
	return nil
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

// CaddyWAF implements an HTTP handler for WAF.
type CaddyWAF struct {
	logger *zap.Logger

	// acquiredKeys records, in Engine-pool order, the registry key acquired for
	// each WafEngineAddr. Cleanup releases exactly these keys; on a provisioning
	// error the keys already acquired for this instance are released again.
	acquiredKeys []engineKey

	// poolFactory, if set, replaces initDetect when building a new Engine's
	// Connection pool (tests only).
	poolFactory func(*t1k.PoolConfig) (*t1k.ChannelPool, error)

	WafEngineAddrs []string `json:"waf_engine_addrs,omitempty"` // WAF Engine address, expects a URL or IP address

	// Multiple WAF engine pools
	Engines EnginePool

	// Load balancing distributes load/requests between backends.
	LoadBalancing *LoadBalancing `json:"load_balancing,omitempty"`

	InitialCap  int           `json:"initial_cap,omitempty"`
	MaxIdle     int           `json:"max_idle,omitempty"`
	MaxCap      int           `json:"max_cap,omitempty"`
	IdleTimeout time.Duration `json:"idle_timeout,omitempty"`

	// MaxBodySize limits the number of request-body bytes sent to the detection engine;
	// the full body is still forwarded downstream. A value of 0 preserves unlimited detection.
	MaxBodySize int64 `json:"max_body_size,omitempty"`

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

	// Acquire one shared Engine per configured address from the process-wide
	// registry. Identical address+config keys share a single Engine (reference
	// counted); any shaping-parameter difference yields independent Engines.
	// A provisioning error releases every Engine already acquired.
	if err := m.acquireEngines(); err != nil {
		return err
	}
	m.logger.Info("WAF plugin instance Provisioned")

	initWAFMetrics(ctx.GetMetricsRegistry())
	startGlobalMetricsUpdater(m.logger)

	return nil
}

// engineKeyFor builds the registry key that identifies one Engine for addr
// given this instance's Connection pool and Passive health parameters.
func (m *CaddyWAF) engineKeyFor(addr string) engineKey {
	return engineKey{
		addr:               addr,
		initialCap:         m.InitialCap,
		maxIdle:            m.MaxIdle,
		maxCap:             m.MaxCap,
		idleTimeout:        m.IdleTimeout,
		healthMaxFails:     m.HealthMaxFails,
		healthFailDuration: time.Duration(m.HealthFailDuration),
	}
}

// newPool builds the t1k Connection pool for addr, or the injected test
// replacement when set.
func (m *CaddyWAF) newPool(pc *t1k.PoolConfig) (*t1k.ChannelPool, error) {
	if m.poolFactory != nil {
		return m.poolFactory(pc)
	}
	return initDetect(pc)
}

// acquireEngines acquires one shared Engine per configured Engine address from
// the process-wide registry, recording what was acquired in m.Engines and
// m.acquiredKeys. On any error every Engine already acquired for this instance
// is released again (provisioning rollback), so no reference leaks.
func (m *CaddyWAF) acquireEngines() error {
	m.Engines = make(EnginePool, len(m.WafEngineAddrs))
	m.acquiredKeys = make([]engineKey, 0, len(m.WafEngineAddrs))
	for i, addr := range m.WafEngineAddrs {
		key := m.engineKeyFor(addr)
		engine, _, err := acquireEngine(key, func() (caddy.Destructor, error) {
			pool, err := m.newPool(&t1k.PoolConfig{
				InitialCap:  m.InitialCap,
				MaxIdle:     m.MaxIdle,
				MaxCap:      m.MaxCap,
				Factory:     &t1k.TcpFactory{Addr: addr},
				IdleTimeout: m.IdleTimeout,
			})
			if err != nil {
				return nil, err
			}
			return &Engine{
				pool:         pool,
				addr:         addr,
				maxFails:     m.HealthMaxFails,
				failDuration: time.Duration(m.HealthFailDuration),
			}, nil
		})
		if err != nil {
			m.releaseAcquiredEngines()
			m.Engines = nil
			return fmt.Errorf("init detect error for %s: %v", addr, err)
		}
		m.Engines[i] = engine
		m.acquiredKeys = append(m.acquiredKeys, key)
	}
	return nil
}

// releaseAcquiredEngines releases every registry reference this instance
// acquired and clears the acquisition record. Used for provisioning rollback
// and Cleanup; Connection pool teardown happens inside the Engine's Destruct,
// deferred until the last referencing instance releases it.
func (m *CaddyWAF) releaseAcquiredEngines() {
	for _, key := range m.acquiredKeys {
		if _, err := releaseEngine(key); err != nil {
			if m.logger != nil {
				m.logger.Warn("failed to release WAF engine",
					zap.String("engine", key.addr),
					zap.Error(err))
			}
		}
	}
	m.acquiredKeys = nil
}

// Validate ensures module configuration is valid.
func (m *CaddyWAF) Validate() error {
	if m.LoadBalancing != nil && m.LoadBalancing.Retries < 0 {
		return fmt.Errorf("load_balancing.retries must be >= 0")
	}
	if m.MaxBodySize < 0 || m.MaxBodySize > maxBodySizeLimit {
		return fmt.Errorf("max_body_size must be between 0 and %d", maxBodySizeLimit)
	}
	return nil
}

type recombinedBody struct {
	io.Reader
	closer io.Closer
}

func (b *recombinedBody) Close() error {
	return b.closer.Close()
}

func (m *CaddyWAF) prepareDetectionRequest(r *http.Request) (func() *http.Request, error) {
	if m.MaxBodySize == 0 || r.Body == nil || (r.ContentLength >= 0 && r.ContentLength <= m.MaxBodySize) {
		return func() *http.Request { return r }, nil
	}

	body := r.Body
	buffered, err := io.ReadAll(io.LimitReader(body, m.MaxBodySize+1))
	r.Body = &recombinedBody{
		Reader: io.MultiReader(bytes.NewReader(buffered), body),
		closer: body,
	}
	if err != nil {
		return nil, err
	}

	detectBody := buffered
	if int64(len(detectBody)) > m.MaxBodySize {
		detectBody = detectBody[:m.MaxBodySize]
		wafMetrics.oversizeRequests.Inc()
	}

	return func() *http.Request {
		detectRequest := new(http.Request)
		*detectRequest = *r
		detectRequest.Body = io.NopCloser(bytes.NewReader(detectBody))
		detectRequest.ContentLength = int64(len(detectBody))
		detectRequest.GetBody = nil
		return detectRequest
	}, nil
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

	newDetectionRequest, err := m.prepareDetectionRequest(r)
	if err != nil {
		m.logger.Warn("reading request body for detection",
			zap.String("request", r.Host),
			zap.String("path", r.URL.Path),
			zap.String("method", r.Method),
			zap.Error(err))
		wafMetrics.requestsTotal.WithLabelValues("error").Inc()
		return next.ServeHTTP(w, r)
	}

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
		result, err := engine.DetectHttpRequest(newDetectionRequest())
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
		engine.fail()
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

// Cleanup releases the shared Engines this instance acquired at provisioning
// time. Metric series are per-Engine and are removed by the Engine's Destruct
// when the last referencing instance cleans up (registry reference count hits
// zero); the global metrics updater keeps running for the remaining Engines.
func (m *CaddyWAF) Cleanup() error {
	m.releaseAcquiredEngines()
	m.logger.Info("Cleaning up WAF plugin instance")
	return nil
}

var clientErrorPatterns = []string{
	// Body() client read errors (unexpected EOF / H2 CANCEL / H3 QUIC / connection reset, etc.).
	// Engine-side TCP resets lack this prefix, so they count as engine errors and enter passive health checks.
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

// Interface guards
var (
	_ caddy.Provisioner           = (*CaddyWAF)(nil)
	_ caddy.Validator             = (*CaddyWAF)(nil)
	_ caddy.CleanerUpper          = (*CaddyWAF)(nil)
	_ caddyhttp.MiddlewareHandler = (*CaddyWAF)(nil)
	_ caddyfile.Unmarshaler       = (*CaddyWAF)(nil)
	_ caddy.Destructor            = (*Engine)(nil)
)
