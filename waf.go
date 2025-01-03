package caddy_waf_t1k

import (
	"fmt"
	"net/http"
	"time"

	"github.com/chaitin/t1k-go"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"

	"go.uber.org/zap"
)

func init() {
	caddy.RegisterModule(CaddyWAF{})
}

type EnginePool []*t1k.ChannelPool

// CaddyWAF implements an HTTP handler for WAF.
type CaddyWAF struct {
	logger *zap.Logger

	WafEngineAddrs []string `json:"waf_engine_addrs,omitempty"` // WAF Engine address, expects a URL or IP address

	// Multiple WAF engine pools
	Engines EnginePool

	// Load balancing distributes load/requests between backends.
	LoadBalancing *LoadBalancing `json:"load_balancing,omitempty"`

	InitialCap  int           `json:"initial_cap,omitempty"`  // InitialCap is the initial capacity of the pool
	MaxIdle     int           `json:"max_idle,omitempty"`     // MaxIdle is the maximum number of idle connections in the pool
	MaxCap      int           `json:"max_cap,omitempty"`      // MaxCap is the maximum capacity of the pool
	IdleTimeout time.Duration `json:"idle_timeout,omitempty"` // IdleTimeout is the duration after which an idle connection is closed
	// block_tpl_path string `json:"block_tpl_path"` // Block template path
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
		m.Engines[i] = engine
	}
	m.logger.Info("WAF plugin instance Provisioned")
	return nil
}

// ServeHTTP processes incoming HTTP requests by utilizing the Caddy WAF engine to detect
// potential threats. If a request is identified as malicious, it redirects the request to
// an intercept handler. Otherwise, it passes the request to the next handler in the chain.
// The method handles detection errors and enforces a timeout for the detection process,
// logging relevant information in each case.
func (m CaddyWAF) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {

	// choose an available WAF upstream
	engine := m.LoadBalancing.SelectionPolicy.Select(m.Engines, r, w)
	if engine == nil {
		return fmt.Errorf("no available WAF engine for request %s %s", r.Method, r.URL.Path)
	}

	result, err := engine.DetectHttpRequest(r)
	if err != nil {
		m.logger.Error("DetectHttpRequest error",
			zap.String("request", r.Host),
			zap.String("path", r.URL.Path),
			zap.String("method", r.Method),
			zap.Error(err))
		return next.ServeHTTP(w, r)
	}
	if result.Blocked() {
		return m.redirectIntercept(w, result)
	}
	return next.ServeHTTP(w, r)
}

// Cleans up the WAF plugin instance by closing the WAF engine and logging the cleanup process.
func (m CaddyWAF) Cleanup() error {
	for _, engine := range m.Engines {
		if engine != nil {
			engine.Release()
		}
	}
	m.logger.Info("Cleaning up WAF plugin instance")
	return nil
}

// Interface guards
var (
	_ caddy.Provisioner           = (*CaddyWAF)(nil)
	_ caddyhttp.MiddlewareHandler = (*CaddyWAF)(nil)
	_ caddyfile.Unmarshaler       = (*CaddyWAF)(nil)
)
