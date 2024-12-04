package caddy_waf_t1k

import (
	"fmt"
	"net/http"

	"github.com/chaitin/t1k-go"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"

	"go.uber.org/zap"
)

func init() {
	caddy.RegisterModule(CaddyWAF{})
}

// CaddyWAF implements an HTTP handler for WAF.
type CaddyWAF struct {
	WafEngineAddr string `json:"waf_engine_addr,omitempty"` // WAF Engine address
	logger        *zap.Logger
	wafEngine     *t1k.Server
	PoolSize      int `json:"pool_size,omitempty"` // Pool size
	// mu            sync.Mutex
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
func initDetect(detectorAddr string, poolSize int) (*t1k.Server, error) {
	server, err := t1k.NewWithPoolSize(detectorAddr, poolSize)
	return server, err
}

// Provision sets up the WAF module.
func (m *CaddyWAF) Provision(ctx caddy.Context) error {
	m.logger = ctx.Logger(m)
	m.logger.Info("Provisioning WAF plugin instance")

	if m.WafEngineAddr == "" {
		return fmt.Errorf("web application firewall engine address is required")
	}

	if m.PoolSize == 0 {
		return fmt.Errorf("pool size is required")
	}

	wafEngine, err := initDetect(m.WafEngineAddr, m.PoolSize)
	if err != nil {
		return fmt.Errorf("init detect error: %v", err)
	}

	m.wafEngine = wafEngine
	m.logger.Info("WAF plugin instance Provisioned")
	return nil
}

// // Validate validates the WAF module configuration.
// func (m *CaddyWAF) Validate() error {
// 	m.logger.Info("Validating WAF plugin configuration")
// 	return nil
// }

// ServeHTTP is the main handler for the CaddyWAF middleware. It processes incoming HTTP requests,
// uses the WAF engine to detect potential threats, and takes appropriate actions based on the detection results.
// If a threat is detected and blocked, it redirects the request to an intercept page. Otherwise, it passes the request
// to the next handler in the chain.
func (m CaddyWAF) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	// wafEngine, err := initDetect(m.WafEngineAddr, m.PoolSize)
	// if err != nil {
	// 	m.logger.Error("init WAF detector error", zap.Error(err))
	// 	return next.ServeHTTP(w, r)
	// }
	// m.wafEngine = wafEngine
	result, err := m.wafEngine.DetectHttpRequest(r)
	if err != nil {
		m.logger.Error("DetectHttpRequest error", zap.Error(err))
		return next.ServeHTTP(w, r)
	}
	if result.Blocked() {
		return m.redirectIntercept(w, result)
	}
	return next.ServeHTTP(w, r)
}

// Cleanup releases resources associated with the CaddyWAF instance.
// It closes the WAF engine and logs the cleanup action.
// Returns an error if any issues occur during the cleanup process.
func (m CaddyWAF) Cleanup() error {
	m.wafEngine.Close()
	m.logger.Info("Cleaning up WAF plugin instance")
	return nil
}

// Interface guards
var (
	_ caddy.Provisioner = (*CaddyWAF)(nil)
	// _ caddy.Validator             = (*CaddyWAF)(nil)
	_ caddyhttp.MiddlewareHandler = (*CaddyWAF)(nil)
	_ caddyfile.Unmarshaler       = (*CaddyWAF)(nil)
)
