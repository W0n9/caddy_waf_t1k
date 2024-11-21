package caddy_waf_t1k

import (
	"net/http"
	"os"

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
func initDetect(detectorAddr string) (*t1k.Server, error) {
	server, err := t1k.NewWithPoolSize(detectorAddr, 10)
	return server, err
}

// Provision sets up the WAF module.
func (m *CaddyWAF) Provision(ctx caddy.Context) error {
	m.logger = ctx.Logger(m)
	m.logger.Info("Provisioning WAF plugin instance")

	if m.WafEngineAddr == "" {
		m.logger.Fatal("WAF Engine Address is required")
		os.Exit(1)
	}

	wafEngine, err := initDetect(m.WafEngineAddr)
	if err != nil {
		m.logger.Fatal("init detect error", zap.Error(err))
		os.Exit(1)
	}

	m.wafEngine = wafEngine
	return nil
}

// Validate validates the WAF module configuration.
func (m *CaddyWAF) Validate() error {
	m.logger.Info("Validating WAF plugin configuration")
	return nil
}

// ServeHTTP handles HTTP requests and applies WAF logic.
func (m CaddyWAF) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
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

// Start starts the WAF module.
func (m CaddyWAF) Start() error {
	m.logger.Info("WAF module started.")
	return nil
}

// Stop stops the WAF module.
func (m CaddyWAF) Stop() error {
	m.logger.Info("WAF module stopped.")
	return nil
}

// Interface guards
var (
	_ caddy.Provisioner           = (*CaddyWAF)(nil)
	_ caddy.Validator             = (*CaddyWAF)(nil)
	_ caddyhttp.MiddlewareHandler = (*CaddyWAF)(nil)
	_ caddyfile.Unmarshaler       = (*CaddyWAF)(nil)
)
