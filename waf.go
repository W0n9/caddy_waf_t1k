package caddy_waf_t1k

import (
	"fmt"
	"net/http"
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

// CaddyWAF implements an HTTP handler for WAF.
type CaddyWAF struct {
	WafEngineAddr string `json:"waf_engine_addr,omitempty"` // WAF Engine address, expects a URL or IP address
	logger        *zap.Logger
	wafEngine     *t1k.Server
	PoolSize      int           `json:"pool_size,omitempty"` // Pool size determines the number of concurrent connections the WAF engine can handle
	Timeout       time.Duration `json:"timeout,omitempty"`   // Timeout for WAF detection to process an HTTP request
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

	if m.Timeout == time.Duration(0)*time.Millisecond {
		return fmt.Errorf("timeout is required")
	}

	wafEngine, err := initDetect(m.WafEngineAddr, m.PoolSize)
	if err != nil {
		return fmt.Errorf("init detect error: %v", err)
	}

	m.wafEngine = wafEngine
	if m.wafEngine == nil {
		return fmt.Errorf("wafEngine initialization failed")
	}

	m.logger.Info("WAF plugin instance Provisioned")
	return nil
}

// // Validate validates the WAF module configuration.
// func (m *CaddyWAF) Validate() error {
// 	m.logger.Info("Validating WAF plugin configuration")
// 	return nil
// }

// ServeHTTP processes incoming HTTP requests by utilizing the Caddy WAF engine to detect
// potential threats. If a request is identified as malicious, it redirects the request to
// an intercept handler. Otherwise, it passes the request to the next handler in the chain.
// The method handles detection errors and enforces a timeout for the detection process,
// logging relevant information in each case.
func (m CaddyWAF) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {

	// result, err := m.wafEngine.DetectHttpRequest(r)
	// if err != nil {
	// 	m.logger.Error("DetectHttpRequest error", zap.Error(err))
	// 	return next.ServeHTTP(w, r)
	// }
	// if result.Blocked() {
	// 	return m.redirectIntercept(w, result)
	// }
	// return next.ServeHTTP(w, r)

	resultCh := make(chan *detection.Result, 1)
	errCh := make(chan error, 1)

	go func() {
		// TODO: Add logging for WAF processing duration
		// start := time.Now()
		// defer func() {
		// 	// Log the total duration taken to process the request
		// 	m.logger.Info("WAF detection processed", zap.Duration("duration", time.Since(start)))
		// 	m.logger.Info("Processing", zap.String("request", r.Host), zap.String("path", r.URL.Path))
		// }()

		result, err := m.wafEngine.DetectHttpRequest(r)
		if err != nil {
			errCh <- err
			return
		}
		resultCh <- result
	}()

	select {
	case result := <-resultCh:
		if result.Blocked() {
			return m.redirectIntercept(w, result)
		}
	case err := <-errCh:
		m.logger.Error("DetectHttpRequest error", zap.String("request", r.Host), zap.String("path", r.URL.Path), zap.String("method", r.Method), zap.Error(err))
		return next.ServeHTTP(w, r)
	case <-time.After(m.Timeout):
		m.logger.Error("DetectHttpRequest timeout", zap.String("request", r.Host), zap.String("path", r.URL.Path), zap.String("method", r.Method))
		return next.ServeHTTP(w, r)
	}
	return next.ServeHTTP(w, r)
}

// Cleans up the WAF plugin instance by closing the WAF engine and logging the cleanup process.
func (m CaddyWAF) Cleanup() error {
	if m.wafEngine != nil {
		m.wafEngine.Close()
	}
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
