package caddy_waf_t1k

import (
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

func init() {
	httpcaddyfile.RegisterHandlerDirective("waf_chaitin", parseCaddyfileHandler) // Register the directive
}

// UnmarshalCaddyfile implements caddyfile.Unmarshaler.
func (m *CaddyWAF) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	if !d.Next() {
		return d.Err("expected tokens")
	}

	for nesting := d.Nesting(); d.NextBlock(nesting); {
		switch d.Val() {
		case "waf_engine_addr":
			args := d.RemainingArgs()
			if len(args) == 0 {
				return d.ArgErr()
			}
			for _, addr := range args {
				host, port, err := net.SplitHostPort(addr)
				if err != nil {
					return d.Errf("invalid address format %q: %v", addr, err)
				}
				if net.ParseIP(host) == nil {
					return d.Errf("invalid IP address: %s", host)
				}
				if _, err := strconv.Atoi(port); err != nil {
					return d.Errf("invalid port number: %s", port)
				}
			}
			m.WafEngineAddrs = args
		case "initial_cap":
			if !d.NextArg() {
				return d.ArgErr()
			}
			initialCap, err := strconv.Atoi(d.Val())
			if err != nil {
				return d.Errf("invalid initial_cap value: %v", err)
			}
			m.InitialCap = initialCap
		case "max_idle":
			if !d.NextArg() {
				return d.ArgErr()
			}
			maxIdle, err := strconv.Atoi(d.Val())
			if err != nil {
				return d.Errf("invalid max_idle value: %v", err)
			}
			m.MaxIdle = maxIdle
		case "max_cap":
			if !d.NextArg() {
				return d.ArgErr()
			}
			maxCap, err := strconv.Atoi(d.Val())
			if err != nil {
				return d.Errf("invalid max_cap value: %v", err)
			}
			m.MaxCap = maxCap
		case "idle_timeout":
			if !d.NextArg() {
				return d.ArgErr()
			}
			dur, err := caddy.ParseDuration(d.Val())
			if err != nil {
				return d.Errf("invalid idle_timeout value: %v", err)
			}
			m.IdleTimeout = dur
		case "health_check_interval":
			if !d.NextArg() {
				return d.ArgErr()
			}
			dur, err := caddy.ParseDuration(d.Val())
			if err != nil {
				return d.Errf("invalid health_check_interval value: %v", err)
			}
			m.HealthCheckInterval = caddy.Duration(dur)
		case "failure_threshold":
			if !d.NextArg() {
				return d.ArgErr()
			}
			n, err := strconv.Atoi(d.Val())
			if err != nil {
				return d.Errf("invalid failure_threshold value: %v", err)
			}
			m.FailureThreshold = n
		case "recovery_threshold":
			if !d.NextArg() {
				return d.ArgErr()
			}
			n, err := strconv.Atoi(d.Val())
			if err != nil {
				return d.Errf("invalid recovery_threshold value: %v", err)
			}
			m.RecoveryThreshold = n
		case "lb_policy":
			if !d.NextArg() {
				return d.ArgErr()
			}
			if m.LoadBalancing != nil && m.LoadBalancing.SelectionPolicyRaw != nil {
				return d.Err("load balancing selection policy already specified")
			}
			name := d.Val()
			modID := "http.waf_chaitin.selection_policies." + name
			unm, err := caddyfile.UnmarshalModule(d, modID)
			if err != nil {
				return err
			}
			sel, ok := unm.(Selector)
			if !ok {
				return d.Errf("module %s (%T) is not a waf_chaitin.Selector", modID, unm)
			}
			if m.LoadBalancing == nil {
				m.LoadBalancing = new(LoadBalancing)
			}
			m.LoadBalancing.SelectionPolicyRaw = caddyconfig.JSONModuleObject(sel, "policy", name, nil)
		case "skip_content_types":
			args := d.RemainingArgs()
			if len(args) == 0 {
				return d.ArgErr()
			}
			m.SkipContentTypes = args
		case "skip_header":
			if !d.NextArg() {
				return d.ArgErr()
			}
			m.SkipHeader = d.Val()
		case "max_body_size":
			if !d.NextArg() {
				return d.ArgErr()
			}
			n, err := parseByteSize(d.Val())
			if err != nil {
				return d.Errf("invalid max_body_size value: %v", err)
			}
			m.MaxBodyBytes = n
		case "log_blocked_requests":
			if !d.NextArg() {
				return d.ArgErr()
			}
			switch d.Val() {
			case "on":
				m.LogBlockedRequests = true
			case "off":
				m.LogBlockedRequests = false
			default:
				return d.Errf("log_blocked_requests must be on or off, got %q", d.Val())
			}
		default:
			return d.Errf("unrecognized subdirective %s", d.Val())
		}
	}
	return nil
}

// parseCaddyfileHandler unmarshals tokens from h into a new middleware handler value.
// syntax:
//
//	waf_chaitin {
//	    waf_engine_addr 169.254.0.5:8000 169.254.0.6:8000 169.254.0.7:8000
//		initial_cap 1
//		max_idle 16
//		max_cap 32
//		idle_timeout 30s
//	    health_check_interval 10s
//	    failure_threshold 3
//	    recovery_threshold 2
//	}
func parseCaddyfileHandler(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	var m CaddyWAF
	err := m.UnmarshalCaddyfile(h.Dispenser)
	return m, err
}

// parseByteSize parses human-readable byte sizes like "1MB", "512KB", "1073741824".
func parseByteSize(s string) (int64, error) {
	if n, err := strconv.ParseInt(s, 10, 64); err == nil {
		return n, nil
	}
	suffixes := []struct {
		suffix string
		mult   int64
	}{
		{"GB", 1024 * 1024 * 1024},
		{"MB", 1024 * 1024},
		{"KB", 1024},
	}
	upper := strings.ToUpper(s)
	for _, sf := range suffixes {
		if strings.HasSuffix(upper, sf.suffix) {
			numStr := s[:len(s)-len(sf.suffix)]
			n, err := strconv.ParseInt(strings.TrimSpace(numStr), 10, 64)
			if err != nil {
				return 0, fmt.Errorf("invalid byte size %q: %v", s, err)
			}
			return n * sf.mult, nil
		}
	}
	return 0, fmt.Errorf("unrecognized byte size format %q (use KB, MB, GB or plain bytes)", s)
}
