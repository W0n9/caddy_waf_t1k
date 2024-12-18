package caddy_waf_t1k

import (
	"strconv"
	"time"

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
			if !d.NextArg() {
				return d.ArgErr()
			}
			m.WafEngineAddr = d.Val()
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
			idleTimeout, err := strconv.Atoi(d.Val())
			if err != nil {
				return d.Errf("invalid idle_timeout value: %v", err)
			}
			m.IdleTimeout = time.Duration(idleTimeout) * time.Second
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
//	    waf_engine_addr 169.254.0.5:8000
//		initial_cap 1
//		max_idle 16
//		max_cap 32
//		idle_timeout 30
//	}
func parseCaddyfileHandler(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	var m CaddyWAF
	err := m.UnmarshalCaddyfile(h.Dispenser)
	return m, err
}
