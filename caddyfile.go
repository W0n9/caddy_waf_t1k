package caddy_waf_t1k

import (
	"fmt"
	"net"
	"strconv"

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
			fmt.Printf("idle_timeout: %v\n", dur)
			if err != nil {
				return d.Errf("bad idle_timeout value '%s': %v", d.Val(), err)
			}
			m.IdleTimeout = dur
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
//	}
func parseCaddyfileHandler(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	var m CaddyWAF
	err := m.UnmarshalCaddyfile(h.Dispenser)
	return m, err
}
