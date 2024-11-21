package caddy_waf_t1k

import (
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
//	}
func parseCaddyfileHandler(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	var m CaddyWAF
	err := m.UnmarshalCaddyfile(h.Dispenser)
	return m, err
}
