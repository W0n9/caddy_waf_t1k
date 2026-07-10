package caddy_waf_t1k

import (
	"testing"

	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
)

func TestUnmarshalCaddyfileLBRetries(t *testing.T) {
	input := `waf_chaitin {
		waf_engine_addr 192.0.2.1:8000
		lb_retries 2
	}`
	d := caddyfile.NewTestDispenser(input)
	var m CaddyWAF
	if err := m.UnmarshalCaddyfile(d); err != nil {
		t.Fatalf("UnmarshalCaddyfile: %v", err)
	}
	if m.LoadBalancing == nil {
		t.Fatal("LoadBalancing is nil")
	}
	if m.LoadBalancing.Retries != 2 {
		t.Fatalf("Retries = %d, want 2", m.LoadBalancing.Retries)
	}
}

func TestUnmarshalCaddyfileLBRetriesDefault(t *testing.T) {
	input := `waf_chaitin {
		waf_engine_addr 192.0.2.1:8000
	}`
	d := caddyfile.NewTestDispenser(input)
	var m CaddyWAF
	if err := m.UnmarshalCaddyfile(d); err != nil {
		t.Fatalf("UnmarshalCaddyfile: %v", err)
	}
	if m.LoadBalancing != nil && m.LoadBalancing.Retries != 0 {
		t.Fatalf("Retries = %d, want 0", m.LoadBalancing.Retries)
	}
}

func TestUnmarshalCaddyfileLBRetriesInvalid(t *testing.T) {
	input := `waf_chaitin {
		waf_engine_addr 192.0.2.1:8000
		lb_retries -1
	}`
	d := caddyfile.NewTestDispenser(input)
	var m CaddyWAF
	if err := m.UnmarshalCaddyfile(d); err == nil {
		t.Fatal("expected error for negative lb_retries")
	}
}
