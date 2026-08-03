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

func TestUnmarshalCaddyfileMaxBodySize(t *testing.T) {
	for _, tt := range []struct {
		name  string
		value string
		want  int64
	}{
		{name: "IEC", value: "1MiB", want: 1 << 20},
		{name: "SI", value: "1MB", want: 1_000_000},
		{name: "kilobytes", value: "512KB", want: 512_000},
		{name: "bare bytes", value: "1024", want: 1024},
		{name: "unlimited", value: "0", want: 0},
	} {
		t.Run(tt.name, func(t *testing.T) {
			input := "waf_chaitin {\n\twaf_engine_addr 192.0.2.1:8000\n\tmax_body_size " + tt.value + "\n}"
			d := caddyfile.NewTestDispenser(input)
			var m CaddyWAF
			if err := m.UnmarshalCaddyfile(d); err != nil {
				t.Fatalf("UnmarshalCaddyfile: %v", err)
			}
			if m.MaxBodySize != tt.want {
				t.Errorf("MaxBodySize = %d, want %d", m.MaxBodySize, tt.want)
			}
		})
	}
}

func TestUnmarshalCaddyfileMaxBodySizeInvalid(t *testing.T) {
	for _, value := range []string{"not-a-size", "999999999999999999999999999999"} {
		input := "waf_chaitin {\n\twaf_engine_addr 192.0.2.1:8000\n\tmax_body_size " + value + "\n}"
		d := caddyfile.NewTestDispenser(input)
		var m CaddyWAF
		if err := m.UnmarshalCaddyfile(d); err == nil {
			t.Fatalf("expected error for max_body_size %q", value)
		}
	}
}
