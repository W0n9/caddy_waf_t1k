package caddy_waf_t1k

import (
	"testing"

	"github.com/caddyserver/caddy/v2/caddytest"
)

func TestWAFChaitinDirective(t *testing.T) {
	// arrange
	tester := caddytest.NewTester(t)
	tester.InitServer(`
	{
		admin localhost:2999
		http_port     9080
		https_port    9443
		grace_period  1ns
	}

	localhost:9080 {
		waf_chaitin {
			waf_engine_addr 169.254.0.5:8000
			initial_cap 1
			max_idle 16
			max_cap 32
			idle_timeout 30
		}
		respond /test 200 {
			body "WAF Chaitin Configured"
		}
	}
	`, "caddyfile")

	// act and assert
	tester.AssertGetResponse("http://localhost:9080/test", 200, "WAF Chaitin Configured")
}

func TestWAFChaitinDirectiveInvalidInitialCap(t *testing.T) {
	// arrange
	tester := caddytest.NewTester(t)
	tester.InitServer(`
	{
		admin localhost:2999
		http_port     9080
		https_port    9443
		grace_period  1ns
	}

	localhost:9080 {
		waf_chaitin {
			waf_engine_addr 169.254.0.5:8000
			initial_cap invalid
			max_idle 16
			max_cap 32
			idle_timeout 30
		}
		respond /test 200 {
			body "WAF Chaitin Configured"
		}
	}
	`, "caddyfile")

	// act and assert
	tester.AssertLoadError(t, `
	{
		admin localhost:2999
		http_port     9080
		https_port    9443
		grace_period  1ns
	}

	localhost:9080 {
		waf_chaitin {
			waf_engine_addr 169.254.0.5:8000
			initial_cap invalid
			max_idle 16
			max_cap 32
			idle_timeout 30
		}
		respond /test 200 {
			body "WAF Chaitin Configured"
		}
	}
	`, "caddyfile", "invalid initial_cap value")
}

func TestWAFChaitinDirectiveInvalidMaxIdle(t *testing.T) {
	// arrange
	tester := caddytest.NewTester(t)
	tester.InitServer(`
	{
		admin localhost:2999
		http_port     9080
		https_port    9443
		grace_period  1ns
	}

	localhost:9080 {
		waf_chaitin {
			waf_engine_addr 169.254.0.5:8000
			initial_cap 1
			max_idle invalid
			max_cap 32
			idle_timeout 30
		}
		respond /test 200 {
			body "WAF Chaitin Configured"
		}
	}
	`, "caddyfile")

	// act and assert
	tester.AssertLoadError(t, `
	{
		admin localhost:2999
		http_port     9080
		https_port    9443
		grace_period  1ns
	}

	localhost:9080 {
		waf_chaitin {
			waf_engine_addr 169.254.0.5:8000
			initial_cap 1
			max_idle invalid
			max_cap 32
			idle_timeout 30
		}
		respond /test 200 {
			body "WAF Chaitin Configured"
		}
	}
	`, "caddyfile", "invalid max_idle value")
}

func TestWAFChaitinDirectiveInvalidMaxCap(t *testing.T) {
	// arrange
	tester := caddytest.NewTester(t)
	tester.InitServer(`
	{
		admin localhost:2999
		http_port     9080
		https_port    9443
		grace_period  1ns
	}

	localhost:9080 {
		waf_chaitin {
			waf_engine_addr 169.254.0.5:8000
			initial_cap 1
			max_idle 16
			max_cap invalid
			idle_timeout 30
		}
		respond /test 200 {
			body "WAF Chaitin Configured"
		}
	}
	`, "caddyfile")

	// act and assert
	tester.AssertLoadError(t, `
	{
		admin localhost:2999
		http_port     9080
		https_port    9443
		grace_period  1ns
	}

	localhost:9080 {
		waf_chaitin {
			waf_engine_addr 169.254.0.5:8000
			initial_cap 1
			max_idle 16
			max_cap invalid
			idle_timeout 30
		}
		respond /test 200 {
			body "WAF Chaitin Configured"
		}
	}
	`, "caddyfile", "invalid max_cap value")
}

func TestWAFChaitinDirectiveInvalidIdleTimeout(t *testing.T) {
	// arrange
	tester := caddytest.NewTester(t)
	tester.InitServer(`
	{
		admin localhost:2999
		http_port     9080
		https_port    9443
		grace_period  1ns
	}

	localhost:9080 {
		waf_chaitin {
			waf_engine_addr 169.254.0.5:8000
			initial_cap 1
			max_idle 16
			max_cap 32
			idle_timeout invalid
		}
		respond /test 200 {
			body "WAF Chaitin Configured"
		}
	}
	`, "caddyfile")

	// act and assert
	tester.AssertLoadError(t, `
	{
		admin localhost:2999
		http_port     9080
		https_port    9443
		grace_period  1ns
	}

	localhost:9080 {
		waf_chaitin {
			waf_engine_addr 169.254.0.5:8000
			initial_cap 1
			max_idle 16
			max_cap 32
			idle_timeout invalid
		}
		respond /test 200 {
			body "WAF Chaitin Configured"
		}
	}
	`, "caddyfile", "invalid idle_timeout value")
}
