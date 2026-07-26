//go:build integration

package caddy_waf_t1k

import (
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	t1k "github.com/chaitin/t1k-go"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"go.uber.org/zap"
)

// engineFromEnv creates a real Engine backed by the address in $T1K_ADDR.
// The test is skipped (not failed) when T1K_ADDR is unset.
func engineFromEnv(t *testing.T) *Engine {
	t.Helper()
	addr := os.Getenv("T1K_ADDR")
	if addr == "" {
		t.Skip("T1K_ADDR not set; skipping real-engine integration test")
	}
	pool, err := t1k.NewChannelPool(&t1k.PoolConfig{
		InitialCap:  1,
		MaxIdle:     4,
		MaxCap:      8,
		Factory:     &t1k.TcpFactory{Addr: addr},
		IdleTimeout: 30 * time.Second,
	})
	if err != nil {
		t.Fatalf("connect to t1k engine %s: %v", addr, err)
	}
	t.Cleanup(func() { pool.Release() })
	return &Engine{pool: pool, addr: addr, maxFails: 0}
}

// newIntegrationWAF builds a CaddyWAF wired to engine with the given cap.
// Uses the same zero-allocation setup as newTestWAF but exposes MaxBodySize.
func newIntegrationWAF(t *testing.T, engine *Engine, maxBodySize int64) *CaddyWAF {
	t.Helper()
	ensureWAFMetrics(t)
	m := &CaddyWAF{
		logger:     zap.NewNop(),
		instanceID: "integration",
		Engines:    EnginePool{engine},
		LoadBalancing: &LoadBalancing{
			SelectionPolicy: &RoundRobinSelection{robin: ^uint32(0)},
			Retries:         0,
		},
		MaxBodySize: maxBodySize,
	}
	return m
}

// TestIntegrationBodyCapDetectionBlindSpot is the real-engine A/B test for the
// detection blind spot introduced by max_body_size.
//
// Three cases prove the blind spot is caused by the cap, not payload construction:
//
//	A. payload within cap   → engine sees the attack → request blocked
//	B. payload beyond cap   → engine only sees harmless padding → request passes
//	C. cap=0 (unlimited) with same padded body → engine sees the attack → request blocked
//
// The SQL injection payload is delivered in an application/x-www-form-urlencoded
// POST body so it is unambiguously a body-only vector (not URL or headers).
func TestIntegrationBodyCapDetectionBlindSpot(t *testing.T) {
	engine := engineFromEnv(t)

	// capBytes is intentionally small so we can construct a body that puts the
	// attack payload cleanly beyond the cap boundary.
	const capBytes = 64

	// sqlAttack is a classic SQL injection fragment placed in a form field.
	// It must fit entirely within capBytes characters (len = 13).
	const sqlAttack = "id=' OR 1=1--"

	// padding is benign filler that occupies exactly capBytes bytes.
	padding := strings.Repeat("a", capBytes)

	cases := []struct {
		name        string
		body        string
		maxBodySize int64
		wantBlocked bool
		desc        string
	}{
		{
			name:        "A_payload_within_cap",
			body:        sqlAttack,
			maxBodySize: capBytes,
			wantBlocked: true,
			desc:        "payload fits within cap; engine must block",
		},
		{
			name:        "B_payload_beyond_cap",
			body:        padding + "&" + sqlAttack,
			maxBodySize: capBytes,
			wantBlocked: false,
			desc:        "payload pushed past cap; engine only sees harmless padding and must pass",
		},
		{
			name:        "C_unlimited_cap_same_padded_body",
			body:        padding + "&" + sqlAttack,
			maxBodySize: 0,
			wantBlocked: true,
			desc:        "cap=0 means unlimited; engine sees full body and must block",
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			waf := newIntegrationWAF(t, engine, tc.maxBodySize)
			req := httptest.NewRequest(
				http.MethodPost,
				"http://example.com/waf-integration-test",
				strings.NewReader(tc.body),
			)
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			req.ContentLength = int64(len(tc.body))

			rr := httptest.NewRecorder()
			nextCalled := false

			err := waf.ServeHTTP(rr, req, caddyhttp.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) error {
				nextCalled = true
				return nil
			}))
			if err != nil {
				t.Fatalf("ServeHTTP returned error: %v", err)
			}

			blocked := rr.Code == http.StatusNotImplemented
			if blocked != tc.wantBlocked {
				if tc.wantBlocked {
					t.Errorf("%s: expected blocked (HTTP 501), got HTTP %d (next called: %v)",
						tc.desc, rr.Code, nextCalled)
				} else {
					t.Errorf("%s: expected passed (next handler called), got HTTP %d (blocked)",
						tc.desc, rr.Code)
				}
			}
		})
	}
}
