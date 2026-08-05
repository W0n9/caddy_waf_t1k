//go:build integration

package caddy_waf_t1k

// T5 of #45: prove the shared-pool promise of #45 against a real SafeLine
// Engine. Two WAF instances over one Engine address share a single Engine and
// its real Connection pool, real detection requests succeed through the shared
// Engine, and the pool is released when the last reference is cleaned up.
//
// The Engine address comes from the runtime $T1K_ADDR environment variable
// (supplied by the operator, never committed to the repo). The whole test is
// skipped when T1K_ADDR is unset.

import (
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

// poolClosedErrMsg is the error text t1k.ChannelPool returns for any
// operation after Release; it distinguishes a released pool from a live one.
const poolClosedErrMsg = "pool is closed"

// realPoolWAF builds a CaddyWAF wired to the real Engine at addr through the
// process-wide registry path (acquireEngines), exactly like Provision does.
// All instances use identical shaping parameters so they must share one Engine.
// InitialCap 1 makes the real pool dial one connection to the Engine up front,
// so connection-count assertions run against an established connection.
func realPoolWAF(addr string) *CaddyWAF {
	return testWAFInstance([]string{addr}, func(m *CaddyWAF) {
		m.InitialCap = 1
		m.MaxIdle = 2
		m.MaxCap = 4
	})
}

// TestIntegrationSharedPoolRefcountAndConnectionCount proves that two WAF
// instances over the same real Engine address share one Engine and one real
// Connection pool: the registry reference count becomes 2 while the pool's
// open-connection count stays flat on the second acquire.
//
// Sequence:
//  1. m1 acquires the Engine for the real address (registry: 1 ref, pool dials
//     one real connection).
//  2. m2 acquires the same address with identical parameters: the same Engine
//     and pool are returned — references 2, open connections unchanged.
//  3. A real detection request through m2 (the second instance's view of the
//     shared Engine) returns a result.
//  4. Cleanup of m1 leaves the shared Engine alive (references 1).
//  5. Cleanup of m2 removes the registry entry and releases the real pool.
func TestIntegrationSharedPoolRefcountAndConnectionCount(t *testing.T) {
	addr := os.Getenv("T1K_ADDR")
	if addr == "" {
		t.Skip("T1K_ADDR not set; skipping real-engine integration test")
	}
	ensureWAFMetrics(t)

	m1 := realPoolWAF(addr)
	if err := m1.acquireEngines(); err != nil {
		t.Fatalf("m1 acquireEngines: %v", err)
	}
	m2 := realPoolWAF(addr)
	if err := m2.acquireEngines(); err != nil {
		t.Fatalf("m2 acquireEngines: %v", err)
	}
	// Acquire failures are handled above; from here on every exit path must
	// release the acquired references so no Engine leaks into later tests.
	t.Cleanup(func() {
		_ = m1.Cleanup()
		_ = m2.Cleanup()
	})

	if m1.Engines[0] != m2.Engines[0] {
		t.Fatal("identical address+config must share one real Engine")
	}
	key := m1.acquiredKeys[0]
	if refs, ok := engineRegistry.References(key); !ok || refs != 2 {
		t.Fatalf("registry references for %s = %d (exists %v), want 2", addr, refs, ok)
	}

	pool := m1.Engines[0].pool
	if pool == nil {
		t.Fatal("shared Engine has no real Connection pool")
	}

	// The second acquire reused the Engine and its pool: no additional TCP
	// connection was opened for the second instance. ActiveConns is t1k's
	// openingConns — total open connections (idle + in-use) — which the first
	// acquire established at InitialCap 1.
	stats := m1.Engines[0].poolStats()
	if stats.ActiveConns != 1 {
		t.Errorf("pool open connections after second acquire = %d, want 1 (no growth)", stats.ActiveConns)
	}

	// A real detection request through the second instance's view of the
	// shared Engine returns a verdict. DetectHttpRequest is called directly
	// rather than via ServeHTTP: T5's contract is the shared Engine and its
	// Connection pool, and full ServeHTTP detection is already covered by the
	// body-cap real-engine test.
	result, err := m2.Engines[0].DetectHttpRequest(sqlInjectionRequest())
	if err != nil {
		t.Fatalf("real detection through shared Engine: %v", err)
	}
	if result == nil {
		t.Fatal("real detection through shared Engine returned no result")
	}

	// The first cleanup drops one reference; the shared pool stays alive.
	if err := m1.Cleanup(); err != nil {
		t.Fatalf("m1 Cleanup: %v", err)
	}
	if refs, ok := engineRegistry.References(key); !ok || refs != 1 {
		t.Fatalf("after m1 Cleanup references = %d (exists %v), want 1", refs, ok)
	}
	if conn, err := pool.Get(); err != nil {
		if strings.Contains(err.Error(), poolClosedErrMsg) {
			t.Fatalf("pool released too early: %v", err)
		}
		t.Fatalf("pool.Get after m1 Cleanup: %v", err)
	} else {
		_ = pool.Put(conn)
	}

	// The last cleanup removes the registry entry and releases the real pool.
	if err := m2.Cleanup(); err != nil {
		t.Fatalf("m2 Cleanup: %v", err)
	}
	if refs, ok := engineRegistry.References(key); ok {
		t.Fatalf("after m2 Cleanup references = %d (exists %v), want gone", refs, ok)
	}
	if _, err := pool.Get(); err == nil || !strings.Contains(err.Error(), poolClosedErrMsg) {
		t.Fatalf("real pool not released after last Cleanup: %v", err)
	}
}

// sqlInjectionRequest is a body-only SQL injection POST. The payload is
// delivered in an application/x-www-form-urlencoded body so it is an
// unambiguous body-only vector, and it is the same payload the existing
// real-engine body-cap test proves SafeLine blocks.
func sqlInjectionRequest() *http.Request {
	const sqlAttack = "id=' OR 1=1--"
	req := httptest.NewRequest(
		http.MethodPost,
		"http://example.com/shared-pool-integration-test",
		strings.NewReader(sqlAttack),
	)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.ContentLength = int64(len(sqlAttack))
	return req
}
