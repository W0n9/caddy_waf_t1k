//go:build integration

package caddy_waf_t1k

// T5 of #45: prove the shared-pool promise of #45 against a real SafeLine
// Engine. Two WAF instances over one Engine address share a single Engine and
// its real Connection pool, real detection requests succeed through the shared
// Engine, and the pool is released when the last reference is cleaned up.
//
// The Engine addresses come from the runtime $T1K_ADDR environment variable
// (supplied by the operator, never committed to the repo). T1K_ADDR may hold a
// comma- or space-separated list so multi-Engine sharing and failover run
// against every real Engine the operator supplies; the tests are skipped when
// T1K_ADDR is unset.

import (
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

// poolClosedErrMsg is the error text t1k.ChannelPool returns for any
// operation after Release; it distinguishes a released pool from a live one.
const poolClosedErrMsg = "pool is closed"

// unreachableEngineAddr is a fixed localhost port that refuses connections
// instantly. It stands in for a dead Engine so failover tests have a
// deterministic unreachable target without committing any real Engine address.
const unreachableEngineAddr = "127.0.0.1:1"

// engineAddrsFromEnv returns the Engine addresses in $T1K_ADDR, splitting on
// commas and whitespace and trimming each entry. The test is skipped (not
// failed) when T1K_ADDR is unset.
func engineAddrsFromEnv(t *testing.T) []string {
	t.Helper()
	raw := os.Getenv("T1K_ADDR")
	if raw == "" {
		t.Skip("T1K_ADDR not set; skipping real-engine integration test")
	}
	var addrs []string
	for _, a := range strings.FieldsFunc(raw, func(r rune) bool { return r == ',' || r == ' ' }) {
		if a != "" {
			addrs = append(addrs, a)
		}
	}
	if len(addrs) == 0 {
		t.Fatal("T1K_ADDR set but contains no addresses")
	}
	return addrs
}

// realPoolWAF builds a CaddyWAF wired to the real Engines at addrs through the
// process-wide registry path (acquireEngines), exactly like Provision does.
// All instances use identical shaping parameters so they must share one Engine
// per address. InitialCap 1 makes each real pool dial one connection to its
// Engine up front, so connection-count assertions run against established
// connections.
func realPoolWAF(addrs []string) *CaddyWAF {
	return testWAFInstance(addrs, func(m *CaddyWAF) {
		m.InitialCap = 1
		m.MaxIdle = 2
		m.MaxCap = 4
	})
}

// TestIntegrationSharedPoolRefcountAndConnectionCount proves that two WAF
// instances over the same Engine addresses share one Engine and one real
// Connection pool per address: every registry reference count becomes 2 while
// the pools' open-connection counts stay flat on the second acquire.
//
// Sequence:
//  1. m1 acquires one Engine per address (registry: 1 ref each, each pool dials
//     one real connection).
//  2. m2 acquires the same addresses with identical parameters: the same
//     Engines and pools are returned — references 2, open connections unchanged.
//  3. A real detection request through m2 (the second instance's view of a
//     shared Engine) returns a result.
//  4. Cleanup of m1 leaves every shared Engine alive (references 1).
//  5. Cleanup of m2 removes the registry entries and releases the real pools.
func TestIntegrationSharedPoolRefcountAndConnectionCount(t *testing.T) {
	addrs := engineAddrsFromEnv(t)
	ensureWAFMetrics(t)

	m1 := realPoolWAF(addrs)
	if err := m1.acquireEngines(); err != nil {
		t.Fatalf("m1 acquireEngines: %v", err)
	}
	// Baseline open connections per pool before the second instance acquires:
	// ActiveConns is t1k's openingConns (total open connections, idle + in-use),
	// which the first acquire established via InitialCap 1.
	baseline := make([]int, len(addrs))
	for i := range addrs {
		baseline[i] = m1.Engines[i].poolStats().ActiveConns
	}
	m2 := realPoolWAF(addrs)
	if err := m2.acquireEngines(); err != nil {
		t.Fatalf("m2 acquireEngines: %v", err)
	}
	// Acquire failures are handled above; from here on every exit path must
	// release the acquired references so no Engine leaks into later tests.
	t.Cleanup(func() {
		_ = m1.Cleanup()
		_ = m2.Cleanup()
	})

	// Distinct Engine addresses must map to distinct Engines (per-address
	// independence); the two instances then share one Engine per address.
	for i := 1; i < len(addrs); i++ {
		if addrs[i] == addrs[0] {
			continue
		}
		if m1.Engines[i] == m1.Engines[0] {
			t.Fatalf("address %s: distinct Engine addresses must yield distinct Engines", addrs[i])
		}
	}

	// m1 and m2 share one Engine per address: references 2, and no additional
	// TCP connection is opened for the second instance.
	for i, addr := range addrs {
		if m1.Engines[i] != m2.Engines[i] {
			t.Fatalf("address %s: identical address+config must share one real Engine", addr)
		}
		key := m1.acquiredKeys[i]
		if refs, ok := engineRegistry.References(key); !ok || refs != 2 {
			t.Fatalf("registry references for %s = %d (exists %v), want 2", addr, refs, ok)
		}
		pool := m1.Engines[i].pool
		if pool == nil {
			t.Fatalf("address %s: shared Engine has no real Connection pool", addr)
		}
		if stats := m1.Engines[i].poolStats(); stats.ActiveConns != baseline[i] {
			t.Errorf("address %s: pool open connections after second acquire = %d, want %d (no growth)", addr, stats.ActiveConns, baseline[i])
		}
	}

	// A real detection request through the second instance's view of the
	// first shared Engine returns a verdict. DetectHttpRequest is called
	// directly rather than via ServeHTTP: T5's contract is the shared Engine
	// and its Connection pool, and full ServeHTTP detection is covered by the
	// body-cap real-engine test and the failover test below.
	result, err := m2.Engines[0].DetectHttpRequest(sqlInjectionRequest())
	if err != nil {
		t.Fatalf("real detection through shared Engine: %v", err)
	}
	if result == nil {
		t.Fatal("real detection through shared Engine returned no result")
	}

	// The first cleanup drops one reference per address; the shared pools stay
	// alive.
	if err := m1.Cleanup(); err != nil {
		t.Fatalf("m1 Cleanup: %v", err)
	}
	for i, addr := range addrs {
		key := m2.acquiredKeys[i]
		if refs, ok := engineRegistry.References(key); !ok || refs != 1 {
			t.Fatalf("address %s: after m1 Cleanup references = %d (exists %v), want 1", addr, refs, ok)
		}
		pool := m1.Engines[i].pool
		if conn, err := pool.Get(); err != nil {
			if strings.Contains(err.Error(), poolClosedErrMsg) {
				t.Fatalf("address %s: pool released too early: %v", addr, err)
			}
			t.Fatalf("address %s: pool.Get after m1 Cleanup: %v", addr, err)
		} else {
			_ = pool.Put(conn)
		}
	}

	// The last cleanup removes every registry entry and releases the real
	// pools.
	keys := append([]engineKey(nil), m2.acquiredKeys...)
	if err := m2.Cleanup(); err != nil {
		t.Fatalf("m2 Cleanup: %v", err)
	}
	for i, key := range keys {
		if refs, ok := engineRegistry.References(key); ok {
			t.Fatalf("address %s: after m2 Cleanup references = %d (exists %v), want gone", addrs[i], refs, ok)
		}
		pool := m1.Engines[i].pool
		if _, err := pool.Get(); err == nil || !strings.Contains(err.Error(), poolClosedErrMsg) {
			t.Fatalf("address %s: real pool not released after last Cleanup: %v", addrs[i], err)
		}
	}
}

// TestIntegrationMultiEngineFailover proves the retry path over real Engines:
// when the first Engine's Connection pool cannot reach its address (dial
// failure), the instance retries (lb_retries) and fails over to a healthy real
// Engine, and the failed Engine is marked unavailable for its health window.
//
// The first address is the fixed unreachable localhost port (unreachableEngineAddr,
// not a real Engine address); the second is the operator-supplied $T1K_ADDR.
// Round-robin starts at index 0 so the unreachable Engine is tried first and
// the failover target is deterministic.
func TestIntegrationMultiEngineFailover(t *testing.T) {
	real := engineAddrsFromEnv(t)
	ensureWAFMetrics(t)

	// testWAFInstance defaults to InitialCap 0, so pools dial on demand: the
	// unreachable pool still constructs, and the first detection dial fails.
	m := testWAFInstance(
		[]string{unreachableEngineAddr, real[0]},
		func(m *CaddyWAF) {
			m.LoadBalancing = &LoadBalancing{
				SelectionPolicy: &RoundRobinSelection{robin: ^uint32(0)},
				Retries:         1,
			}
		},
	)
	if err := m.acquireEngines(); err != nil {
		t.Fatalf("acquireEngines: %v", err)
	}
	t.Cleanup(func() { _ = m.Cleanup() })

	refusedBefore := testutil.ToFloat64(wafMetrics.connectionErrors.WithLabelValues(unreachableEngineAddr, reasonConnectionRefused))
	passedBefore := testutil.ToFloat64(wafMetrics.requestsTotal.WithLabelValues("passed"))

	req := httptest.NewRequest(http.MethodGet, "http://example.com/failover-test", nil)
	rr := httptest.NewRecorder()
	nextCalled := false
	err := m.ServeHTTP(rr, req, caddyhttp.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) error {
		nextCalled = true
		return nil
	}))
	if err != nil {
		t.Fatalf("ServeHTTP: %v", err)
	}

	if !nextCalled {
		t.Fatal("failover must reach the next handler on a benign request")
	}
	if rr.Code == http.StatusNotImplemented {
		t.Fatal("benign request must not be blocked")
	}
	if got := m.Engines[0].Fails(); got != 1 {
		t.Errorf("unreachable Engine failures = %d, want 1 (it must be tried first and fail)", got)
	}
	if got := testutil.ToFloat64(wafMetrics.connectionErrors.WithLabelValues(unreachableEngineAddr, reasonConnectionRefused)); got != refusedBefore+1 {
		t.Errorf("connection_refused errors for unreachable Engine = %v, want %v", got, refusedBefore+1)
	}
	if got := testutil.ToFloat64(wafMetrics.requestsTotal.WithLabelValues("passed")); got != passedBefore+1 {
		t.Errorf("passed requests = %v, want %v (real detection must succeed on failover)", got, passedBefore+1)
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
