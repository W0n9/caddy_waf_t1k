package caddy_waf_t1k

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	t1k "github.com/chaitin/t1k-go"
	"go.uber.org/zap"
)

// testWAFInstance builds a CaddyWAF ready for acquireEngines/Cleanup without a
// caddy.Context. Config defaults satisfy t1k.ChannelPool's capacity rules with
// InitialCap 0 (no dialing happens at construction).
func testWAFInstance(addrs []string, opts ...func(*CaddyWAF)) *CaddyWAF {
	m := &CaddyWAF{
		WafEngineAddrs:     addrs,
		InitialCap:         0,
		MaxIdle:            1,
		MaxCap:             1,
		IdleTimeout:        30 * time.Second,
		HealthMaxFails:     1,
		HealthFailDuration: caddy.Duration(30 * time.Second),
		logger:             zap.NewNop(),
	}
	for _, o := range opts {
		o(m)
	}
	return m
}

// withPoolFactory injects a Connection-pool constructor for tests.
func withPoolFactory(f func(*t1k.PoolConfig) (*t1k.ChannelPool, error)) func(*CaddyWAF) {
	return func(m *CaddyWAF) { m.poolFactory = f }
}

// withSharedPool injects a constructor that builds a new, dial-free pool per
// Engine; shared Engine instances therefore keep distinct pools but tests never
// touch the network.
func withSharedPool() func(*CaddyWAF) {
	return withPoolFactory(func(*t1k.PoolConfig) (*t1k.ChannelPool, error) { return nil, nil })
}

func TestAcquireEnginesRecordsPerAddress(t *testing.T) {
	ensureWAFMetrics(t)
	addrs := []string{"203.0.113.1:8000", "203.0.113.2:8000", "203.0.113.3:8000"}
	m := testWAFInstance(addrs)

	if err := m.acquireEngines(); err != nil {
		t.Fatalf("acquireEngines: %v", err)
	}

	if len(m.Engines) != len(addrs) {
		t.Fatalf("Engines = %d, want %d", len(m.Engines), len(addrs))
	}
	if len(m.acquiredKeys) != len(addrs) {
		t.Fatalf("acquiredKeys = %d, want %d", len(m.acquiredKeys), len(addrs))
	}
	for i, addr := range addrs {
		if m.Engines[i].addr != addr {
			t.Errorf("Engines[%d].addr = %q, want %q", i, m.Engines[i].addr, addr)
		}
		if m.acquiredKeys[i].addr != addr {
			t.Errorf("acquiredKeys[%d].addr = %q, want %q", i, m.acquiredKeys[i].addr, addr)
		}
		if refs, ok := engineRegistry.References(m.acquiredKeys[i]); !ok || refs != 1 {
			t.Errorf("references for %s = %d, exists = %v; want 1", addr, refs, ok)
		}
	}

	// Cleaning up the instance releases every acquired Engine.
	keys := append([]engineKey(nil), m.acquiredKeys...)
	if err := m.Cleanup(); err != nil {
		t.Fatalf("Cleanup: %v", err)
	}
	for _, key := range keys {
		if refs, ok := engineRegistry.References(key); ok {
			t.Errorf("key %v still in registry after Cleanup (refs = %d)", key.addr, refs)
		}
	}
}

func TestAcquireEnginesSharesIdenticalConfig(t *testing.T) {
	ensureWAFMetrics(t)
	addr := "203.0.113.10:8000"
	m1 := testWAFInstance([]string{addr})
	m2 := testWAFInstance([]string{addr})

	if err := m1.acquireEngines(); err != nil {
		t.Fatalf("m1 acquireEngines: %v", err)
	}
	if err := m2.acquireEngines(); err != nil {
		t.Fatalf("m2 acquireEngines: %v", err)
	}

	if m1.Engines[0] != m2.Engines[0] {
		t.Fatal("identical address+config must share one Engine instance")
	}
	key := m1.acquiredKeys[0]
	if refs, ok := engineRegistry.References(key); !ok || refs != 2 {
		t.Fatalf("references = %d, exists = %v; want 2", refs, ok)
	}

	// Cleaning up one of two referencing instances keeps the Engine alive.
	if err := m1.Cleanup(); err != nil {
		t.Fatalf("m1 Cleanup: %v", err)
	}
	if refs, ok := engineRegistry.References(key); !ok || refs != 1 {
		t.Fatalf("after one Cleanup references = %d, exists = %v; want 1", refs, ok)
	}

	// The last cleanup removes the Engine from the registry.
	if err := m2.Cleanup(); err != nil {
		t.Fatalf("m2 Cleanup: %v", err)
	}
	if refs, ok := engineRegistry.References(key); ok {
		t.Fatalf("after last Cleanup references = %d, exists = %v; want gone", refs, ok)
	}
}

func TestAcquireEnginesConfigDiffIsolatesEngine(t *testing.T) {
	ensureWAFMetrics(t)
	addr := "203.0.113.20:8000"

	variants := []struct {
		name  string
		apply func(*CaddyWAF)
	}{
		{"pool initial_cap", func(m *CaddyWAF) { m.InitialCap = 2 }},
		{"pool max_idle", func(m *CaddyWAF) { m.MaxIdle = 2 }},
		{"pool max_cap", func(m *CaddyWAF) { m.MaxCap = 2 }},
		{"pool idle_timeout", func(m *CaddyWAF) { m.IdleTimeout = time.Minute }},
		{"health_max_fails", func(m *CaddyWAF) { m.HealthMaxFails = 2 }},
		{"health_fail_duration", func(m *CaddyWAF) { m.HealthFailDuration = caddy.Duration(time.Minute) }},
	}

	for _, v := range variants {
		t.Run(v.name, func(t *testing.T) {
			base := testWAFInstance([]string{addr}, withSharedPool())
			variant := testWAFInstance([]string{addr}, withSharedPool())
			v.apply(variant)

			if err := base.acquireEngines(); err != nil {
				t.Fatalf("base acquireEngines: %v", err)
			}
			t.Cleanup(func() { _ = base.Cleanup() })
			if err := variant.acquireEngines(); err != nil {
				t.Fatalf("variant acquireEngines: %v", err)
			}
			t.Cleanup(func() { _ = variant.Cleanup() })

			if base.Engines[0] == variant.Engines[0] {
				t.Fatal("configs differing in any shaping parameter must yield independent Engines")
			}
			if refs, _ := engineRegistry.References(base.acquiredKeys[0]); refs != 1 {
				t.Errorf("base references = %d, want 1", refs)
			}
			if refs, _ := engineRegistry.References(variant.acquiredKeys[0]); refs != 1 {
				t.Errorf("variant references = %d, want 1", refs)
			}
		})
	}
}

func TestAcquireEnginesRollsBackOnError(t *testing.T) {
	ensureWAFMetrics(t)
	addrs := []string{"203.0.113.97:8000", "203.0.113.98:8000", "203.0.113.99:8000"}
	broken := addrs[2]

	factory := func(pc *t1k.PoolConfig) (*t1k.ChannelPool, error) {
		if pc.Factory.(*t1k.TcpFactory).Addr == broken {
			return nil, errors.New("dial engine failed")
		}
		return nil, nil
	}
	m := testWAFInstance(addrs, withPoolFactory(factory))

	err := m.acquireEngines()
	if err == nil {
		t.Fatal("acquireEngines must fail when an Engine cannot be constructed")
	}
	if len(m.acquiredKeys) != 0 {
		t.Errorf("acquiredKeys = %d after rollback, want 0", len(m.acquiredKeys))
	}
	if m.Engines != nil {
		t.Error("Engines must be nil after rollback")
	}

	// Every Engine already acquired before the failure must be released.
	for i := 0; i < len(addrs)-1; i++ {
		key := m.engineKeyFor(addrs[i])
		if refs, ok := engineRegistry.References(key); ok {
			t.Errorf("key %s still referenced after rollback (refs = %d)", addrs[i], refs)
		}
	}
}

func TestCleanupLastReferenceReleasesPool(t *testing.T) {
	ensureWAFMetrics(t)
	// 127.0.0.1:1 dials fail fast (connection refused), so pool.Get() errors are
	// distinguishable from a released pool ("pool is closed").
	addr := "127.0.0.1:1"
	m1 := testWAFInstance([]string{addr})
	m2 := testWAFInstance([]string{addr})

	if err := m1.acquireEngines(); err != nil {
		t.Fatalf("m1 acquireEngines: %v", err)
	}
	if err := m2.acquireEngines(); err != nil {
		t.Fatalf("m2 acquireEngines: %v", err)
	}
	if m1.Engines[0] != m2.Engines[0] {
		t.Fatal("identical configs must share one Engine instance")
	}
	pool := m1.Engines[0].pool
	if pool == nil {
		t.Fatal("shared Engine has no Connection pool")
	}
	key := m1.acquiredKeys[0]

	// Intermediate cleanup: the shared Engine stays alive, its pool untouched.
	if err := m1.Cleanup(); err != nil {
		t.Fatalf("m1 Cleanup: %v", err)
	}
	if refs, ok := engineRegistry.References(key); !ok || refs != 1 {
		t.Fatalf("after m1 Cleanup references = %d, exists = %v; want 1", refs, ok)
	}
	if _, err := pool.Get(); err == nil || strings.Contains(err.Error(), "pool is closed") {
		t.Fatalf("pool released too early: %v", err)
	}

	// Last cleanup: the Engine tears down and releases its Connection pool.
	if err := m2.Cleanup(); err != nil {
		t.Fatalf("m2 Cleanup: %v", err)
	}
	if refs, ok := engineRegistry.References(key); ok {
		t.Fatalf("after m2 Cleanup references = %d, exists = %v; want gone", refs, ok)
	}
	if _, err := pool.Get(); err == nil || !strings.Contains(err.Error(), "pool is closed") {
		t.Fatalf("pool not released after last Cleanup: %v", err)
	}
}
