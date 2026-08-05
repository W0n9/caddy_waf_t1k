package caddy_waf_t1k

import (
	"strings"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	t1k "github.com/chaitin/t1k-go"
	"github.com/prometheus/client_golang/prometheus"
)

// testEngineKey returns a fully-populated engineKey for registry tests.
func testEngineKey(addr string) engineKey {
	return engineKey{
		addr:               addr,
		initialCap:         1,
		maxIdle:            16,
		maxCap:             32,
		idleTimeout:        30 * time.Second,
		healthMaxFails:     1,
		healthFailDuration: 30 * time.Second,
	}
}

// testEngine builds an Engine without a real Connection pool; Destruct is a
// no-op for the pool when it is nil.
func testEngine(addr string) *Engine {
	return &Engine{addr: addr, maxFails: 1, failDuration: 30 * time.Second}
}

func testEngineConstructor(addr string) caddy.Constructor {
	return func() (caddy.Destructor, error) { return testEngine(addr), nil }
}

func TestEngineRegistrySharedKey(t *testing.T) {
	key := testEngineKey("192.0.2.1:8000")

	e1, loaded, err := acquireEngine(key, testEngineConstructor(key.addr))
	if err != nil {
		t.Fatalf("first acquire: %v", err)
	}
	if loaded {
		t.Fatal("first acquire must construct a new Engine")
	}

	e2, loaded, err := acquireEngine(key, testEngineConstructor(key.addr))
	if err != nil {
		t.Fatalf("second acquire: %v", err)
	}
	if !loaded {
		t.Fatal("second acquire must load the existing Engine")
	}
	if e1 != e2 {
		t.Fatal("identical keys must share one Engine instance")
	}

	if refs, ok := engineRegistry.References(key); !ok || refs != 2 {
		t.Fatalf("references = %d, exists = %v; want 2", refs, ok)
	}

	if _, err := releaseEngine(key); err != nil {
		t.Fatalf("intermediate release: %v", err)
	}
	if _, err := releaseEngine(key); err != nil {
		t.Fatalf("final release: %v", err)
	}
}

func TestEngineRegistryShapingParamsIsolate(t *testing.T) {
	base := testEngineKey("192.0.2.1:8000")

	variants := []struct {
		name string
		key  engineKey
	}{
		{"pool initial_cap", func() (k engineKey) {
			k = base
			k.initialCap++
			return
		}()},
		{"pool max_idle", func() (k engineKey) {
			k = base
			k.maxIdle++
			return
		}()},
		{"pool max_cap", func() (k engineKey) {
			k = base
			k.maxCap++
			return
		}()},
		{"pool idle_timeout", func() (k engineKey) {
			k = base
			k.idleTimeout += time.Second
			return
		}()},
		{"health_max_fails", func() (k engineKey) {
			k = base
			k.healthMaxFails++
			return
		}()},
		{"health_fail_duration", func() (k engineKey) {
			k = base
			k.healthFailDuration += time.Second
			return
		}()},
	}

	for _, v := range variants {
		t.Run(v.name, func(t *testing.T) {
			baseEngine, _, err := acquireEngine(base, testEngineConstructor(base.addr))
			if err != nil {
				t.Fatalf("acquire base: %v", err)
			}
			t.Cleanup(func() { _, _ = releaseEngine(base) })

			variant, _, err := acquireEngine(v.key, testEngineConstructor(v.key.addr))
			if err != nil {
				t.Fatalf("acquire variant: %v", err)
			}
			t.Cleanup(func() { _, _ = releaseEngine(v.key) })

			if baseEngine == variant {
				t.Fatal("keys differing in any shaping parameter must yield independent Engines")
			}
			if refs, _ := engineRegistry.References(base); refs != 1 {
				t.Fatalf("base references = %d, want 1", refs)
			}
			if refs, _ := engineRegistry.References(v.key); refs != 1 {
				t.Fatalf("variant references = %d, want 1", refs)
			}
		})
	}
}

func TestEngineRegistryReleaseLastReferenceDestructs(t *testing.T) {
	ensureWAFMetrics(t)
	addr := "127.0.0.1:8000"
	key := testEngineKey(addr)

	var pool *t1k.ChannelPool
	construct := func() (caddy.Destructor, error) {
		p, err := t1k.NewChannelPool(&t1k.PoolConfig{
			InitialCap:  0,
			MaxIdle:     1,
			MaxCap:      1,
			Factory:     &t1k.TcpFactory{Addr: "127.0.0.1:1"},
			IdleTimeout: 30 * time.Second,
		})
		if err != nil {
			return nil, err
		}
		pool = p
		return &Engine{pool: p, addr: addr, maxFails: 1}, nil
	}

	// Pre-populate metric series for the Engine's address, as the production
	// per-instance updater would. t.Cleanup guards against leaking series into
	// later tests if an assertion fails mid-test.
	seriesLabels := prometheus.Labels{"engine": addr}
	t.Cleanup(func() {
		wafMetrics.enginesHealthy.DeletePartialMatch(seriesLabels)
		wafMetrics.poolIdleConns.DeletePartialMatch(seriesLabels)
		wafMetrics.poolActiveConns.DeletePartialMatch(seriesLabels)
		wafMetrics.poolMaxConns.DeletePartialMatch(seriesLabels)
		wafMetrics.poolWaitingReqs.DeletePartialMatch(seriesLabels)
	})
	wafMetrics.enginesHealthy.WithLabelValues(addr, "i1").Set(1)
	wafMetrics.poolIdleConns.WithLabelValues(addr, "i1").Set(2)
	wafMetrics.poolActiveConns.WithLabelValues(addr, "i1").Set(3)
	wafMetrics.poolMaxConns.WithLabelValues(addr, "i1").Set(4)
	wafMetrics.poolWaitingReqs.WithLabelValues(addr, "i1").Set(0)

	e1, _, err := acquireEngine(key, construct)
	if err != nil {
		t.Fatalf("first acquire: %v", err)
	}
	e2, _, err := acquireEngine(key, construct)
	if err != nil {
		t.Fatalf("second acquire: %v", err)
	}
	if e1 != e2 {
		t.Fatal("identical keys must share one Engine instance")
	}
	if pool == nil {
		t.Fatal("constructor did not build a Connection pool")
	}

	// Intermediate release: the Engine stays alive and its pool untouched.
	deleted, err := releaseEngine(key)
	if err != nil {
		t.Fatalf("intermediate release: %v", err)
	}
	if deleted {
		t.Fatal("intermediate release must not tear the Engine down")
	}
	if _, err := pool.Get(); err == nil || strings.Contains(err.Error(), "pool is closed") {
		t.Fatalf("pool released too early: %v", err)
	}

	// Last release: the Engine tears down — pool released, series removed.
	deleted, err = releaseEngine(key)
	if err != nil {
		t.Fatalf("final release: %v", err)
	}
	if !deleted {
		t.Fatal("last release must tear the Engine down")
	}
	if _, err := pool.Get(); err == nil || !strings.Contains(err.Error(), "pool is closed") {
		t.Fatalf("pool not released after last release: %v", err)
	}

	// Destruct must have removed every series for the Engine address; a second
	// DeletePartialMatch deleting nothing proves it. (Using WithLabelValues +
	// ToFloat64 here would recreate the series and pollute later tests.)
	for name, vec := range map[string]*prometheus.GaugeVec{
		"engines_healthy":       wafMetrics.enginesHealthy,
		"pool_idle_conns":       wafMetrics.poolIdleConns,
		"pool_active_conns":     wafMetrics.poolActiveConns,
		"pool_max_conns":        wafMetrics.poolMaxConns,
		"pool_waiting_requests": wafMetrics.poolWaitingReqs,
	} {
		if deleted := vec.DeletePartialMatch(seriesLabels); deleted != 0 {
			t.Errorf("%s series not removed after last release: %d still present", name, deleted)
		}
	}
}

func TestEngineRegistrySixtyEightInstancesThreeEngines(t *testing.T) {
	addrs := []string{"192.0.2.1:8000", "192.0.2.2:8000", "192.0.2.3:8000"}
	var acquired []engineKey
	t.Cleanup(func() {
		for _, key := range acquired {
			if _, err := releaseEngine(key); err != nil {
				t.Errorf("release %v: %v", key, err)
			}
		}
	})

	for range 68 {
		for _, addr := range addrs {
			key := testEngineKey(addr)
			if _, _, err := acquireEngine(key, testEngineConstructor(addr)); err != nil {
				t.Fatalf("acquire %s: %v", addr, err)
			}
			acquired = append(acquired, key)
		}
	}

	engines := 0
	engineRegistry.Range(func(_, _ any) bool { engines++; return true })
	if engines != 3 {
		t.Fatalf("registry holds %d Engines, want 3 (68 instances × 3 identical addresses)", engines)
	}
}

func TestEngineRegistryReferenceCountZeroRemovesKey(t *testing.T) {
	key := testEngineKey("192.0.2.9:8000")

	for range 3 {
		if _, _, err := acquireEngine(key, testEngineConstructor(key.addr)); err != nil {
			t.Fatalf("acquire: %v", err)
		}
	}
	if refs, ok := engineRegistry.References(key); !ok || refs != 3 {
		t.Fatalf("references = %d, exists = %v; want 3", refs, ok)
	}

	for range 3 {
		if _, err := releaseEngine(key); err != nil {
			t.Fatalf("release: %v", err)
		}
	}
	if _, ok := engineRegistry.References(key); ok {
		t.Fatal("key must be removed from the registry once its reference count reaches zero")
	}
}
