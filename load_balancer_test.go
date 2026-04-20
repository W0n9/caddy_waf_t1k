package caddy_waf_t1k

import (
	"net/http/httptest"
	"testing"
)

func makeTestEntry(addr string, healthy bool) *engineEntry {
	e := &engineEntry{addr: addr}
	e.healthy.Store(healthy)
	return e
}

func TestRandomSelection_SkipsUnhealthyEngines(t *testing.T) {
	pool := EnginePool{
		makeTestEntry("1.1.1.1:8000", false),
		makeTestEntry("2.2.2.2:8000", true),
		makeTestEntry("3.3.3.3:8000", false),
	}
	sel := RandomSelection{}
	r := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()

	for i := 0; i < 30; i++ {
		got := sel.Select(pool, r, w)
		if got == nil {
			t.Fatal("Select returned nil")
		}
		if got.addr != "2.2.2.2:8000" {
			t.Fatalf("expected healthy engine 2.2.2.2:8000, got %s", got.addr)
		}
	}
}

func TestRandomSelection_FailOpen_WhenAllUnhealthy(t *testing.T) {
	pool := EnginePool{
		makeTestEntry("1.1.1.1:8000", false),
		makeTestEntry("2.2.2.2:8000", false),
	}
	sel := RandomSelection{}
	r := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()

	got := sel.Select(pool, r, w)
	if got == nil {
		t.Fatal("Select should fail-open and return an engine when all are unhealthy")
	}
}

func TestRoundRobinSelection_SkipsUnhealthyEngines(t *testing.T) {
	pool := EnginePool{
		makeTestEntry("1.1.1.1:8000", true),
		makeTestEntry("2.2.2.2:8000", false),
		makeTestEntry("3.3.3.3:8000", true),
	}
	sel := &RoundRobinSelection{}
	r := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()

	for i := 0; i < 10; i++ {
		got := sel.Select(pool, r, w)
		if got == nil {
			t.Fatal("Select returned nil")
		}
		if got.addr == "2.2.2.2:8000" {
			t.Fatal("unhealthy engine should not be selected")
		}
	}
}

func TestRoundRobinSelection_FailOpen_WhenAllUnhealthy(t *testing.T) {
	pool := EnginePool{
		makeTestEntry("1.1.1.1:8000", false),
	}
	sel := &RoundRobinSelection{}
	r := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()

	got := sel.Select(pool, r, w)
	if got == nil {
		t.Fatal("Select should fail-open and return an engine when all are unhealthy")
	}
}

func TestHealthyPool_AllHealthy(t *testing.T) {
	pool := EnginePool{
		makeTestEntry("a", true),
		makeTestEntry("b", true),
	}
	got := healthyPool(pool)
	if len(got) != 2 {
		t.Fatalf("expected 2 healthy engines, got %d", len(got))
	}
}

func TestHealthyPool_FallbackWhenAllUnhealthy(t *testing.T) {
	pool := EnginePool{
		makeTestEntry("a", false),
		makeTestEntry("b", false),
	}
	got := healthyPool(pool)
	if len(got) != 2 {
		t.Fatalf("expected fallback to full pool (2), got %d", len(got))
	}
}
