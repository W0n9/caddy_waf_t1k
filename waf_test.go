package caddy_waf_t1k

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/chaitin/t1k-go/detection"
	"github.com/prometheus/client_golang/prometheus"
	"go.uber.org/zap"
)

func TestIsEngineError(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		expected bool
	}{
		{"connection refused is engine error", errors.New("dial tcp 10.0.0.1:8000: connect: connection refused"), true},
		{"dial timeout is engine error", errors.New("dial tcp 10.0.0.1:8000: i/o timeout"), true},
		{"broken pipe is engine error", errors.New("write: broken pipe"), true},
		{"unknown error is engine error", errors.New("something unexpected"), true},

		{"H3 request cancelled is client error", errors.New("H3_REQUEST_CANCELLED"), false},
		{"H3 error is client error", errors.New("H3 error (0x0)"), false},
		{"client disconnected is client error", errors.New("client disconnected"), false},
		{"keepalive limit is client error", errors.New("NO_ERROR (remote): keepalive limit reached"), false},
		{"client body connection reset is client error", errors.New("read request body: read tcp 1.2.3.4:443->5.6.7.8:12345: read: connection reset by peer"), false},
		{"engine-side connection reset is engine error", errors.New("read tcp 192.0.2.1:56702->198.51.100.10:8000: read: connection reset by peer"), true},
		{"engine-side write connection reset is engine error", errors.New("write tcp 192.0.2.1:32552->198.51.100.10:8000: write: connection reset by peer"), true},
		{"QUIC idle timeout is client error", errors.New("timeout: no recent network activity"), false},
		{"chunked encoding error is client error", errors.New("empty hex number for chunk length"), false},
		{"context canceled is client error", errors.New("context canceled"), false},
		{"request canceled is client error", errors.New("request canceled"), false},

		{"client body unexpected EOF is client error", errors.New("read request body: unexpected EOF"), false},
		{"client body stream cancel is client error", errors.New("read request body: stream error: stream ID 1; CANCEL"), false},
		{"engine-side unexpected EOF stays engine error", errors.New("unexpected EOF"), true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isEngineError(tt.err)
			if got != tt.expected {
				t.Errorf("isEngineError(%q) = %v, want %v", tt.err, got, tt.expected)
			}
		})
	}
}

func TestEngineAvailable(t *testing.T) {
	t.Run("always available when maxFails is 0", func(t *testing.T) {
		e := &Engine{maxFails: 0}
		atomic.StoreInt64(&e.fails, 100)
		if !e.Available() {
			t.Error("expected Available() = true when maxFails is 0")
		}
	})

	t.Run("available when fails below threshold", func(t *testing.T) {
		e := &Engine{maxFails: 3}
		atomic.StoreInt64(&e.fails, 2)
		if !e.Available() {
			t.Error("expected Available() = true when fails < maxFails")
		}
	})

	t.Run("unavailable when fails at threshold", func(t *testing.T) {
		e := &Engine{maxFails: 3}
		atomic.StoreInt64(&e.fails, 3)
		if e.Available() {
			t.Error("expected Available() = false when fails >= maxFails")
		}
	})

	t.Run("unavailable when fails above threshold", func(t *testing.T) {
		e := &Engine{maxFails: 3}
		atomic.StoreInt64(&e.fails, 5)
		if e.Available() {
			t.Error("expected Available() = false when fails > maxFails")
		}
	})
}

func TestEngineCountFail(t *testing.T) {
	e := &Engine{}

	e.countFail(1)
	if got := e.Fails(); got != 1 {
		t.Errorf("after countFail(1): Fails() = %d, want 1", got)
	}

	e.countFail(1)
	if got := e.Fails(); got != 2 {
		t.Errorf("after second countFail(1): Fails() = %d, want 2", got)
	}

	e.countFail(-1)
	if got := e.Fails(); got != 1 {
		t.Errorf("after countFail(-1): Fails() = %d, want 1", got)
	}
}

func TestSelectRandomHostSkipsUnhealthy(t *testing.T) {
	healthy := &Engine{addr: "healthy", maxFails: 1}
	unhealthy := &Engine{addr: "unhealthy", maxFails: 1}
	atomic.StoreInt64(&unhealthy.fails, 1)

	pool := []*Engine{unhealthy, healthy}

	for range 100 {
		got := selectRandomHost(pool)
		if got == nil {
			t.Fatal("selectRandomHost returned nil with available engines")
		}
		if got.addr == "unhealthy" {
			t.Fatal("selectRandomHost selected unhealthy engine")
		}
	}
}

func TestSelectRandomHostReturnsNilWhenAllUnhealthy(t *testing.T) {
	e1 := &Engine{addr: "e1", maxFails: 1}
	e2 := &Engine{addr: "e2", maxFails: 1}
	atomic.StoreInt64(&e1.fails, 1)
	atomic.StoreInt64(&e2.fails, 1)

	got := selectRandomHost([]*Engine{e1, e2})
	if got != nil {
		t.Errorf("expected nil when all engines unhealthy, got %s", got.addr)
	}
}

func TestRoundRobinSkipsUnhealthy(t *testing.T) {
	healthy := &Engine{addr: "healthy", maxFails: 1}
	unhealthy := &Engine{addr: "unhealthy", maxFails: 1}
	atomic.StoreInt64(&unhealthy.fails, 1)

	rr := &RoundRobinSelection{}
	pool := EnginePool{unhealthy, healthy}

	for range 10 {
		got := rr.Select(pool, nil, nil)
		if got == nil {
			t.Fatal("RoundRobin returned nil with available engines")
		}
		if got.addr == "unhealthy" {
			t.Fatal("RoundRobin selected unhealthy engine")
		}
	}
}

func TestRoundRobinReturnsNilWhenAllUnhealthy(t *testing.T) {
	e1 := &Engine{addr: "e1", maxFails: 1}
	e2 := &Engine{addr: "e2", maxFails: 1}
	atomic.StoreInt64(&e1.fails, 1)
	atomic.StoreInt64(&e2.fails, 1)

	rr := &RoundRobinSelection{}
	got := rr.Select(EnginePool{e1, e2}, nil, nil)
	if got != nil {
		t.Errorf("expected nil when all engines unhealthy, got %s", got.addr)
	}
}

func TestRoundRobinDistribution(t *testing.T) {
	e1 := &Engine{addr: "e1", maxFails: 0}
	e2 := &Engine{addr: "e2", maxFails: 0}
	e3 := &Engine{addr: "e3", maxFails: 0}

	rr := &RoundRobinSelection{}
	pool := EnginePool{e1, e2, e3}

	counts := map[string]int{}
	for range 30 {
		got := rr.Select(pool, nil, nil)
		counts[got.addr]++
	}

	for _, addr := range []string{"e1", "e2", "e3"} {
		if counts[addr] != 10 {
			t.Errorf("expected 10 selections for %s, got %d", addr, counts[addr])
		}
	}
}

func TestSelectRandomHostEmptyPool(t *testing.T) {
	got := selectRandomHost([]*Engine{})
	if got != nil {
		t.Error("expected nil for empty pool")
	}
}

func TestCountFailureDisabledWhenZeroDuration(t *testing.T) {
	m := &CaddyWAF{HealthFailDuration: 0}
	e := &Engine{maxFails: 1}

	m.countFailure(e)

	if got := e.Fails(); got != 0 {
		t.Errorf("countFailure should be no-op when HealthFailDuration=0, got Fails()=%d", got)
	}
}

func TestCountFailureIncrementsAndDecrements(t *testing.T) {
	m := &CaddyWAF{HealthFailDuration: caddy.Duration(100 * time.Millisecond)}
	e := &Engine{maxFails: 3}

	m.countFailure(e)
	if got := e.Fails(); got != 1 {
		t.Errorf("after countFailure: Fails() = %d, want 1", got)
	}

	m.countFailure(e)
	if got := e.Fails(); got != 2 {
		t.Errorf("after second countFailure: Fails() = %d, want 2", got)
	}

	// Wait for timers to expire
	time.Sleep(200 * time.Millisecond)

	if got := e.Fails(); got != 0 {
		t.Errorf("after timer expiry: Fails() = %d, want 0", got)
	}
}

func TestCountFailureEngineBecomesAvailableAfterExpiry(t *testing.T) {
	m := &CaddyWAF{HealthFailDuration: caddy.Duration(100 * time.Millisecond)}
	e := &Engine{maxFails: 1}

	m.countFailure(e)
	if e.Available() {
		t.Error("engine should be unavailable after failure")
	}

	time.Sleep(200 * time.Millisecond)

	if !e.Available() {
		t.Error("engine should be available after timer expiry")
	}
}

func TestRoundRobinEmptyPool(t *testing.T) {
	rr := &RoundRobinSelection{}
	got := rr.Select(EnginePool{}, nil, nil)
	if got != nil {
		t.Error("expected nil for empty pool")
	}
}

func TestExcludeEngines(t *testing.T) {
	e1 := &Engine{addr: "192.0.2.1:8000"}
	e2 := &Engine{addr: "192.0.2.2:8000"}
	e3 := &Engine{addr: "192.0.2.3:8000"}
	pool := EnginePool{e1, e2, e3}

	t.Run("empty tried returns same pool contents", func(t *testing.T) {
		got := excludeEngines(pool, nil)
		if len(got) != 3 {
			t.Fatalf("len = %d, want 3", len(got))
		}
	})

	t.Run("excludes tried engines", func(t *testing.T) {
		tried := map[*Engine]struct{}{e1: {}}
		got := excludeEngines(pool, tried)
		if len(got) != 2 {
			t.Fatalf("len = %d, want 2", len(got))
		}
		for _, e := range got {
			if e == e1 {
				t.Fatal("excluded engine still present")
			}
		}
	})

	t.Run("all tried returns empty", func(t *testing.T) {
		tried := map[*Engine]struct{}{e1: {}, e2: {}, e3: {}}
		got := excludeEngines(pool, tried)
		if len(got) != 0 {
			t.Fatalf("len = %d, want 0", len(got))
		}
	})
}

func ensureWAFMetrics(t *testing.T) {
	t.Helper()
	initWAFMetrics(prometheus.NewRegistry())
}

func newTestWAF(engines EnginePool, retries int) *CaddyWAF {
	return &CaddyWAF{
		logger:     zap.NewNop(),
		instanceID: "test",
		Engines:    engines,
		LoadBalancing: &LoadBalancing{
			SelectionPolicy: &RoundRobinSelection{robin: ^uint32(0)},
			Retries:         retries,
		},
		HealthFailDuration: 0,
	}
}

func TestServeHTTPNoRetryByDefault(t *testing.T) {
	ensureWAFMetrics(t)
	var calls atomic.Int32
	e1 := &Engine{addr: "192.0.2.1:8000", maxFails: 0, detectFn: func(*http.Request) (*detection.Result, error) {
		calls.Add(1)
		return nil, errors.New("connection refused")
	}}
	e2 := &Engine{addr: "192.0.2.2:8000", maxFails: 0, detectFn: func(*http.Request) (*detection.Result, error) {
		calls.Add(1)
		return &detection.Result{Head: '.'}, nil
	}}

	m := newTestWAF(EnginePool{e1, e2}, 0)
	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	rr := httptest.NewRecorder()
	nextCalled := false
	err := m.ServeHTTP(rr, req, caddyhttp.HandlerFunc(func(http.ResponseWriter, *http.Request) error {
		nextCalled = true
		return nil
	}))
	if err != nil {
		t.Fatalf("ServeHTTP: %v", err)
	}
	if !nextCalled {
		t.Fatal("expected fail-open to call next")
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("Detect calls = %d, want 1 (no retry)", got)
	}
}

func TestServeHTTPRetriesOnEngineError(t *testing.T) {
	ensureWAFMetrics(t)
	var calls atomic.Int32
	e1 := &Engine{addr: "192.0.2.1:8000", maxFails: 0, detectFn: func(*http.Request) (*detection.Result, error) {
		calls.Add(1)
		return nil, errors.New("connection refused")
	}}
	e2 := &Engine{addr: "192.0.2.2:8000", maxFails: 0, detectFn: func(*http.Request) (*detection.Result, error) {
		calls.Add(1)
		return &detection.Result{Head: '.'}, nil
	}}

	m := newTestWAF(EnginePool{e1, e2}, 1)
	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	rr := httptest.NewRecorder()
	nextCalled := false
	err := m.ServeHTTP(rr, req, caddyhttp.HandlerFunc(func(http.ResponseWriter, *http.Request) error {
		nextCalled = true
		return nil
	}))
	if err != nil {
		t.Fatalf("ServeHTTP: %v", err)
	}
	if !nextCalled {
		t.Fatal("expected next after pass")
	}
	if got := calls.Load(); got != 2 {
		t.Fatalf("Detect calls = %d, want 2", got)
	}
}

func TestServeHTTPNoRetryOnClientError(t *testing.T) {
	ensureWAFMetrics(t)
	var calls atomic.Int32
	e1 := &Engine{addr: "192.0.2.1:8000", maxFails: 0, detectFn: func(*http.Request) (*detection.Result, error) {
		calls.Add(1)
		return nil, errors.New("read request body: unexpected EOF")
	}}
	e2 := &Engine{addr: "192.0.2.2:8000", maxFails: 0, detectFn: func(*http.Request) (*detection.Result, error) {
		calls.Add(1)
		return &detection.Result{Head: '.'}, nil
	}}

	m := newTestWAF(EnginePool{e1, e2}, 1)
	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	rr := httptest.NewRecorder()
	_ = m.ServeHTTP(rr, req, caddyhttp.HandlerFunc(func(http.ResponseWriter, *http.Request) error {
		return nil
	}))
	if got := calls.Load(); got != 1 {
		t.Fatalf("Detect calls = %d, want 1 (client error not retried)", got)
	}
}

func TestServeHTTPRetryExhaustedFailOpen(t *testing.T) {
	ensureWAFMetrics(t)
	var calls atomic.Int32
	fail := func(*http.Request) (*detection.Result, error) {
		calls.Add(1)
		return nil, errors.New("connection refused")
	}
	e1 := &Engine{addr: "192.0.2.1:8000", maxFails: 0, detectFn: fail}
	e2 := &Engine{addr: "192.0.2.2:8000", maxFails: 0, detectFn: fail}

	m := newTestWAF(EnginePool{e1, e2}, 1)
	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	rr := httptest.NewRecorder()
	nextCalled := false
	err := m.ServeHTTP(rr, req, caddyhttp.HandlerFunc(func(http.ResponseWriter, *http.Request) error {
		nextCalled = true
		return nil
	}))
	if err != nil {
		t.Fatalf("ServeHTTP: %v", err)
	}
	if !nextCalled {
		t.Fatal("expected fail-open")
	}
	if got := calls.Load(); got != 2 {
		t.Fatalf("Detect calls = %d, want 2", got)
	}
}

func TestServeHTTPRetrySkipsTriedEngine(t *testing.T) {
	ensureWAFMetrics(t)
	var e1Calls, e2Calls atomic.Int32
	e1 := &Engine{addr: "192.0.2.1:8000", maxFails: 0, detectFn: func(*http.Request) (*detection.Result, error) {
		e1Calls.Add(1)
		return nil, errors.New("connection refused")
	}}
	e2 := &Engine{addr: "192.0.2.2:8000", maxFails: 0, detectFn: func(*http.Request) (*detection.Result, error) {
		e2Calls.Add(1)
		return &detection.Result{Head: '.'}, nil
	}}

	m := newTestWAF(EnginePool{e1, e2}, 3)
	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	rr := httptest.NewRecorder()
	_ = m.ServeHTTP(rr, req, caddyhttp.HandlerFunc(func(http.ResponseWriter, *http.Request) error {
		return nil
	}))
	if e1Calls.Load() != 1 {
		t.Fatalf("e1 calls = %d, want 1", e1Calls.Load())
	}
	if e2Calls.Load() != 1 {
		t.Fatalf("e2 calls = %d, want 1", e2Calls.Load())
	}
}
