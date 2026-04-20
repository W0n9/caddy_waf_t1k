package caddy_waf_t1k

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/chaitin/t1k-go/detection"
	"go.uber.org/zap"

	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

type mockDetector struct {
	result *detection.Result
	err    error
}

func (m *mockDetector) DetectHttpRequest(_ *http.Request) (*detection.Result, error) {
	return m.result, m.err
}

func allowedResult() *detection.Result {
	r := &detection.Result{}
	r.Head = '.'
	return r
}

func blockedResult() *detection.Result {
	r := &detection.Result{}
	r.Head = 'X'
	return r
}

func botResult(body []byte) *detection.Result {
	r := &detection.Result{
		BotQuery: []byte("challenge"),
		BotBody:  body,
	}
	r.Head = '.'
	return r
}

func makeWAF(d detector) CaddyWAF {
	e := &engineEntry{engine: d, addr: "mock"}
	e.healthy.Store(true)
	return CaddyWAF{
		logger:  zap.NewNop(),
		Engines: EnginePool{e},
		LoadBalancing: &LoadBalancing{
			SelectionPolicy: RandomSelection{},
		},
	}
}

type handlerFunc func(http.ResponseWriter, *http.Request) error

func (h handlerFunc) ServeHTTP(w http.ResponseWriter, r *http.Request) error {
	return h(w, r)
}

func TestServeHTTP_Allowed(t *testing.T) {
	waf := makeWAF(&mockDetector{result: allowedResult()})
	r := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()
	nextCalled := false
	next := handlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		nextCalled = true
		return nil
	})
	if err := waf.ServeHTTP(w, r, next); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !nextCalled {
		t.Fatal("next handler should be called for allowed requests")
	}
}

func TestServeHTTP_Blocked(t *testing.T) {
	waf := makeWAF(&mockDetector{result: blockedResult()})
	r := httptest.NewRequest("GET", "/attack", nil)
	w := httptest.NewRecorder()
	next := handlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		t.Fatal("next should not be called for blocked requests")
		return nil
	})
	if err := waf.ServeHTTP(w, r, next); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if w.Code != http.StatusNotImplemented {
		t.Fatalf("expected 501, got %d", w.Code)
	}
}

func TestServeHTTP_EngineError_FailOpen(t *testing.T) {
	waf := makeWAF(&mockDetector{err: fmt.Errorf("connection refused")})
	r := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()
	nextCalled := false
	next := handlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		nextCalled = true
		return nil
	})
	if err := waf.ServeHTTP(w, r, next); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !nextCalled {
		t.Fatal("next handler should be called when engine errors (fail-open)")
	}
}

func TestServeHTTP_BotDetected_WritesBodyAndSkipsNext(t *testing.T) {
	waf := makeWAF(&mockDetector{result: botResult([]byte(`<html>challenge</html>`))})
	waf.BotDetect = true
	r := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()
	next := handlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		t.Fatal("next should not be called for bot challenge")
		return nil
	})
	if err := waf.ServeHTTP(w, r, next); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	if w.Body.String() != `<html>challenge</html>` {
		t.Fatalf("expected bot body, got %s", w.Body.String())
	}
}

func TestServeHTTP_BotDetect_Disabled_PassesThrough(t *testing.T) {
	waf := makeWAF(&mockDetector{result: botResult([]byte("challenge"))})
	waf.BotDetect = false
	r := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()
	nextCalled := false
	next := handlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		nextCalled = true
		return nil
	})
	if err := waf.ServeHTTP(w, r, next); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !nextCalled {
		t.Fatal("with bot_detect off, BotDetected result should fall through to normal allow/block logic")
	}
}

func TestServeHTTP_SkipFilter_CallsNext(t *testing.T) {
	waf := makeWAF(&mockDetector{result: blockedResult()})
	waf.SkipHeader = "X-Skip"
	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("X-Skip", "1")
	w := httptest.NewRecorder()
	nextCalled := false
	next := handlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		nextCalled = true
		return nil
	})
	if err := waf.ServeHTTP(w, r, next); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !nextCalled {
		t.Fatal("skipped request should bypass detection and call next")
	}
}

var _ caddyhttp.Handler = handlerFunc(nil)
