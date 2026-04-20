package caddy_waf_t1k

import (
	"net/http/httptest"
	"testing"
)

func TestCheckFilter_SkipHeader(t *testing.T) {
	r := httptest.NewRequest("POST", "/", nil)
	r.Header.Set("X-Internal-Token", "secret")
	got := checkFilter(r, nil, "X-Internal-Token", 0)
	if got != filterSkipAll {
		t.Fatalf("expected filterSkipAll, got %d", got)
	}
}

func TestCheckFilter_HeaderAbsent_NoSkip(t *testing.T) {
	r := httptest.NewRequest("POST", "/", nil)
	got := checkFilter(r, nil, "X-Internal-Token", 0)
	if got != filterPass {
		t.Fatalf("expected filterPass when header absent, got %d", got)
	}
}

func TestCheckFilter_SkipContentType_Exact(t *testing.T) {
	r := httptest.NewRequest("POST", "/upload", nil)
	r.Header.Set("Content-Type", "image/jpeg")
	got := checkFilter(r, []string{"image/jpeg", "image/png"}, "", 0)
	if got != filterSkipAll {
		t.Fatalf("expected filterSkipAll, got %d", got)
	}
}

func TestCheckFilter_SkipContentType_PrefixMatch(t *testing.T) {
	r := httptest.NewRequest("POST", "/", nil)
	r.Header.Set("Content-Type", "image/jpeg; charset=utf-8")
	got := checkFilter(r, []string{"image/jpeg"}, "", 0)
	if got != filterSkipAll {
		t.Fatalf("expected filterSkipAll for prefix match, got %d", got)
	}
}

func TestCheckFilter_SkipBody_OverSize(t *testing.T) {
	r := httptest.NewRequest("POST", "/", nil)
	r.ContentLength = 10 * 1024 * 1024 // 10MB
	got := checkFilter(r, nil, "", 1*1024*1024)
	if got != filterSkipBody {
		t.Fatalf("expected filterSkipBody, got %d", got)
	}
}

func TestCheckFilter_BodyUnderSize_Pass(t *testing.T) {
	r := httptest.NewRequest("POST", "/", nil)
	r.ContentLength = 512 * 1024 // 512KB
	got := checkFilter(r, nil, "", 1*1024*1024)
	if got != filterPass {
		t.Fatalf("expected filterPass for under-size body, got %d", got)
	}
}

func TestCheckFilter_NoRules_Pass(t *testing.T) {
	r := httptest.NewRequest("GET", "/", nil)
	got := checkFilter(r, nil, "", 0)
	if got != filterPass {
		t.Fatalf("expected filterPass with no rules, got %d", got)
	}
}
