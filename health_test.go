package caddy_waf_t1k

import (
	"testing"

	"go.uber.org/zap"
)

func TestUpdateHealth_MarkUnhealthy(t *testing.T) {
	logger := zap.NewNop()
	e := &engineEntry{addr: "127.0.0.1:8000"}
	e.healthy.Store(true)

	e.updateHealth(false, 3, 2, logger)
	e.updateHealth(false, 3, 2, logger)
	if !e.healthy.Load() {
		t.Fatal("should still be healthy after 2 failures (threshold=3)")
	}

	e.updateHealth(false, 3, 2, logger)
	if e.healthy.Load() {
		t.Fatal("should be unhealthy after 3 consecutive failures")
	}
}

func TestUpdateHealth_Recovery(t *testing.T) {
	logger := zap.NewNop()
	e := &engineEntry{addr: "127.0.0.1:8000"}
	e.healthy.Store(false)
	e.failCount.Store(3)

	e.updateHealth(true, 3, 2, logger)
	if e.healthy.Load() {
		t.Fatal("should still be unhealthy after 1 success (threshold=2)")
	}

	e.updateHealth(true, 3, 2, logger)
	if !e.healthy.Load() {
		t.Fatal("should be healthy after 2 consecutive successes")
	}
}

func TestUpdateHealth_FailCountResetOnSuccess(t *testing.T) {
	logger := zap.NewNop()
	e := &engineEntry{addr: "127.0.0.1:8000"}
	e.healthy.Store(true)

	e.updateHealth(false, 3, 2, logger)
	e.updateHealth(false, 3, 2, logger)
	e.updateHealth(true, 3, 2, logger)

	if e.failCount.Load() != 0 {
		t.Fatalf("failCount should be 0 after success, got %d", e.failCount.Load())
	}
	if !e.healthy.Load() {
		t.Fatal("should still be healthy")
	}
}

func TestUpdateHealth_OkCountResetOnFailure(t *testing.T) {
	logger := zap.NewNop()
	e := &engineEntry{addr: "127.0.0.1:8000"}
	e.healthy.Store(false)

	e.updateHealth(true, 3, 2, logger)
	e.updateHealth(false, 3, 2, logger)

	if e.okCount.Load() != 0 {
		t.Fatalf("okCount should be 0 after failure, got %d", e.okCount.Load())
	}
}
