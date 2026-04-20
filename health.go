package caddy_waf_t1k

import (
	"context"
	"net"
	"net/http"
	"sync/atomic"
	"time"

	t1k "github.com/chaitin/t1k-go"
	"github.com/chaitin/t1k-go/detection"
	"go.uber.org/zap"
)

// detector abstracts WAF engine detection for testability.
type detector interface {
	DetectHttpRequest(*http.Request) (*detection.Result, error)
}

type engineEntry struct {
	engine    detector
	addr      string
	healthy   atomic.Bool
	failCount atomic.Int32
	okCount   atomic.Int32
}

func newEngineEntry(pool *t1k.ChannelPool, addr string) *engineEntry {
	e := &engineEntry{engine: pool, addr: addr}
	e.healthy.Store(true)
	return e
}

// updateHealth updates engine health state based on a single probe result.
// Called by the health check goroutine; also usable directly in tests.
func (e *engineEntry) updateHealth(success bool, failureThreshold, recoveryThreshold int32, logger *zap.Logger) {
	if success {
		e.failCount.Store(0)
		newOK := e.okCount.Add(1)
		if newOK >= recoveryThreshold && e.healthy.CompareAndSwap(false, true) {
			logger.Info("WAF engine recovered",
				zap.String("engine_addr", e.addr))
		}
	} else {
		e.okCount.Store(0)
		newFail := e.failCount.Add(1)
		if newFail >= failureThreshold && e.healthy.CompareAndSwap(true, false) {
			logger.Warn("WAF engine marked unhealthy",
				zap.String("engine_addr", e.addr),
				zap.Int32("fail_count", newFail))
		}
	}
	setEngineHealthy(e.addr, e.healthy.Load())
}

// startHealthCheck starts a background goroutine that probes the engine via TCP dial.
// The goroutine exits when ctx is cancelled.
func (e *engineEntry) startHealthCheck(ctx context.Context, interval time.Duration, failureThreshold, recoveryThreshold int32, logger *zap.Logger) {
	dialTimeout := max(interval/2, 500*time.Millisecond)
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				conn, err := net.DialTimeout("tcp", e.addr, dialTimeout)
				if err == nil {
					conn.Close()
					e.updateHealth(true, failureThreshold, recoveryThreshold, logger)
				} else {
					e.updateHealth(false, failureThreshold, recoveryThreshold, logger)
				}
			}
		}
	}()
}
