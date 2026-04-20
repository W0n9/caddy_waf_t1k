package caddy_waf_t1k

import (
	"encoding/json"
	weakrand "math/rand"
	"net/http"
	"sync/atomic"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
)

func init() {
	caddy.RegisterModule(RandomSelection{})
	caddy.RegisterModule(RoundRobinSelection{})
}

// LoadBalancing has parameters related to load balancing.
type LoadBalancing struct {
	SelectionPolicyRaw json.RawMessage `json:"selection_policy,omitempty" caddy:"namespace=http.waf_chaitin.selection_policies inline_key=policy"`
	SelectionPolicy    Selector        `json:"-"`
}

// Selector selects an available engine from the pool.
type Selector interface {
	Select(EnginePool, *http.Request, http.ResponseWriter) *engineEntry
}

// healthyPool returns only healthy engines. Returns the full pool if all are unhealthy (fail-open).
func healthyPool(pool EnginePool) EnginePool {
	var healthy EnginePool
	for _, e := range pool {
		if e.healthy.Load() {
			healthy = append(healthy, e)
		}
	}
	if len(healthy) == 0 {
		return pool
	}
	return healthy
}

// RandomSelection selects an available engine at random.
type RandomSelection struct{}

func (RandomSelection) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.waf_chaitin.selection_policies.random",
		New: func() caddy.Module { return new(RandomSelection) },
	}
}

func (r RandomSelection) Select(pool EnginePool, _ *http.Request, _ http.ResponseWriter) *engineEntry {
	return selectRandomEntry(healthyPool(pool))
}

func (r *RandomSelection) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	d.Next()
	if d.NextArg() {
		return d.ArgErr()
	}
	return nil
}

func selectRandomEntry(pool EnginePool) *engineEntry {
	var chosen *engineEntry
	var count int
	for _, e := range pool {
		count++
		if (weakrand.Int() % count) == 0 { //nolint:gosec
			chosen = e
		}
	}
	return chosen
}

// RoundRobinSelection selects an engine based on round-robin ordering.
type RoundRobinSelection struct {
	robin uint32
}

func (RoundRobinSelection) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.waf_chaitin.selection_policies.round_robin",
		New: func() caddy.Module { return new(RoundRobinSelection) },
	}
}

func (r *RoundRobinSelection) Select(pool EnginePool, _ *http.Request, _ http.ResponseWriter) *engineEntry {
	candidates := healthyPool(pool)
	n := uint32(len(candidates))
	if n == 0 {
		return nil
	}
	robin := atomic.AddUint32(&r.robin, 1)
	return candidates[robin%n]
}

func (r *RoundRobinSelection) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	d.Next()
	if d.NextArg() {
		return d.ArgErr()
	}
	return nil
}

// Interface guards
var (
	_ Selector = (*RandomSelection)(nil)
	_ Selector = (*RoundRobinSelection)(nil)
)
