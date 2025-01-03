package caddy_waf_t1k

import (
	"encoding/json"
	weakrand "math/rand"
	"net/http"
	"sync/atomic"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/chaitin/t1k-go"
)

func init() {
	caddy.RegisterModule(RandomSelection{})
	caddy.RegisterModule(RoundRobinSelection{})
}

// LoadBalancing has parameters related to load balancing.
type LoadBalancing struct {
	// A selection policy is how to choose an available backend.
	// The default policy is random selection.
	SelectionPolicyRaw json.RawMessage `json:"selection_policy,omitempty" caddy:"namespace=http.waf_chaitin.selection_policies inline_key=policy"`

	SelectionPolicy Selector `json:"-"`
}

// Selector selects an available upstream from the pool.
type Selector interface {
	Select(EnginePool, *http.Request, http.ResponseWriter) *t1k.ChannelPool
}

// RandomSelection is a policy that selects
// an available host at random.
type RandomSelection struct{}

// CaddyModule returns the Caddy module information.
func (RandomSelection) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.waf_chaitin.selection_policies.random",
		New: func() caddy.Module { return new(RandomSelection) },
	}
}

// Select returns an available host, if any.
func (r RandomSelection) Select(pool EnginePool, request *http.Request, _ http.ResponseWriter) *t1k.ChannelPool {
	return selectRandomHost(pool)
}

// UnmarshalCaddyfile sets up the module from Caddyfile tokens.
func (r *RandomSelection) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	d.Next() // consume policy name
	if d.NextArg() {
		return d.ArgErr()
	}
	return nil
}

// selectRandomHost returns a random available host
func selectRandomHost(pool []*t1k.ChannelPool) *t1k.ChannelPool {
	// use reservoir sampling because the number of available
	// hosts isn't known: https://en.wikipedia.org/wiki/Reservoir_sampling
	var randomHost *t1k.ChannelPool
	var count int
	for _, upstream := range pool {
		count++
		if (weakrand.Int() % count) == 0 { //nolint:gosec
			randomHost = upstream
		}
	}
	return randomHost
}

// RoundRobinSelection is a policy that selects
// a host based on round-robin ordering.
type RoundRobinSelection struct {
	robin uint32
}

// CaddyModule returns the Caddy module information.
func (RoundRobinSelection) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.waf_chaitin.selection_policies.round_robin",
		New: func() caddy.Module { return new(RoundRobinSelection) },
	}
}

// Select returns an available host, if any.
func (r *RoundRobinSelection) Select(pool EnginePool, _ *http.Request, _ http.ResponseWriter) *t1k.ChannelPool {
	n := uint32(len(pool))
	if n == 0 {
		return nil
	}
	robin := atomic.AddUint32(&r.robin, 1)
	host := pool[robin%n]
	return host
}

// UnmarshalCaddyfile sets up the module from Caddyfile tokens.
func (r *RoundRobinSelection) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	d.Next() // consume policy name
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
