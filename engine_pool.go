package caddy_waf_t1k

import (
	"time"

	"github.com/caddyserver/caddy/v2"
)

// engineKey uniquely identifies one Engine configuration in the process-wide
// registry: the Engine address plus every Connection pool and Passive health
// check parameter. Fully identical keys share one Engine; any difference
// yields an independent Engine (surfaced as separate metric series — an
// operator misconfiguration signal).
type engineKey struct {
	addr               string
	initialCap         int
	maxIdle            int
	maxCap             int
	idleTimeout        time.Duration
	healthMaxFails     int
	healthFailDuration time.Duration
}

// engineRegistry is the process-wide, reference-counted store of Engines.
// An Engine lives until the last referencing WAF instance releases it,
// surviving config reloads in between (caddy.UsagePool, the same primitive
// reverseproxy.hosts uses to preserve upstream state).
var engineRegistry = caddy.NewUsagePool()

// acquireEngine returns the Engine registered under key, constructing a new
// one via construct on first use. loaded is true when an existing Engine was
// reused. Either way the Engine's reference count is incremented; callers
// must call releaseEngine once for every successful acquireEngine.
func acquireEngine(key engineKey, construct caddy.Constructor) (*Engine, bool, error) {
	value, loaded, err := engineRegistry.LoadOrNew(key, construct)
	if err != nil {
		return nil, false, err
	}
	return value.(*Engine), loaded, nil
}

// releaseEngine decrements the reference count for key. deleted is true when
// the count reached zero, the Engine left the registry, and its Destruct()
// ran (Connection pool released, metric series removed).
func releaseEngine(key engineKey) (bool, error) {
	return engineRegistry.Delete(key)
}
