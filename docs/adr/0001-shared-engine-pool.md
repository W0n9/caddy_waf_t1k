# Shared engine pool across WAF instances

Every `waf_chaitin` occurrence in the Caddyfile is provisioned as a separate handler instance, and each instance previously built its own `t1k.ChannelPool` per engine address. With ~68 instances × 3 addresses in production this created ~204 independent pools (up to ~26k connections) and made the pool gauge metrics (summed over the `waf_instance` label) meaningless.

We decided to make Engines process-shared: a process-wide, reference-counted registry (`caddy.UsagePool`, the same primitive `reverseproxy.hosts` uses) keyed by engine address plus every pool and health parameter. Two instances only share an Engine when all shaping parameters match; otherwise they get independent Engines. Each Engine owns its connection pool and its passive-health state (`health_max_fails` / `health_fail_duration` fixed onto the Engine, not the instance), so availability is agreed globally and the pool survives config reloads until the last referencing instance releases it. Pool and health metrics are now reported per engine address by a single global updater; the `waf_instance` label is gone from pool gauges, health, pool events, and connection-error counters.

## Considered options

- **Share only the connection pool, keep health per-instance** — rejected: connection count shrinks but health verdicts would still diverge across instances.
- **Key by address only, first-wins on config conflicts** — rejected: later instances' `max_cap` etc. would silently not apply; keying by all parameters makes capacity tuning per-site still work via separate Engines.
- **Keep per-instance metric updaters / keep the `waf_instance` label** — rejected: 68 goroutines setting identical values and 204 redundant series defeat the purpose.

## Consequences

- Same-address Engines with different parameter sets are deliberately *not* shared (two pools to one address) — an operator footgun, but visible in metrics and a signal of misconfiguration.
- `caddy_waf_pool_active_conns` still reports t1k's `openingConns` (total open connections, idle + in-use), not just in-use; existing semantics kept, documented as "active connections" in the pool.
