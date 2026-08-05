# caddy-waf-t1k

A Caddy middleware that sends HTTP requests to Chaitin SafeLine (t1k) detection engines and blocks or passes them based on the result. One Caddy process typically provisions many `waf_chaitin` handler instances (one per vhost / route), all backed by the same set of engines.

## Language

**WAF instance**:
A single occurrence of the `waf_chaitin` directive in the Caddyfile. Caddy provisions each occurrence as a separate handler instance, even when the configs are identical.
_Avoid_: handler, directive

**Engine**:
A SafeLine detection engine reachable at one TCP address (`host:port`). Owns its connection pool and its passive-health state. Engines are shared process-wide: all instances referencing the same address+config combination use the same Engine.
_Avoid_: backend, upstream

**Engine pool** (an instance's view):
The ordered set of Engines one WAF instance load-balances across. Per-instance; distinct from the process-wide engine registry.
_Avoid_: shared pool, engine set

**Engine registry**:
The process-wide, reference-counted store of Engines, keyed by engine address plus every pool/health parameter. An Engine lives until the last referencing instance releases it. This is what survives config reloads.
_Avoid_: pool manager, engine cache

**Detection**:
Sending an HTTP request to an Engine for threat inspection. Outcome is one of blocked / passed / error.
_Avoid_: scanning, filtering

**Fail-open**:
The behavior when no Engine is available: the request is passed through to the next handler without detection. Explicitly chosen over fail-closed.
_Avoid_: pass-through (ambiguous)

**Passive health check**:
Counting detection failures against an Engine within a decay window; the Engine is treated as unavailable while the count is at or above `health_max_fails`. Decay duration and threshold are fixed onto the shared Engine, so all instances agree on availability.
_Avoid_: health status, fail count

**Connection pool**:
The per-Engine pool of TCP connections to the engine address (idle + in-use). Capacity governed by `initial_cap`, `max_idle`, `max_cap`, `idle_timeout`.
_Avoid_: channel, connection manager

**Load balancing policy**:
How a WAF instance selects among its Engines on each request (`random` or `round_robin`). Selection state is per-instance.
_Avoid_: upstream policy

**Engine address**:
The `host:port` of an Engine, as given by `waf_engine_addr`.
_Avoid_: engine URL, endpoint
