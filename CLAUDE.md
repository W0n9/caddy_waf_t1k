# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What This Project Is

A [Caddy Server](https://github.com/caddyserver/caddy) plugin that integrates [Chaitin SafeLine](https://github.com/chaitin/SafeLine) as a WAF backend engine. HTTP requests are forwarded to one or more t1k engine instances over TCP for threat detection; blocked requests receive an intercept response.

## Build Commands

This plugin cannot be built with `go build` directly — Caddy plugins must be compiled via `xcaddy`:

```bash
# Install xcaddy first
go install github.com/caddyserver/xcaddy/cmd/xcaddy@latest

# Build a Caddy binary with this plugin embedded
xcaddy build \
  --with github.com/W0n9/caddy_waf_t1k \
  --replace github.com/chaitin/t1k-go=github.com/w0n9/t1k-go@latest

# Build from local checkout (development)
xcaddy build \
  --with github.com/W0n9/caddy_waf_t1k=. \
  --replace github.com/chaitin/t1k-go=./src/t1k-go \
  --output ./build/caddy
```

## Test / Lint Commands

```bash
# Compile check (no real unit tests exist yet)
go test ./...

# Verify module consistency
go mod tidy
go mod verify
```

## Repository Layout Notes

- Root module is the Caddy plugin; `src/t1k-go`, `src/caddy`, and `src/xcaddy` are adjacent source checkouts for local dependency/reference work, not plugin packages.
- Local development/testing should prefer the local `src/t1k-go` checkout; if a remote `t1k-go` tag is needed, ask the human which tag to use instead of hard-coding one.
- `go test ./...` is a compile check only; request detection behavior requires a reachable SafeLine/t1k engine at each `waf_engine_addr`.

## Architecture

Five core source files plus metrics/error helpers:

| File | Responsibility |
|------|---------------|
| `waf.go` | Module registration, `Engine` wrapper struct (self-contained health: `fail()`/`Destruct()`), `Provision` (acquire Engines from the registry), `ServeHTTP` (detect + block + metrics), `Cleanup` (release registry references), error classification (`isEngineError`) |
| `engine_pool.go` | Process-wide, reference-counted Engine registry (`caddy.UsagePool`): `engineKey` (address + all pool/health params), `acquireEngine`/`releaseEngine`, `Engine.Destruct()` (pool release + metric series removal) |
| `caddyfile.go` | Caddyfile directive parsing (`waf_chaitin { ... }`) |
| `load_balancer.go` | `Selector` interface + `RandomSelection` / `RoundRobinSelection` implementations (skip unhealthy engines) |
| `rule.go` | `redirectIntercept` — writes the block response when a request is flagged |
| `metrics.go` | Prometheus metrics registration and single global pool/health gauge updater (10s) |
| `errors.go` | `classifyConnectionError` — maps Detect errors to Prometheus `reason` labels |

**Request flow:**  
`ServeHTTP` → when `max_body_size > 0` and the body exceeds the cap or its length is unknown, pre-read the first N+1 bytes, reattach the fully-read segment plus the remaining original stream to the downstream request, and build a separate request containing only the first N bytes for detection; when the length is known and within the cap, or the cap is 0, the original request is kept as-is → loop up to 1+lb_retries: Select from engines excluding already-tried (skips unhealthy) → `DetectHttpRequest` → on success block/pass → on client error fail-open → on engine error `engine.fail()` and retry if attempts remain and untried engines exist → else fail-open. If Select returns nil with no prior tries → failopen; if nil after tries → error.

**Error classification:**  
`isEngineError()` distinguishes client-side errors (H3_REQUEST_CANCELLED, client disconnected, keepalive limit, `read request body` prefix from t1k-go Body reads, etc.) from engine-side errors (connection refused, dial timeout, broken pipe, engine TCP connection reset). Client body-read failures are tagged with `read request body` so they are not confused with engine-side `unexpected EOF` / reset. Only engine errors count toward health check failures.

**Passive health check (Caddy-style):**  
On engine error, `Engine.fail()` atomically increments the Engine's fail counter and schedules a `time.AfterFunc` that decrements it after the Engine's own `failDuration` (copied from `health_fail_duration` at construction). When `fails >= maxFails` (`health_max_fails`), the Engine is marked unavailable and skipped by selection policies. Because the health window lives on the shared Engine, all instances agree on availability. Setting `health_fail_duration` to 0 (default) disables health checking entirely.

**Intercept response:**  
Blocked requests set `Content-Type: application/json`, `X-Event-ID`, return HTTP 501, and write `{"message":"Intercept illegal requests","event_id":"..."}` JSON from `redirectIntercept`.

**Prometheus metrics:**  
Engines are shared process-wide (see `engine_pool.go`); one global updater goroutine (started once by the first provisioned instance, `startGlobalMetricsUpdater`) reports every Engine in the registry on a 10s cadence. Pool/health gauges, `pool_events_total`, and `connection_errors_total` are labeled by Engine address only — there is no `waf_instance` label — so a shared Engine exposes exactly one series and `sum by (engine)(...)` / `max by (engine)(caddy_waf_engines_healthy)` work directly. `Cleanup` releases registry references; an Engine's metric series are removed by its `Destruct` when the last referencing instance releases it. `requests_total`, `detect_duration_seconds`, and `oversize_requests_total` have always been instance-independent.

Request / detection:
- `caddy_waf_requests_total{action}` — counter (blocked/passed/error/failopen)
- `caddy_waf_detect_duration_seconds{engine}` — histogram
- `caddy_waf_oversize_requests_total` — counter of requests whose body was truncated for detection

Engine health & connection pool (refreshed every 10s by the single global updater):
- `caddy_waf_engines_healthy{engine}` — gauge (1=healthy, 0=unhealthy)
- `caddy_waf_pool_idle_conns{engine}` — gauge
- `caddy_waf_pool_active_conns{engine}` — gauge
- `caddy_waf_pool_max_conns{engine}` — gauge
- `caddy_waf_pool_waiting_requests{engine}` — gauge

Connection errors & pool events:
- `caddy_waf_connection_errors_total{engine,reason}` — counter (Detect-layer errors: connection_refused, dial_timeout, broken_pipe, max_active_reached, pool_closed, client_error, other)
- `caddy_waf_pool_events_total{engine,reason}` — counter (pool lifecycle: dial_failed, idle_expired, ping_failed, pool_full_close, max_active_hit)

Scrape via Caddy `metrics` handler or Admin API `/metrics`. See README for examples.

**Engine pool:**  
Engines are process-shared via the registry in `engine_pool.go`: one `t1k.ChannelPool` (a TCP connection pool to one SafeLine engine address) per unique `engineKey` (address + `initial_cap` + `max_idle` + `max_cap` + `idle_timeout` + `health_max_fails` + `health_fail_duration`). All WAF instances referencing the same address with identical shaping parameters share one Engine and its pool; differing parameters yield independent Engines. An Engine survives config reloads until the last referencing instance releases it.

## Important: Module Replace Directive

`go.mod` replaces the upstream `github.com/chaitin/t1k-go` with the local checkout at `./src/t1k-go` for development. For release builds, use `--replace github.com/chaitin/t1k-go=github.com/w0n9/t1k-go@latest` (or a pinned tag). Forgetting this flag causes a build failure.

## Caddyfile Configuration Reference

```caddyfile
waf_chaitin {
    waf_engine_addr 169.254.0.5:8000 169.254.0.6:8000  # one or more IP:port
    initial_cap 1      # initial connections per pool
    max_idle 16        # max idle connections per pool
    max_cap 32         # max total connections per pool
    idle_timeout 30s   # duration string (e.g. 30s, 1m) — NOT bare integer
    max_body_size 1MiB # bytes inspected per detection; 0 = unlimited (default)
    lb_policy round_robin  # optional; default is random
    lb_retries 1              # optional; additional Detect attempts after engine error (default: 0)
    health_fail_duration 30s  # passive health check window; 0 = disabled (default)
    health_max_fails 3        # failure threshold to mark engine unhealthy (default: 1)
}
```

## Caddy Module IDs

- Handler: `http.handlers.waf_chaitin`
- Selection policies namespace: `http.waf_chaitin.selection_policies`
  - `http.waf_chaitin.selection_policies.random`
  - `http.waf_chaitin.selection_policies.round_robin`
