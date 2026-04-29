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
  --replace github.com/chaitin/t1k-go=github.com/w0n9/t1k-go@latest \
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

Four source files form the entire plugin:

| File | Responsibility |
|------|---------------|
| `waf.go` | Module registration, `Engine` wrapper struct, `Provision` (pool init), `ServeHTTP` (detect + block + metrics), `Cleanup`, error classification (`isEngineError`), passive health check (`countFailure`) |
| `caddyfile.go` | Caddyfile directive parsing (`waf_chaitin { ... }`) |
| `load_balancer.go` | `Selector` interface + `RandomSelection` / `RoundRobinSelection` implementations (skip unhealthy engines) |
| `rule.go` | `redirectIntercept` — writes the block response when a request is flagged |
| `metrics.go` | Prometheus metrics registration and engine health gauge updater |

**Request flow:**  
`ServeHTTP` → pick engine via `LoadBalancing.SelectionPolicy.Select(m.Engines, r, w)` (skips unhealthy engines) → if all engines unavailable, fail-open → `engine.DetectHttpRequest(r)` → if error, classify via `isEngineError()`: engine errors trigger `countFailure()` (logged as error), client errors are logged as warn; both fail-open → if `result.Blocked()` call `redirectIntercept`, else call `next.ServeHTTP`.

**Error classification:**  
`isEngineError()` distinguishes client-side errors (H3_REQUEST_CANCELLED, client disconnected, keepalive limit, connection reset by peer, etc.) from engine-side errors (connection refused, dial timeout, broken pipe). Only engine errors count toward health check failures.

**Passive health check (Caddy-style):**  
On engine error, `countFailure()` atomically increments the engine's fail counter and spawns a goroutine that decrements it after `health_fail_duration`. When `fails >= health_max_fails`, the engine is marked unavailable and skipped by selection policies. Setting `health_fail_duration` to 0 (default) disables health checking entirely.

**Intercept response:**  
Blocked requests set `Content-Type: application/json`, `X-Event-ID`, return HTTP 501, and write `{"message":"Intercept illegal requests","event_id":"..."}` JSON from `redirectIntercept`.

**Prometheus metrics:**  
- `caddy_waf_requests_total{action}` — counter (blocked/passed/error/failopen)
- `caddy_waf_detect_duration_seconds{engine}` — histogram
- `caddy_waf_engines_healthy{engine}` — gauge (1=healthy, 0=unhealthy), updated every 10s

**Engine pool:**  
Each address in `waf_engine_addrs` gets its own `t1k.ChannelPool` (a TCP connection pool to one SafeLine engine). The pool settings (`initial_cap`, `max_idle`, `max_cap`, `idle_timeout`) are shared across all pools.

## Important: Module Replace Directive

`go.mod` replaces the upstream `github.com/chaitin/t1k-go` with a fork `github.com/w0n9/t1k-go`. This must be carried through in every `xcaddy build` call via `--replace github.com/chaitin/t1k-go=github.com/w0n9/t1k-go@latest`. Forgetting this flag causes a build failure.

## Caddyfile Configuration Reference

```caddyfile
waf_chaitin {
    waf_engine_addr 169.254.0.5:8000 169.254.0.6:8000  # one or more IP:port
    initial_cap 1      # initial connections per pool
    max_idle 16        # max idle connections per pool
    max_cap 32         # max total connections per pool
    idle_timeout 30s   # duration string (e.g. 30s, 1m) — NOT bare integer
    lb_policy round_robin  # optional; default is random
    health_fail_duration 30s  # passive health check window; 0 = disabled (default)
    health_max_fails 3        # failure threshold to mark engine unhealthy (default: 1)
}
```

## Caddy Module IDs

- Handler: `http.handlers.waf_chaitin`
- Selection policies namespace: `http.waf_chaitin.selection_policies`
  - `http.waf_chaitin.selection_policies.random`
  - `http.waf_chaitin.selection_policies.round_robin`
