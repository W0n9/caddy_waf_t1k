# About this repo

This is a WAF plugin for [Caddy Server](https://github.com/caddyserver/caddy) using [Chaitin SafeLine](https://github.com/chaitin/SafeLine) as backend engine.

# How to use

```
(waf) {
	route {
		waf_chaitin {
			waf_engine_addr 169.254.0.5:8000 169.254.0.6:8000 169.254.0.7:8000
			initial_cap 1 # initial connection of the engine
			max_idle 16 # max idle connections
			max_cap 32 # max connections
			idle_timeout 30s # connections idle timeout
			lb_policy round_robin # load balancing policy (random or round_robin, default: random)
			health_fail_duration 30s # passive health check window (default: 0 = disabled)
			health_max_fails 3 # failure threshold to mark engine unhealthy (default: 1)
		}
	}
}

:8000 {
	import waf
	respond / "Hello, world!"
}

```

# How to build

```
xcaddy build --with github.com/W0n9/caddy_waf_t1k --replace github.com/chaitin/t1k-go=github.com/w0n9/t1k-go@latest
```

Local development (uses `src/t1k-go` checkout):

```
xcaddy build \
  --with github.com/W0n9/caddy_waf_t1k=. \
  --replace github.com/chaitin/t1k-go=./src/t1k-go \
  --output ./build/caddy
```

# Prometheus metrics

The plugin registers metrics on Caddy's metrics registry. Expose them for scraping:

```caddyfile
:9090 {
    metrics /metrics
}
```

Or scrape the Admin API: `GET http://localhost:2019/metrics`

**Request metrics**

| Metric | Labels | Description |
|--------|--------|-------------|
| `caddy_waf_requests_total` | `action` | blocked / passed / error / failopen |
| `caddy_waf_detect_duration_seconds` | `engine` | WAF detection latency |

**Engine health & connection pool** (updated every 10s)

| Metric | Labels | Description |
|--------|--------|-------------|
| `caddy_waf_engines_healthy` | `engine` | 1=healthy, 0=unhealthy |
| `caddy_waf_pool_idle_conns` | `engine` | Idle TCP connections |
| `caddy_waf_pool_active_conns` | `engine` | Active TCP connections |
| `caddy_waf_pool_max_conns` | `engine` | Configured max connections |
| `caddy_waf_pool_waiting_requests` | `engine` | Requests waiting for a connection |

**Connection errors & pool events**

| Metric | Labels | Description |
|--------|--------|-------------|
| `caddy_waf_connection_errors_total` | `engine`, `reason` | Detect errors (connection_refused, dial_timeout, broken_pipe, max_active_reached, pool_closed, client_error, other) |
| `caddy_waf_pool_events_total` | `engine`, `reason` | Pool lifecycle (dial_failed, idle_expired, ping_failed, pool_full_close, max_active_hit) |

**Example PromQL**

```promql
# Connection pool utilization
caddy_waf_pool_active_conns / caddy_waf_pool_max_conns

# Engine unhealthy
caddy_waf_engines_healthy == 0

# Connection error rate
rate(caddy_waf_connection_errors_total[5m])
```

**Example alert rules**

```yaml
- alert: WAFEngineUnhealthy
  expr: caddy_waf_engines_healthy == 0
  for: 1m

- alert: WAFPoolSaturated
  expr: caddy_waf_pool_active_conns / caddy_waf_pool_max_conns > 0.9
  for: 5m

- alert: WAFPoolWaiting
  expr: caddy_waf_pool_waiting_requests > 0
  for: 2m

- alert: WAFConnectionErrors
  expr: rate(caddy_waf_connection_errors_total[5m]) > 0.1
  for: 3m
```

# TODO
- [x] Detection and Interception  
- [x]  Pass the `remote_addr` to the Engine  
- [x]  Multi backend engine instances support, include Load Balance and High Availability
