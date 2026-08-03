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
			lb_retries 1 # additional engines to try after Detect engine error (default: 0)
			max_body_size 1MiB # inspect at most 1 MiB of each request body; 0 = unlimited (default)
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

# 请求体检测上限

默认情况下，WAF 会为检测而缓冲完整请求体。使用 `max_body_size` 可限制发送给 WAF 引擎的请求体字节数：

```caddyfile
max_body_size 1MiB
```

只有前 N 个字节会送往检测；完整请求体仍会流式转发给下游处理器，因此此配置**不会**限制或截断上传。若需限制上传本身的大小，请使用 Caddy 原生的 `request_body { max_size ... }` 指令。

默认值为 `0`，保持原有的无限制行为。大小可以使用字节数或 `go-humanize` 的 SI/IEC 后缀，例如 `1MB`、`1MiB`、`512KB`。

# Load balancing retries

By default (`lb_retries 0`), a Detect engine error fail-opens immediately (same as before).
Set `lb_retries` to try other engines on the same request (engine errors only; client errors are never retried).
To approximate nginx `t1k_next_upstream` with N engines, use `lb_retries N-1`.

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
| `caddy_waf_oversize_requests_total` | — | Requests whose body was truncated for detection |

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

# 端到端冒烟验证

本节描述如何手动验证 `max_body_size` 在真实 Caddy 进程中同时满足三个目标：
- 大文件上传到达上游时校验和不变（插件不截断实际传输）
- `caddy_waf_oversize_requests_total` 递增（截断逻辑触发）
- 进程常驻内存峰值被压住（不随文件大小线性增长）

## 第一步：构建 Caddy

```bash
xcaddy build \
  --with github.com/W0n9/caddy_waf_t1k=. \
  --replace github.com/chaitin/t1k-go=github.com/w0n9/t1k-go@v1.5.10 \
  --output ./build/caddy
```

## 第二步：生成测试文件并记录校验和

```bash
# 生成约 50 MiB 的随机数据
openssl rand -out /tmp/testfile.bin $((50 * 1024 * 1024))

# 记录源文件校验和，后续对比用
sha256sum /tmp/testfile.bin
# 示例输出：
# a3b4c5...  /tmp/testfile.bin
```

## 第三步：准备上游与 Caddyfile

启动一个能接收上传并将内容原样写入文件的简易上游。可以用任意 HTTP 工具，例如：

```bash
# 用 Python 在 9999 端口起一个简易文件接收服务
python3 - <<'PY' &
import http.server, os

class Handler(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        length = int(self.headers.get('Content-Length', 0))
        data = self.rfile.read(length)
        with open('/tmp/received.bin', 'wb') as f:
            f.write(data)
        self.send_response(200)
        self.end_headers()
    def log_message(self, *_): pass

http.server.HTTPServer(('127.0.0.1', 9999), Handler).serve_forever()
PY
UPSTREAM_PID=$!
```

编写 `Caddyfile`，将 `:8080` 的所有请求经过 WAF 后反代到上游：

```caddyfile
:8080 {
    route {
        waf_chaitin {
            waf_engine_addr <T1K_ENGINE_ADDR>
            max_body_size 1MiB
            initial_cap 1
            max_idle 4
            max_cap 8
        }
        reverse_proxy 127.0.0.1:9999
    }
}

:9090 {
    metrics /metrics
}
```

将 `<T1K_ENGINE_ADDR>` 替换为实际 SafeLine/t1k 引擎的地址（如 `169.254.0.5:8000`）。

启动 Caddy：

```bash
./build/caddy run --config Caddyfile
```

## 第四步：上传并验证校验和

```bash
# 上传前记录基准指标（oversize 计数）
BEFORE=$(curl -s http://localhost:9090/metrics \
  | grep '^caddy_waf_oversize_requests_total' \
  | awk '{print $2}')
echo "oversize before: ${BEFORE}"

# 上传测试文件
curl -s -X POST http://localhost:8080/upload \
  --data-binary @/tmp/testfile.bin \
  -H "Content-Type: application/octet-stream"

# 计算上游收到的文件校验和
sha256sum /tmp/received.bin
# 预期：与第二步 sha256sum /tmp/testfile.bin 的输出完全一致
```

如果两个 sha256 完全一致，说明插件在截断检测缓冲的同时完整转发了请求体，上游数据无损。

## 第五步：确认指标与内存峰值

**oversize 计数递增**

```bash
AFTER=$(curl -s http://localhost:9090/metrics \
  | grep '^caddy_waf_oversize_requests_total' \
  | awk '{print $2}')
echo "oversize after: ${AFTER}"
# 预期：AFTER = BEFORE + 1
```

如果计数递增，说明截断逻辑确实在本次请求中触发。

**进程内存峰值**

```bash
# 在上传期间（或上传后立即）抓取常驻内存
curl -s http://localhost:9090/metrics \
  | grep '^process_resident_memory_bytes'
# 预期：读数远低于 50 MiB（接近 max_body_size 量级的几倍，而不是文件大小级别）
```

如果常驻内存峰值明显低于 50 MiB（接近 1–2 MiB 量级），说明 `max_body_size` 有效地阻止了 WAF 将完整请求体读入内存。

## 清理

```bash
kill $UPSTREAM_PID 2>/dev/null || true
rm -f /tmp/testfile.bin /tmp/received.bin
```
