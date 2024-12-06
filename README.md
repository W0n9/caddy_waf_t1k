# About this repo

This is a WAF plugin for [Caddy Server](https://github.com/caddyserver/caddy) using [Chaitin SafeLine](https://github.com/chaitin/SafeLine) as backend engine.

# How to use

```
(waf) {
	route {
		waf_chaitin {
			waf_engine_addr 169.254.0.5:8000
			pool_size 10
			timeout 1000
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
xcaddy build --with github.com/W0n9/caddy_waf_t1k
```

# TODO
- [x] Detection and Interception  
- [x]  Pass the `remote_addr` to the Engine  
- [ ]  Multi backend engine instances support, include Load Balance and High Availability
