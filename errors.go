package caddy_waf_t1k

import (
	"strings"
)

const (
	reasonConnectionRefused = "connection_refused"
	reasonDialTimeout       = "dial_timeout"
	reasonBrokenPipe        = "broken_pipe"
	reasonMaxActiveReached  = "max_active_reached"
	reasonPoolClosed        = "pool_closed"
	reasonClientError       = "client_error"
	reasonOther             = "other"
)

func classifyConnectionError(err error) string {
	if err == nil {
		return reasonOther
	}

	msg := err.Error()
	if !isEngineError(err) {
		return reasonClientError
	}

	switch {
	case strings.Contains(msg, "connection refused"):
		return reasonConnectionRefused
	case strings.Contains(msg, "i/o timeout"):
		return reasonDialTimeout
	case strings.Contains(msg, "broken pipe"):
		return reasonBrokenPipe
	case strings.Contains(msg, "max active connections reached"):
		return reasonMaxActiveReached
	case strings.Contains(msg, "pool is closed"):
		return reasonPoolClosed
	default:
		return reasonOther
	}
}
