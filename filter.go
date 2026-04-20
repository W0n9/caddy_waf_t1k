package caddy_waf_t1k

import (
	"net/http"
	"strings"
)

type filterResult int

const (
	filterPass     filterResult = iota
	filterSkipAll               // skip entire detection
	filterSkipBody              // skip body detection only; headers still inspected
)

// checkFilter returns how a request should be handled before WAF detection.
func checkFilter(r *http.Request, skipContentTypes []string, skipHeader string, maxBodyBytes int64) filterResult {
	if skipHeader != "" && r.Header.Get(skipHeader) != "" {
		return filterSkipAll
	}
	ct := r.Header.Get("Content-Type")
	if ct != "" {
		for _, skip := range skipContentTypes {
			if strings.HasPrefix(ct, skip) {
				return filterSkipAll
			}
		}
	}
	if maxBodyBytes > 0 && r.ContentLength > maxBodyBytes {
		return filterSkipBody
	}
	return filterPass
}
