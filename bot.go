package caddy_waf_t1k

import (
	"net/http"
	"strings"
)

var botCookieNames = []string{
	"sl_xxx_ug_to",
	"sl_xxx_ug_to_t",
	"sl_xxx_ug_fg",
	"sl_xxx_fig",
}

// stripBotCookies removes SafeLine internal bot-detection cookies from the request
// so they are not forwarded to the upstream backend.
func stripBotCookies(r *http.Request) {
	cookies := r.Cookies()
	var kept []string
	for _, c := range cookies {
		isBotCookie := false
		for _, name := range botCookieNames {
			if c.Name == name {
				isBotCookie = true
				break
			}
		}
		if !isBotCookie {
			kept = append(kept, c.String())
		}
	}
	if len(kept) > 0 {
		r.Header.Set("Cookie", strings.Join(kept, "; "))
	} else {
		r.Header.Del("Cookie")
	}
}
