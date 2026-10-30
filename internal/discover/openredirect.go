// Open-redirect detection: when a URL takes a parameter like ?url=, ?next=,
// ?redirect= and reflects it as a Location header, that's a classic open-
// redirect — low on its own but a potent primitive for phishing, OAuth
// state-smuggling, and SSRF-adjacent chains.
//
// Hellhound already surfaces URLs with suspicious parameter names during
// discovery; this phase actively verifies they're exploitable by sending a
// known external payload and checking whether the server tries to redirect
// us to it.
package discover

import (
	"context"
	"net/url"
	"strings"

	"github.com/securewithharshitrajput/hellhound/internal/engine"
)

// redirectParams is the set of parameter names commonly used for post-login
// / post-action redirects. Kept small so we don't fuzz every query key.
var redirectParams = []string{
	"url", "redirect", "redirect_uri", "redirect_url", "redirectUri", "redirectUrl",
	"next", "nextUrl", "return", "returnTo", "return_url", "returnUrl",
	"goto", "target", "destination", "dest", "continue", "callback",
	"forward", "forward_url", "to",
}

// openRedirectCanary is a fully-qualified host that is unmistakably external
// and belongs to no legitimate relative-path handling. Any redirect to this
// is unambiguous evidence the parameter is reflected without validation.
const openRedirectCanary = "https://example.org/hellhound-open-redirect-canary"

// ScanOpenRedirects looks at every URL in `candidates`, finds those whose
// query string contains a redirect-shaped parameter, and probes each one
// with the canary value. A 3xx Location pointing to the canary host (or
// to a path like //example.org/... that browsers follow externally) is
// classified as an open-redirect finding.
func ScanOpenRedirects(ctx context.Context, eng *engine.Engine, candidates []string) []SecurityFinding {
	type probeInfo struct {
		OriginalURL string
		Param       string
	}
	var reqs []engine.Request
	var infos []probeInfo

	seen := map[string]bool{}
	for _, raw := range candidates {
		u, err := url.Parse(raw)
		if err != nil {
			continue
		}
		q := u.Query()
		if len(q) == 0 {
			continue
		}
		for _, p := range redirectParams {
			// case-insensitive param lookup (q.Get is case-sensitive)
			var actualKey string
			for k := range q {
				if strings.EqualFold(k, p) {
					actualKey = k
					break
				}
			}
			if actualKey == "" {
				continue
			}
			// Build a probe URL with this param replaced by the canary
			nq := cloneValues(q)
			nq.Set(actualKey, openRedirectCanary)
			probe := *u
			probe.RawQuery = nq.Encode()
			key := probe.String() + "|" + actualKey
			if seen[key] {
				continue
			}
			seen[key] = true
			reqs = append(reqs, engine.Request{Method: "GET", URL: probe.String()})
			infos = append(infos, probeInfo{OriginalURL: raw, Param: actualKey})
		}
	}

	if len(reqs) == 0 {
		return nil
	}
	resps := eng.DoAll(ctx, reqs)

	var out []SecurityFinding
	for i, resp := range resps {
		if resp.Err != nil {
			continue
		}
		if resp.Status < 300 || resp.Status >= 400 {
			continue
		}
		loc := resp.Header.Get("Location")
		if loc == "" {
			loc = resp.RedirectTo
		}
		if !redirectsExternally(loc) {
			continue
		}
		out = append(out, SecurityFinding{
			Type:        "open-redirect",
			Severity:    "medium",
			URL:         infos[i].OriginalURL,
			Description: "parameter " + infos[i].Param + " is reflected into the Location header without validation — attacker-controlled external redirect",
			Evidence:    "Location: " + loc,
		})
	}
	return out
}

// redirectsExternally returns true when loc would send a browser to an
// attacker-controlled destination — either a canary absolute URL or a
// protocol-relative "//host/..." that browsers resolve as external.
func redirectsExternally(loc string) bool {
	if loc == "" {
		return false
	}
	trimmed := strings.TrimSpace(loc)
	// Protocol-relative // paths are external in a browser context.
	if strings.HasPrefix(trimmed, "//") && strings.Contains(trimmed, "example.org") {
		return true
	}
	u, err := url.Parse(trimmed)
	if err != nil || u.Host == "" {
		return false
	}
	return strings.Contains(strings.ToLower(u.Host), "example.org")
}

// cloneValues makes an independent copy of a url.Values so modifying it
// doesn't mutate the caller's parsed URL.
func cloneValues(src url.Values) url.Values {
	out := make(url.Values, len(src))
	for k, v := range src {
		cp := make([]string, len(v))
		copy(cp, v)
		out[k] = cp
	}
	return out
}
