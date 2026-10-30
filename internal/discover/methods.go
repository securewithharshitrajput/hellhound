// Dangerous HTTP method detection: for every endpoint we already discovered,
// send an OPTIONS request and parse its Allow header. If PUT, DELETE, PATCH,
// or TRACE show up, that's a real misconfig — most app authors enforce auth
// only on GET/POST and the extra verbs let an attacker upload or delete
// without any surface a browser would ever hit. TRACE is useful for XST
// (Cross-Site Tracing) attacks that leak auth cookies even with HttpOnly.
//
// Only runs against endpoints hellhound already classified as interesting:
// probing every 404 would waste requests, and the server's auth posture on a
// path it doesn't serve isn't meaningful.
package discover

import (
	"context"
	"strings"

	"github.com/securewithharshitrajput/hellhound/internal/engine"
)

// dangerousMethods are verbs whose presence on the Allow header deserves a
// finding. GET/HEAD/POST/OPTIONS are expected and not flagged.
var dangerousMethods = []string{"PUT", "DELETE", "PATCH", "TRACE"}

// ScanDangerousMethods sends OPTIONS to each discovered endpoint and reports
// those whose Allow header advertises PUT/DELETE/PATCH/TRACE. Deduplicated
// by URL so repeated findings in the same cluster don't produce duplicate
// method advisories.
func ScanDangerousMethods(ctx context.Context, eng *engine.Engine, urls []string) []SecurityFinding {
	seen := map[string]bool{}
	unique := make([]string, 0, len(urls))
	for _, u := range urls {
		if u == "" || seen[u] {
			continue
		}
		seen[u] = true
		unique = append(unique, u)
	}

	reqs := make([]engine.Request, len(unique))
	for i, u := range unique {
		reqs[i] = engine.Request{Method: "OPTIONS", URL: u}
	}
	resps := eng.DoAll(ctx, reqs)

	var out []SecurityFinding
	for i, resp := range resps {
		if resp.Err != nil || resp.Status == 0 {
			continue
		}
		// Pull Allow header (sometimes split across values, sometimes a
		// single comma-separated value). Also accept the misspelled "Allowed"
		// some frameworks emit.
		allowValues := append([]string{}, resp.Header.Values("Allow")...)
		allowValues = append(allowValues, resp.Header.Values("Allowed")...)
		if len(allowValues) == 0 {
			continue
		}
		allowed := parseAllowHeader(strings.Join(allowValues, ","))
		var found []string
		for _, m := range dangerousMethods {
			if allowed[m] {
				found = append(found, m)
			}
		}
		if len(found) == 0 {
			continue
		}
		sev := "medium"
		// TRACE alone is lower severity (XST only); PUT/DELETE/PATCH on an
		// unauth endpoint is likely critical, but we can't verify auth here,
		// so medium is the honest ceiling without an auth probe.
		if len(found) == 1 && found[0] == "TRACE" {
			sev = "low"
		}
		out = append(out, SecurityFinding{
			Type:        "dangerous-methods",
			Severity:    sev,
			URL:         unique[i],
			Description: "server advertises " + strings.Join(found, ", ") + " via OPTIONS Allow header",
			Evidence:    strings.Join(allowValues, ", "),
		})
	}
	return out
}

// parseAllowHeader splits an Allow header value ("GET, POST, PUT") into an
// uppercased method set.
func parseAllowHeader(v string) map[string]bool {
	out := map[string]bool{}
	for _, part := range strings.Split(v, ",") {
		m := strings.ToUpper(strings.TrimSpace(part))
		if m != "" {
			out[m] = true
		}
	}
	return out
}
