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

	"github.com/securewithharshitrajput/hellhound/internal/analyze"
	"github.com/securewithharshitrajput/hellhound/internal/engine"
)

// dangerousMethods are verbs whose presence on the Allow header deserves a
// finding. GET/HEAD/POST/OPTIONS are expected and not flagged.
var dangerousMethods = []string{"PUT", "DELETE", "PATCH", "TRACE"}

// ScanDangerousMethods sends OPTIONS to each discovered endpoint and reports
// those whose Allow header advertises PUT/DELETE/PATCH/TRACE.
//
// Many servers and frameworks answer OPTIONS with one blanket Allow header
// for every path, existing or not. Reporting that once per URL would bury
// the report, so each origin is also probed at a random nonexistent path:
// when that baseline already advertises dangerous methods, a single
// origin-wide finding is emitted and only endpoints whose method set
// differs from the baseline are reported individually.
func ScanDangerousMethods(ctx context.Context, eng *engine.Engine, urls []string) []SecurityFinding {
	seen := map[string]bool{}
	unique := make([]string, 0, len(urls))
	var origins []string
	originSeen := map[string]bool{}
	for _, u := range urls {
		if u == "" || seen[u] {
			continue
		}
		seen[u] = true
		unique = append(unique, u)
		if o := schemeAndHostOf(u); !originSeen[o] {
			originSeen[o] = true
			origins = append(origins, o)
		}
	}
	if len(unique) == 0 {
		return nil
	}

	reqs := make([]engine.Request, 0, len(unique)+len(origins))
	for _, u := range unique {
		reqs = append(reqs, engine.Request{Method: "OPTIONS", URL: u})
	}
	for _, o := range origins {
		reqs = append(reqs, engine.Request{Method: "OPTIONS", URL: o + "/" + analyze.RandomToken()})
	}
	resps := eng.DoAll(ctx, reqs)
	if len(resps) != len(reqs) {
		return nil
	}

	var out []SecurityFinding
	baseline := map[string]string{} // origin -> dangerous set advertised for a nonexistent path
	for i, o := range origins {
		found, raw := dangerousFromResponse(resps[len(unique)+i])
		if len(found) == 0 {
			continue
		}
		baseline[o] = strings.Join(found, ", ")
		out = append(out, SecurityFinding{
			Type:        "dangerous-methods",
			Severity:    "low",
			URL:         o,
			Description: "server advertises " + baseline[o] + " via OPTIONS for every path, including nonexistent ones — a blanket Allow header; confirm against a real endpoint before treating the methods as usable",
			Evidence:    raw,
		})
	}

	for i, resp := range resps[:len(unique)] {
		found, raw := dangerousFromResponse(resp)
		if len(found) == 0 {
			continue
		}
		set := strings.Join(found, ", ")
		if baseline[schemeAndHostOf(unique[i])] == set {
			continue // same as the origin-wide answer, already reported once
		}
		sev := "medium"
		// TRACE alone is lower severity (XST only); PUT/DELETE/PATCH may be
		// an unauthenticated write path, but auth is not verified here, so
		// medium is the honest ceiling.
		if set == "TRACE" {
			sev = "low"
		}
		out = append(out, SecurityFinding{
			Type:        "dangerous-methods",
			Severity:    sev,
			URL:         unique[i],
			Description: "server advertises " + set + " via OPTIONS Allow header",
			Evidence:    raw,
		})
	}
	return out
}

// dangerousFromResponse extracts the dangerous methods an OPTIONS response
// advertises (in dangerousMethods order) and the raw Allow value.
func dangerousFromResponse(resp engine.Response) ([]string, string) {
	if resp.Err != nil || resp.Status == 0 || resp.Header == nil {
		return nil, ""
	}
	// Some frameworks emit the misspelled "Allowed".
	allowValues := append([]string{}, resp.Header.Values("Allow")...)
	allowValues = append(allowValues, resp.Header.Values("Allowed")...)
	if len(allowValues) == 0 {
		return nil, ""
	}
	raw := strings.Join(allowValues, ", ")
	allowed := parseAllowHeader(raw)
	var found []string
	for _, m := range dangerousMethods {
		if allowed[m] {
			found = append(found, m)
		}
	}
	return found, raw
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
