// Information-disclosure header detection: captures Server, X-Powered-By,
// X-AspNet-Version, X-Generator and similar response headers that leak exact
// framework and runtime versions. Not a vulnerability by itself, but
// invaluable for pivoting (version → CVE lookup, framework → default-cred
// list, etc.), so hellhound surfaces them as low-severity findings rather
// than letting the operator miss them by scrolling past 200s.
package discover

import (
	"net/http"
	"regexp"
	"strings"
)

// volatileHeaders carry a value that changes from response to response (a
// timing, a request id, whichever cache node answered). Their presence is
// worth one informational note per host; their value is not a version and
// must not be used as a dedupe key, or a 10,000-request scan reports the
// same header 10,000 times.
var volatileHeaders = map[string]bool{
	"X-Runtime":              true,
	"X-Varnish":              true,
	"X-Served-By":            true,
	"X-Backend-Server":       true,
	"X-Drupal-Cache":         true,
	"X-Drupal-Dynamic-Cache": true,
	"Via":                    true,
}

// CaptureInfoDisclosure walks all discovered Results and emits one finding
// per distinct (host, header, value) — or per (host, header) for volatile
// headers — never one per URL. Output order is deterministic: results in
// input order, headers in capturedHeaders order.
//
// Severity: "low" when a stable header carries an exact version number
// (feeds CVE lookup), "info" otherwise.
func CaptureInfoDisclosure(results []Result) []SecurityFinding {
	seen := map[string]bool{}
	var out []SecurityFinding
	for _, r := range results {
		if len(r.Headers) == 0 {
			continue
		}
		origin := schemeAndHostOf(r.URL)
		for _, name := range capturedHeaders {
			val := strings.TrimSpace(r.Headers[name])
			if val == "" {
				continue
			}
			key := origin + "|" + name + "|" + val
			if volatileHeaders[name] {
				key = origin + "|" + name
			}
			if seen[key] {
				continue
			}
			seen[key] = true
			if len(val) > 120 {
				val = val[:120]
			}
			out = append(out, SecurityFinding{
				Type:        "info-disclosure",
				Severity:    classifyHeaderSeverity(name, val),
				URL:         origin,
				Description: name + " header exposes " + describeHeader(name, val),
				Evidence:    name + ": " + val,
			})
		}
	}
	return out
}

// classifyHeaderSeverity returns "low" when a stable header's value carries
// an exact version number, "info" otherwise.
func classifyHeaderSeverity(name, value string) string {
	if volatileHeaders[http.CanonicalHeaderKey(name)] {
		return "info"
	}
	if containsVersion(value) {
		return "low"
	}
	return "info"
}

var versionRe = regexp.MustCompile(`\d+\.\d+`)

// containsVersion reports whether v carries a dotted version number such as
// "1.21.3", "7.4" or "10.0.19041".
func containsVersion(v string) bool {
	return versionRe.MatchString(v)
}

func describeHeader(name, value string) string {
	switch strings.ToLower(name) {
	case "server":
		return "server software: " + value
	case "x-powered-by":
		return "backend technology: " + value
	case "x-aspnet-version", "x-aspnetmvc-version":
		return "exact ASP.NET version: " + value
	case "x-rails-version":
		return "exact Rails version: " + value
	case "x-runtime":
		return "backend request timing (Rack/Rails-style framework fingerprint)"
	case "x-generator":
		return "generator/CMS: " + value
	case "x-drupal-cache", "x-drupal-dynamic-cache":
		return "a Drupal fingerprint"
	case "x-application-context":
		return "Spring Boot application context: " + value
	case "x-varnish":
		return "a Varnish cache in front of the application"
	case "x-served-by", "x-backend-server":
		return "internal server/cache node names"
	case "via":
		return "proxy/CDN chain: " + value
	}
	return value
}

// schemeAndHostOf returns "scheme://host" from a full URL, preserving the
// real scheme — the info-disclosure URL should match what the operator
// actually scanned (http vs https).
func schemeAndHostOf(fullURL string) string {
	if i := strings.Index(fullURL, "://"); i >= 0 {
		scheme := fullURL[:i]
		rest := fullURL[i+3:]
		if j := strings.IndexAny(rest, "/?#"); j >= 0 {
			return scheme + "://" + rest[:j]
		}
		return scheme + "://" + rest
	}
	return fullURL
}
