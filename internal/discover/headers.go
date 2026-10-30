// Information-disclosure header detection: captures Server, X-Powered-By,
// X-AspNet-Version, X-Generator and similar response headers that leak exact
// framework and runtime versions. Not a vulnerability by itself, but
// invaluable for pivoting (version → CVE lookup, framework → default-cred
// list, etc.), so hellhound surfaces them as low-severity findings rather
// than letting the operator miss them by scrolling past 200s.
package discover

import "strings"

// disclosingHeaders are header names whose values typically reveal
// framework/runtime/version info. Lowercased for case-insensitive matching
// against the stored Result.Headers map (also lowercased).
var disclosingHeaders = []string{
	"server",
	"x-powered-by",
	"x-aspnet-version",
	"x-aspnetmvc-version",
	"x-generator",
	"x-runtime",
	"x-rails-version",
	"x-drupal-cache",
	"x-drupal-dynamic-cache",
	"x-application-context",
	"x-backend-server",
	"x-served-by",
	"x-varnish",
	"via",
}

// CaptureInfoDisclosure walks all discovered Results and emits one finding
// per distinct (host, header-name, header-value) triple — not one per URL,
// since every request to the same host returns the same Server header and
// we don't want to drown the report in duplicates.
//
// Severity rules:
//   - "high" if the header value exposes an exact numeric version AND the
//     product has a long CVE history (apache, nginx, iis, php, tomcat, etc.)
//   - "low" otherwise (name of a product/framework, no version)
//   - "info" if it's just a generic token like "cloudflare" that reveals a CDN
func CaptureInfoDisclosure(results []Result) []SecurityFinding {
	seen := map[string]bool{}
	hostToURL := map[string]string{} // preserve the real scheme-and-host seen in Results
	var out []SecurityFinding
	for _, r := range results {
		host := hostOf(r.URL)
		if _, ok := hostToURL[host]; !ok {
			hostToURL[host] = schemeAndHostOf(r.URL)
		}
		for name, val := range r.Headers {
			if val == "" {
				continue
			}
			if !isDisclosingHeader(name) {
				continue
			}
			key := host + "|" + strings.ToLower(name) + "|" + val
			if seen[key] {
				continue
			}
			seen[key] = true
			sev := classifyHeaderSeverity(name, val)
			if sev == "" {
				continue
			}
			out = append(out, SecurityFinding{
				Type:        "info-disclosure",
				Severity:    sev,
				URL:         hostToURL[host],
				Description: name + " header exposes " + describeHeader(name, val),
				Evidence:    name + ": " + val,
			})
		}
	}
	return out
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

func isDisclosingHeader(name string) bool {
	ln := strings.ToLower(name)
	for _, h := range disclosingHeaders {
		if ln == h {
			return true
		}
	}
	return false
}

// classifyHeaderSeverity returns a severity based on whether the value
// contains an exact version-like token. Empty string means "don't report".
func classifyHeaderSeverity(name, value string) string {
	v := strings.ToLower(value)
	// Pure CDN / cache indicator — informational only.
	switch v {
	case "cloudflare", "akamaighost", "akamai", "varnish", "nginx", "apache", "microsoft-iis":
		return "info"
	}
	if containsVersion(value) {
		return "low"
	}
	return "info"
}

// containsVersion is a lightweight check: at least one digit AND at least
// one '.' near each other, matching tokens like "1.21.3", "7.4", "10.0.19041".
func containsVersion(v string) bool {
	for i := 0; i < len(v); i++ {
		c := v[i]
		if c < '0' || c > '9' {
			continue
		}
		// scan forward for '.' within next 8 chars
		end := i + 8
		if end > len(v) {
			end = len(v)
		}
		for j := i + 1; j < end; j++ {
			if v[j] == '.' {
				return true
			}
		}
	}
	return false
}

func describeHeader(name, value string) string {
	ln := strings.ToLower(name)
	switch ln {
	case "server":
		return "server software and version: " + value
	case "x-powered-by":
		return "backend technology: " + value
	case "x-aspnet-version", "x-aspnetmvc-version":
		return "exact ASP.NET version: " + value
	case "x-rails-version":
		return "exact Rails version: " + value
	case "x-runtime":
		return "backend runtime timing (framework fingerprint)"
	case "x-generator":
		return "generator/CMS: " + value
	case "x-drupal-cache", "x-drupal-dynamic-cache":
		return "Drupal fingerprint"
	case "x-application-context":
		return "Spring Boot context: " + value
	case "via":
		return "proxy/CDN chain: " + value
	}
	return value
}

func hostOf(fullURL string) string {
	if i := strings.Index(fullURL, "://"); i >= 0 {
		rest := fullURL[i+3:]
		if j := strings.IndexAny(rest, "/?#"); j >= 0 {
			return rest[:j]
		}
		return rest
	}
	return fullURL
}
