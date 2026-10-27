// Package wordlist builds target-derived candidate word lists instead of
// relying solely on a static dictionary. It scrapes JS bundles, HTML,
// robots.txt and sitemap.xml for real path fragments and route strings —
// the same files katana crawls, but mined here for fuzzing candidates
// rather than just "found links".
package wordlist

import (
	"regexp"
	"sort"
	"strings"
)

// Seed is a small built-in set of high-value generic words, used as a
// baseline when no target-derived words are found or to supplement them.
// Kept intentionally short here — a real deployment would load SecLists;
// this is enough to demonstrate the merge/generation behavior.
var Seed = []string{
	"admin", "api", "backup", "config", "login", "test", "dev", "staging",
	"debug", "internal", "private", "old", "tmp", "upload", "uploads",
	"static", "assets", "dashboard", "console", "health", "status", "metrics",
	"actuator", "swagger", "swagger.json", "openapi.json", "graphql",
	".git/config", ".env", ".env.local", "robots.txt", "sitemap.xml",
	"package.json", "web.config", "server-status", ".well-known/security.txt",
}

// FrameworkPaths are probed opportunistically based on fingerprinted
// technology (see Fingerprint). Each advanced-tool differentiator: instead
// of fuzzing "/actuator" against a plain static site, we only add it when
// we have a real signal the target is running Spring, etc.
var FrameworkPaths = map[string][]string{
	"spring":    {"actuator", "actuator/health", "actuator/env", "actuator/beans", "actuator/mappings"},
	"laravel":   {"telescope", ".env", "storage/logs/laravel.log", "nova"},
	"django":    {"admin", "api/docs", "__debug__"},
	"express":   {"api", "node_modules/.package-lock.json"},
	"nextjs":    {"_next/static", "api/auth/session", "_next/data"},
	"wordpress": {"wp-admin", "wp-json/wp/v2/users", "wp-content/debug.log", "xmlrpc.php"},
}

// routeStringRe finds quoted strings that look like URL paths inside JS
// source: "/api/v1/users", '/admin/settings', etc. Deliberately permissive;
// false positives are cheap (they just become extra fuzz candidates), false
// negatives cost coverage.
var routeStringRe = regexp.MustCompile(`["'\x60](/[a-zA-Z0-9_\-./:]{2,80})["'\x60]`)

// identifierRe pulls bare path-like words from HTML comments / robots.txt /
// sitemap entries that may not be quoted JS strings.
var identifierRe = regexp.MustCompile(`(?m)^\s*(?:Disallow|Allow):\s*(/[a-zA-Z0-9_\-./]*)`)

// FromJS extracts candidate path fragments from one JS (or source-mapped)
// file's contents.
func FromJS(src []byte) []string {
	matches := routeStringRe.FindAllSubmatch(src, -1)
	out := make([]string, 0, len(matches))
	for _, m := range matches {
		p := string(m[1])
		if looksLikeRoute(p) {
			out = append(out, p)
		}
	}
	return out
}

// FromRobots extracts Disallow/Allow paths from a robots.txt body — these
// are a goldmine: the site owner is explicitly telling you what exists and
// wants hidden.
func FromRobots(body []byte) []string {
	matches := identifierRe.FindAllSubmatch(body, -1)
	out := make([]string, 0, len(matches))
	for _, m := range matches {
		out = append(out, string(m[1]))
	}
	return out
}

// looksLikeRoute filters out obvious non-route noise: mime types, image
// paths that are clearly static assets with hashes, overly long strings.
func looksLikeRoute(p string) bool {
	if len(p) < 2 || len(p) > 80 {
		return false
	}
	lower := strings.ToLower(p)
	for _, suf := range []string{".png", ".jpg", ".jpeg", ".gif", ".svg", ".woff", ".woff2", ".ttf", ".css", ".map"} {
		if strings.HasSuffix(lower, suf) {
			return false
		}
	}
	if strings.Contains(p, "..") {
		return false
	}
	return true
}

// PathToWords decomposes extracted route paths into standalone fuzz words,
// e.g. "/api/v1/internal-tools" -> ["api", "v1", "internal-tools"]. Both
// the full paths AND the decomposed segments are useful: full paths can be
// tried verbatim, segments feed into combinatorial guesses elsewhere.
func PathToWords(paths []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, p := range paths {
		for _, seg := range strings.Split(strings.Trim(p, "/"), "/") {
			seg = strings.TrimSpace(seg)
			if seg == "" || seen[seg] {
				continue
			}
			seen[seg] = true
			out = append(out, seg)
		}
	}
	sort.Strings(out)
	return out
}

// Fingerprint inspects response headers/body for lightweight technology
// signals. Returns framework keys matching FrameworkPaths.
func Fingerprint(headers map[string][]string, body []byte) []string {
	var hits []string
	check := func(name string, cond bool) {
		if cond {
			hits = append(hits, name)
		}
	}
	h := flattenHeaders(headers)
	b := strings.ToLower(string(body))

	check("spring", strings.Contains(h, "spring") || strings.Contains(b, "whitelabel error page"))
	check("laravel", strings.Contains(h, "laravel") || strings.Contains(b, "laravel"))
	check("django", strings.Contains(h, "django") || strings.Contains(b, "csrfmiddlewaretoken"))
	check("express", strings.Contains(h, "express"))
	check("nextjs", strings.Contains(b, "__next_data__") || strings.Contains(b, "/_next/"))
	check("wordpress", strings.Contains(b, "wp-content") || strings.Contains(b, "wp-json"))
	return hits
}

func flattenHeaders(h map[string][]string) string {
	var sb strings.Builder
	for k, vs := range h {
		sb.WriteString(strings.ToLower(k))
		sb.WriteByte(':')
		for _, v := range vs {
			sb.WriteString(strings.ToLower(v))
			sb.WriteByte(' ')
		}
	}
	return sb.String()
}

// Merge combines target-derived words with the seed list and any
// framework-specific paths, deduplicated and sorted for determinism.
func Merge(lists ...[]string) []string {
	seen := map[string]bool{}
	var out []string
	for _, l := range lists {
		for _, w := range l {
			w = strings.TrimSpace(w)
			if w == "" || seen[w] {
				continue
			}
			seen[w] = true
			out = append(out, w)
		}
	}
	sort.Strings(out)
	return out
}
