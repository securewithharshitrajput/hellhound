// Link crawling: follow real <a href>/src/action links from the target,
// same-origin, breadth-first, to reach pages that are LINKED but not
// guessable from any wordlist (a random slug, a numeric id, an internal
// report path). This is the one thing a pure wordlist fuzzer structurally
// cannot do — it's what katana exists for — so hellhound does it too,
// alongside its calibrated fuzzing rather than instead of it.
package discover

import (
	"context"
	"net/url"
	"regexp"
	"strings"

	"github.com/securewithharshitrajput/hellhound/internal/engine"
)

// linkAttrRe pulls URL-valued attributes (href, src, action) out of raw
// HTML. A regex rather than a full HTML parser keeps the project
// dependency-free and matches the existing extraction style (scriptSrcRe,
// the wordlist miner); for link DISCOVERY the occasional malformed match
// is harmless — it just gets scope-filtered and deduped away downstream.
var linkAttrRe = regexp.MustCompile(`(?i)(?:href|src|action)\s*=\s*["']([^"'<>]+)["']`)

// CrawlResult is one URL reached by following real links, with the HTTP
// status it returned and the link-depth at which it was discovered.
type CrawlResult struct {
	URL    string
	Status int
	Depth  int
}

// Crawl walks the target's link graph breadth-first, same-origin only, up
// to maxDepth hops from the start page and maxPages total fetched URLs
// (both hard bounds so a large or hostile site can't make this run
// forever). It returns every linked page it reached, excluding the start
// page itself.
func Crawl(ctx context.Context, eng *engine.Engine, target string, maxDepth, maxPages int) []CrawlResult {
	base, err := url.Parse(target)
	if err != nil || base.Host == "" {
		return nil
	}
	if maxDepth < 1 {
		maxDepth = 1
	}
	if maxPages < 1 {
		maxPages = 1
	}

	type item struct {
		u     *url.URL
		depth int
	}
	seen := map[string]bool{}
	var results []CrawlResult

	start := *base
	start.Fragment = ""
	seen[canonicalURL(&start)] = true
	frontier := []item{{u: &start, depth: 0}}

	for len(frontier) > 0 && len(results) < maxPages {
		reqs := make([]engine.Request, len(frontier))
		for i, it := range frontier {
			reqs[i] = engine.Request{Method: "GET", URL: it.u.String()}
		}
		resps := eng.DoAll(ctx, reqs)

		var next []item
		for i, resp := range resps {
			it := frontier[i]
			if resp.Err != nil {
				continue
			}
			if it.depth > 0 { // never report the start page as a "finding"
				results = append(results, CrawlResult{URL: it.u.String(), Status: resp.Status, Depth: it.depth})
			}
			if it.depth >= maxDepth {
				continue
			}
			// Only parse genuine 2xx HTML for more links — a redirect,
			// error, or non-HTML asset has no navigable links worth
			// following (and parsing a binary body for "href=" is noise).
			if resp.Status < 200 || resp.Status >= 300 {
				continue
			}
			if ct := strings.ToLower(resp.Header.Get("Content-Type")); ct != "" && !strings.Contains(ct, "html") {
				continue
			}
			for _, raw := range extractLinks(resp.Body) {
				abs := resolveInScope(it.u, raw, base.Host)
				if abs == nil {
					continue
				}
				key := canonicalURL(abs)
				if seen[key] {
					continue
				}
				seen[key] = true
				next = append(next, item{u: abs, depth: it.depth + 1})
			}
		}
		frontier = next
	}
	return results
}

// resolveInScope resolves a raw href/src value against the page it was
// found on and returns it only if it stays on the target host and uses
// http(s); otherwise nil. Fragments are dropped so "/x" and "/x#section"
// aren't crawled as two pages.
func resolveInScope(page *url.URL, raw, host string) *url.URL {
	ref, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return nil
	}
	abs := page.ResolveReference(ref)
	abs.Fragment = ""
	if abs.Host != host {
		return nil
	}
	if abs.Scheme != "http" && abs.Scheme != "https" {
		return nil
	}
	return abs
}

// canonicalURL is the dedupe key: scheme+host+path+query, no fragment. Query
// is kept so distinct query-driven pages are each visited, bounded by
// maxPages.
func canonicalURL(u *url.URL) string {
	return u.Scheme + "://" + u.Host + u.Path + "?" + u.RawQuery
}

// extractLinks returns the raw href/src/action values from an HTML body,
// skipping non-navigable schemes (data:, javascript:, mailto:, tel:).
func extractLinks(body []byte) []string {
	matches := linkAttrRe.FindAllSubmatch(body, -1)
	out := make([]string, 0, len(matches))
	for _, m := range matches {
		s := strings.TrimSpace(string(m[1]))
		if s == "" {
			continue
		}
		lower := strings.ToLower(s)
		if strings.HasPrefix(lower, "data:") || strings.HasPrefix(lower, "javascript:") ||
			strings.HasPrefix(lower, "mailto:") || strings.HasPrefix(lower, "tel:") {
			continue
		}
		out = append(out, s)
	}
	return out
}
