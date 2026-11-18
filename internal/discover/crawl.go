// Link crawling: follow real <a href>/src/action links from the target,
// same-origin, breadth-first, to reach pages that are LINKED but not
// guessable from any wordlist (a random slug, a numeric id, an internal
// report path). This is the one thing a pure wordlist fuzzer structurally
// cannot do — it's what katana exists for — so hellhound does it too,
// alongside its calibrated fuzzing rather than instead of it.
package discover

import (
	"context"
	"fmt"
	"hash/fnv"
	"html"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"sync"

	"github.com/securewithharshitrajput/hellhound/internal/engine"
)

// fnv64a is a cheap, non-cryptographic content fingerprint — good enough to
// recognise an exact-duplicate response body during one crawl run; it is
// never used for anything security-relevant.
func fnv64a(b []byte) uint64 {
	h := fnv.New64a()
	h.Write(b)
	return h.Sum64()
}

// linkAttrRe pulls URL-valued attributes (href, src, action) out of raw
// HTML. A regex rather than a full HTML parser keeps the project
// dependency-free and matches the existing extraction style (scriptSrcRe,
// the wordlist miner); for link DISCOVERY the occasional malformed match
// is harmless — it just gets scope-filtered and deduped away downstream.
var linkAttrRe = regexp.MustCompile(`(?i)(?:href|src|action|formaction|poster|cite|background|data|data-src|data-href|data-url|hx-get|hx-post|hx-put|hx-patch)\s*=\s*["']([^"'<>]+)["']`)

// CrawlResult is one URL reached by following real links, with the HTTP
// status it returned and the link-depth at which it was discovered.
// BodyPreview and Headers mirror discover.Result so Tier-A security phases
// (dir-listing, info-disclosure) can classify crawled pages uniformly.
type CrawlResult struct {
	URL         string
	Status      int
	Depth       int
	BodyPreview []byte
	Headers     map[string]string
}

// AsResults projects crawl results into the shared Result shape so one
// Tier-A pipeline can consume both fuzz and crawl discoveries.
func AsResults(crawl []CrawlResult) []Result {
	out := make([]Result, 0, len(crawl))
	for _, c := range crawl {
		out = append(out, Result{
			URL:         c.URL,
			Status:      c.Status,
			Depth:       c.Depth,
			BodyPreview: c.BodyPreview,
			Headers:     c.Headers,
		})
	}
	return out
}

// Crawl walks the target's link graph breadth-first, same-origin only, up
// to maxDepth hops from the start page and maxPages total fetched URLs
// (both hard bounds so a large or hostile site can't make this run
// forever). It returns every linked page it reached, excluding the start
// page itself.
func Crawl(ctx context.Context, eng *engine.Engine, target string, maxDepth, maxPages int) []CrawlResult {
	return CrawlWith(ctx, eng, target, maxDepth, maxPages, nil)
}

// Renderer returns the DOM of a page after its scripts have run.
type Renderer func(ctx context.Context, pageURL string) ([]byte, error)

// maxRenderParallel bounds how many browser instances run at once; each
// is a full browser process.
const maxRenderParallel = 3

// CrawlWith is Crawl with an optional Renderer. When render is non-nil,
// every HTML page that is fetched is also rendered, and links that only
// exist after its JavaScript has run are followed too — what makes
// single-page apps crawlable. The engine still fetches every page itself,
// so statuses, headers, scope rules and rate limits apply as usual; the
// renderer only contributes links. onRenderError, if non-nil, receives
// render failures (they never stop the crawl).
func CrawlWith(ctx context.Context, eng *engine.Engine, target string, maxDepth, maxPages int, render Renderer, onRenderError ...func(pageURL string, err error)) []CrawlResult {
	cfg := CrawlConfig{MaxDepth: maxDepth, MaxPages: maxPages, Render: render}
	if len(onRenderError) > 0 {
		cfg.OnRenderError = onRenderError[0]
	}
	results, _ := CrawlOpts(ctx, eng, target, cfg)
	return results
}

// CrawlConfig configures CrawlOpts.
type CrawlConfig struct {
	MaxDepth, MaxPages int
	Render             Renderer
	OnRenderError      func(pageURL string, err error)
	// MaxSimilar caps how many links sharing one URL pattern are followed
	// (0 = unlimited). A pattern replaces id-like path segments — long hex
	// strings, numbers, UUIDs — with {id} and ignores query values, so
	// "/products/6aec5b93a3abcba16ec33454" and every other product page are
	// one pattern. Following five of them shows the page; following all of
	// them only repeats it (and, with -render, starts a browser for each).
	MaxSimilar int
}

// CrawlStats reports what the crawl deliberately left out.
type CrawlStats struct {
	// Capped maps a URL pattern to the number of links matching it that
	// were not followed because of MaxSimilar.
	Capped map[string]int
	// Forms are the distinct forms seen on crawled pages (described, never
	// submitted).
	Forms []Form
}

// CrawlOpts is the full-featured crawl; Crawl and CrawlWith wrap it.
func CrawlOpts(ctx context.Context, eng *engine.Engine, target string, cfg CrawlConfig) ([]CrawlResult, CrawlStats) {
	maxDepth, maxPages, render := cfg.MaxDepth, cfg.MaxPages, cfg.Render
	stats := CrawlStats{}
	perPattern := map[string]int{}
	base, err := url.Parse(target)
	if err != nil || base.Host == "" {
		return nil, stats
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
	seenForms := map[string]bool{}
	seenAssetBody := map[string]bool{}
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

		// Render the pages worth parsing (2xx HTML, not at the depth limit),
		// a few at a time.
		rendered := make([][]byte, len(resps))
		if render != nil {
			sem := make(chan struct{}, maxRenderParallel)
			var wg sync.WaitGroup
			for i, resp := range resps {
				if ctx.Err() != nil || frontier[i].depth >= maxDepth || !isParsableHTML(resp) {
					continue
				}
				wg.Add(1)
				sem <- struct{}{}
				go func(i int, pageURL string) {
					defer wg.Done()
					defer func() { <-sem }()
					dom, err := render(ctx, pageURL)
					if err != nil {
						if cfg.OnRenderError != nil && ctx.Err() == nil {
							cfg.OnRenderError(pageURL, err)
						}
						return
					}
					rendered[i] = dom
				}(i, frontier[i].u.String())
			}
			wg.Wait()
		}

		var next []item
		for i, resp := range resps {
			it := frontier[i]
			if resp.Err != nil {
				continue
			}
			// A dead link is not a discovery: 404/410 are followed no
			// further and not reported.
			if resp.Status == 404 || resp.Status == 410 {
				continue
			}
			// Some dev servers (confirmed live against Juice Shop) serve the
			// SAME static asset body for any nested path that happens to end
			// in that filename: /main.js, /address/main.js and
			// /address/edit/main.js all return byte-identical JS. Each such
			// path is "discovered" by the previous page's own relative
			// <script src="main.js">, so without this check the crawl keeps
			// re-finding, re-reporting and re-scraping the same bundle under
			// one new path per directory depth — noise, not new pages, and
			// wasted requests scraping the same JS for endpoints over and
			// over. A byte-identical body under a static-asset extension is
			// reported and processed only the first time it is seen.
			if IsStaticAsset(it.u.Path) && len(resp.Body) > 0 {
				key := fmt.Sprintf("%d:%x", len(resp.Body), fnv64a(resp.Body))
				if seenAssetBody[key] {
					continue
				}
				seenAssetBody[key] = true
			}
			if it.depth > 0 { // never report the start page as a "finding"
				results = append(results, CrawlResult{
					URL:         it.u.String(),
					Status:      resp.Status,
					Depth:       it.depth,
					BodyPreview: previewOf(resp.Body, resp.Header.Get("Content-Type")),
					Headers:     captureHeaders(resp.Header),
				})
			}
			if it.depth >= maxDepth {
				continue
			}
			// Where this response points. A redirect target is itself a
			// discovery (a login page, a canonical URL); HTML contributes its
			// links, forms and inline-script endpoints; JavaScript and CSS
			// contribute the endpoints written in them; headers (Link,
			// Refresh, Content-Location) contribute the rest. Error pages and
			// binary bodies contribute nothing.
			var raws []string
			switch {
			case resp.Status >= 300 && resp.Status < 400:
				if resp.RedirectTo != "" {
					raws = append(raws, resp.RedirectTo)
				}
			case resp.Status >= 200 && resp.Status < 300:
				ct := strings.ToLower(resp.Header.Get("Content-Type"))
				lowerPath := strings.ToLower(it.u.Path)
				switch {
				case ct == "" || strings.Contains(ct, "html"):
					rel := it.u // what relative links resolve against
					if b := baseHref(resp.Body); b != "" {
						if bu, err := it.u.Parse(b); err == nil {
							rel = bu
						}
					}
					var links []string
					links = append(links, extractLinks(resp.Body)...)
					links = append(links, extractLinks(rendered[i])...)
					links = append(links, srcsetLinks(resp.Body)...)
					links = append(links, metaRefreshLinks(resp.Body)...)
					for _, raw := range links {
						if abs := absoluteAgainst(rel, raw); abs != "" {
							raws = append(raws, abs)
						}
					}
					raws = append(raws, inlineScriptEndpoints(resp.Body)...)
					for _, src := range [][]byte{resp.Body, rendered[i]} {
						for _, f := range ExtractForms(src, it.u) {
							if k := formKey(f); !seenForms[k] {
								seenForms[k] = true
								stats.Forms = append(stats.Forms, f)
								raws = append(raws, f.Action)
							}
						}
					}
				case strings.Contains(ct, "javascript") || strings.HasSuffix(lowerPath, ".js") || strings.HasSuffix(lowerPath, ".mjs"):
					raws = append(raws, jsEndpoints(resp.Body)...)
				}
				raws = append(raws, headerLinks(resp.Header)...)
			}
			for _, raw := range raws {
				abs := resolveInScope(it.u, raw, base.Host)
				if abs == nil {
					continue
				}
				key := canonicalURL(abs)
				if seen[key] {
					continue
				}
				seen[key] = true
				if cfg.MaxSimilar > 0 {
					pat := URLPattern(abs)
					if perPattern[pat] >= cfg.MaxSimilar {
						if stats.Capped == nil {
							stats.Capped = map[string]int{}
						}
						stats.Capped[pat]++
						continue
					}
					perPattern[pat]++
				}
				next = append(next, item{u: abs, depth: it.depth + 1})
			}
		}
		frontier = next
	}
	return results, stats
}

// URLPattern returns the path of u with id-like segments replaced by {id},
// followed by the sorted names of its query parameters.
func URLPattern(u *url.URL) string {
	segs := strings.Split(u.Path, "/")
	for i, sg := range segs {
		if isIDSegment(sg) {
			segs[i] = "{id}"
		} else if isSlugID(sg) {
			segs[i] = "{slug}-{id}"
		}
	}
	p := strings.Join(segs, "/")
	if p == "" {
		p = "/"
	}
	q := u.Query()
	if len(q) == 0 {
		return p
	}
	names := make([]string, 0, len(q))
	for k := range q {
		names = append(names, k)
	}
	sort.Strings(names)
	return p + "?" + strings.Join(names, "&")
}

// isIDSegment reports whether a path segment looks like an identifier
// rather than a word: all digits (record numbers, timestamps), a UUID, a
// date, or a hex string of 8+ characters containing a digit (MongoDB
// ObjectIDs, hashes). The digit requirement keeps a plain English word
// that happens to be spelled with a-f only from being taken for a hash.
func isIDSegment(s string) bool {
	if s == "" {
		return false
	}
	digits, hex, hasDigit := true, len(s) >= 8, false
	for i := 0; i < len(s); i++ {
		c := s[i]
		isD := c >= '0' && c <= '9'
		isH := isD || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
		if isD {
			hasDigit = true
		} else {
			digits = false
		}
		if !isH {
			hex = false
		}
	}
	if digits || (hex && hasDigit) {
		return true
	}
	// 8-4-4-4-12 UUID
	if len(s) == 36 && s[8] == '-' && s[13] == '-' && s[18] == '-' && s[23] == '-' {
		return isIDSegment(strings.ReplaceAll(s, "-", ""))
	}
	// 2026-11-18
	if len(s) == 10 && s[4] == '-' && s[7] == '-' && isIDSegment(s[:4]) && isIDSegment(s[5:7]) && isIDSegment(s[8:]) {
		return true
	}
	return false
}

// isSlugID reports whether a segment is a readable slug ending in an id:
// "Complete-Data-Science-6aac2df9c0c67432264be265", "post-12345". Sites
// build these from a title plus a database id, so every item of a catalogue
// has a different segment but is one kind of page.
func isSlugID(s string) bool {
	i := strings.LastIndexByte(s, '-')
	if i <= 0 || i == len(s)-1 {
		return false
	}
	tail := s[i+1:]
	if len(tail) < 4 && !isAllDigits(tail) {
		return false
	}
	return isIDSegment(tail) && (len(tail) >= 4)
}

func isAllDigits(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return s != ""
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
	if len(abs.Path)+len(abs.RawQuery) > maxLinkLen || endsSession(abs.Path) {
		return nil
	}
	if abs.Scheme != "http" && abs.Scheme != "https" {
		return nil
	}
	return abs
}

// maxLinkLen bounds the path+query of a link worth following; longer ones
// are generated junk (or an attempt to make the crawler misbehave).
const maxLinkLen = 2048

// endsSession reports whether following path would log the scanning
// identity out — fatal for an authenticated crawl (-H "Cookie: ..."), since
// every later request would see the logged-out site.
func endsSession(path string) bool {
	seg := strings.ToLower(lastSeg(path))
	for _, w := range []string{"logout", "log-out", "log_out", "signout", "sign-out", "sign_out", "logoff", "log-off"} {
		if strings.HasPrefix(seg, w) {
			return true
		}
	}
	return false
}

// canonicalURL is the dedupe key: scheme+host+path plus the sorted NAMES of
// the query parameters, no fragment. Parameter values are left out so a
// session id, cache-buster or page counter that changes on every link
// ("/a?sid=1", "/a?sid=2", ...) is one page, not an endless supply of new
// ones; a link with a different parameter set is still visited.
func canonicalURL(u *url.URL) string {
	// "/about" and "/about/" are one page on practically every site (one
	// redirects to the other), so both spellings share a key; otherwise a
	// site linking both ways lists every page twice.
	path := strings.TrimRight(u.Path, "/")
	if path == "" {
		path = "/" // "http://host" and "http://host/" are the same page
	}
	q := u.Query()
	names := make([]string, 0, len(q))
	for k := range q {
		names = append(names, k)
	}
	sort.Strings(names)
	return u.Scheme + "://" + u.Host + path + "?" + strings.Join(names, "&")
}

// extractLinks returns the raw href/src/action values from an HTML body,
// skipping non-navigable schemes (data:, javascript:, mailto:, tel:).
func extractLinks(body []byte) []string {
	matches := linkAttrRe.FindAllSubmatch(body, -1)
	out := make([]string, 0, len(matches))
	for _, m := range matches {
		// Attribute values are HTML: "&amp;" in an href means "&". Left
		// encoded, a link like "/img?url=a&amp;w=64" is requested with a
		// mangled query and the server rightly answers 400.
		s := strings.TrimSpace(html.UnescapeString(string(m[1])))
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

// WordsFromCrawl turns crawl results into fuzz-word candidates: every path
// SEGMENT of every discovered URL (e.g. "/api/v2/billing-export" ->
// "api", "v2", "billing-export"), deduplicated. This is the crawl->fuzz
// feedback loop — a path the crawler found by following a real link (an
// unguessable slug, a real API version, an internal section name) becomes
// a word the fuzzer then tries in EVERY directory, so the two phases
// reinforce each other instead of running blind to one another. File-like
// final segments (anything with a ".") are skipped: "app.js" is a leaf
// asset, not a useful fuzz word, and its stem rarely generalizes.
func WordsFromCrawl(results []CrawlResult) []string {
	seen := map[string]bool{}
	var out []string
	for _, r := range results {
		u, err := url.Parse(r.URL)
		if err != nil {
			continue
		}
		for _, seg := range strings.Split(strings.Trim(u.Path, "/"), "/") {
			seg = strings.TrimSpace(seg)
			if seg == "" || len(seg) > 64 || strings.Contains(seg, ".") || seen[seg] {
				continue
			}
			seen[seg] = true
			out = append(out, seg)
		}
	}
	return out
}

// isParsableHTML reports whether resp is a successful HTML page — the only
// kind worth parsing (or rendering) for links.
func isParsableHTML(resp engine.Response) bool {
	if resp.Err != nil || resp.Status < 200 || resp.Status >= 300 {
		return false
	}
	ct := strings.ToLower(resp.Header.Get("Content-Type"))
	return ct == "" || strings.Contains(ct, "html")
}
