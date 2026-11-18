// Target-derived wordlist assembly: fetches robots.txt and the homepage
// (plus same-origin JS it links to), mines them via internal/wordlist, and
// fingerprints the tech stack to add framework-specific paths. This is the
// piece that was built (internal/wordlist's FromJS/FromRobots/Fingerprint)
// but never actually wired into a run — an earlier version of this CLI only
// ever used the static seed list, silently skipping the whole
// "learn from the target" step it was supposed to demonstrate.
package discover

import (
	"context"
	"errors"
	"fmt"
	"net"
	"regexp"
	"strings"

	"bytes"
	"compress/gzip"
	"github.com/securewithharshitrajput/hellhound/internal/engine"
	"github.com/securewithharshitrajput/hellhound/internal/wordlist"
	"html"
	"io"
	"net/url"
)

var scriptSrcRe = regexp.MustCompile(`<script[^>]+src=["']([^"']+)["']`)

// maxJSFiles caps how many same-origin scripts we fetch and mine per run,
// so a page with dozens of bundles doesn't turn wordlist-building into a
// scan of its own.
const maxJSFiles = 8

// BuildWordlist extends seed with words mined directly from the target.
// This is the thing ffuf/katana don't do: both require you to supply (or
// separately crawl for) every candidate word. Here, one request to
// robots.txt and the homepage can hand back real route fragments and an
// explicit "please don't look here" list from the target itself, before a
// single fuzz request is sent.
//
// robots.txt and the homepage are fetched CONCURRENTLY (via DoAll), not
// sequentially — found against a real slow/rate-limited target (Vercel's
// bot-mitigation challenge page stalling requests): a sequential version
// took 2x the configured timeout just to fail this step, before
// calibration or fuzzing even started. Same fix as the API-probing phase
// got earlier; this phase had the identical bug and was never caught
// until a real target surfaced it.
func BuildWordlist(ctx context.Context, eng *engine.Engine, baseURL string, seed []string) []string {
	words, _ := BuildWordlistStats(ctx, eng, baseURL, seed)
	return words
}

// MineStats reports how mining went: which sources could not be read (so a
// thin wordlist is explained rather than silent) and the page paths the
// target's own sitemap lists (pages it already publishes, not discoveries).
type MineStats struct {
	Failed       []string // e.g. "homepage (403)", "robots.txt (timeout)"
	SitemapPaths []string
	// HomeLinks are the same-site paths the homepage itself links to: pages
	// the site publishes, so finding them by guessing is not a discovery.
	HomeLinks []string
}

// BuildWordlistStats is BuildWordlist plus a report of what it could read.
func BuildWordlistStats(ctx context.Context, eng *engine.Engine, baseURL string, seed []string) ([]string, MineStats) {
	var mined []string
	var st MineStats

	first := eng.DoAll(ctx, []engine.Request{
		{Method: "GET", URL: baseURL + "/robots.txt"},
		{Method: "GET", URL: baseURL + "/"},
		{Method: "GET", URL: baseURL + "/sitemap.xml"},
	})
	robots, home, sitemap := first[0], first[1], first[2]
	// robots.txt and sitemap.xml are optional: a 404 is normal. Errors,
	// and a homepage that does not answer 2xx/3xx, mean the target refused
	// or failed the request and mining saw less than the site has.
	if robots.Err != nil {
		st.Failed = append(st.Failed, "robots.txt ("+shortErr(robots.Err)+")")
	} else if blockStatuses[robots.Status] {
		st.Failed = append(st.Failed, fmt.Sprintf("robots.txt (%d)", robots.Status))
	}
	if sitemap.Err != nil {
		st.Failed = append(st.Failed, "sitemap.xml ("+shortErr(sitemap.Err)+")")
	} else if blockStatuses[sitemap.Status] {
		st.Failed = append(st.Failed, fmt.Sprintf("sitemap.xml (%d)", sitemap.Status))
	}

	// The sitemap is the target's own list of its pages: every path in it
	// is a real one, and its segments are exactly the vocabulary this site
	// uses. robots.txt may point at further sitemaps.
	var robotsBody []byte
	if robots.Err == nil && robots.Status == 200 {
		robotsBody = robots.Body
	}
	st.SitemapPaths = sitemapPaths(ctx, eng, baseURL, sitemap, robotsBody)
	for _, p := range st.SitemapPaths {
		if w := strings.Trim(p, "/"); w != "" && len(w) <= 200 {
			mined = append(mined, w)
		}
		mined = append(mined, wordlist.PathToWords([]string{p})...)
	}

	if robots.Err == nil && robots.Status == 200 {
		paths := wordlist.FromRobots(robots.Body)
		mined = append(mined, wordlist.PathToWords(paths)...)
		for _, p := range paths { // also keep full paths verbatim, not just decomposed fragments
			if w := strings.Trim(p, "/"); w != "" {
				mined = append(mined, w)
			}
		}
	}

	if home.Err != nil {
		st.Failed = append(st.Failed, "homepage ("+shortErr(home.Err)+")")
		return wordlist.Merge(seed, mined), st
	}
	if home.Status >= 400 {
		// A block or error page has no links of the site in it; mining it
		// only adds the firewall's words.
		st.Failed = append(st.Failed, fmt.Sprintf("homepage (%d)", home.Status))
		return wordlist.Merge(seed, mined), st
	}

	if base, err := url.Parse(baseURL + "/"); err == nil {
		seenLink := map[string]bool{}
		for _, raw := range extractLinks(home.Body) {
			if abs := resolveInScope(base, raw, base.Host); abs != nil && abs.Path != "" && abs.Path != "/" && !seenLink[abs.Path] {
				seenLink[abs.Path] = true
				st.HomeLinks = append(st.HomeLinks, abs.Path)
			}
		}
	}

	mined = append(mined, wordlist.PathToWords(wordlist.FromJS(home.Body))...)

	for _, fp := range wordlist.Fingerprint(home.Header, home.Body) {
		mined = append(mined, wordlist.FrameworkPaths[fp]...)
	}

	srcs := scriptSrcs(home.Body)
	if len(srcs) > maxJSFiles {
		srcs = srcs[:maxJSFiles]
	}
	// Same reasoning as above: up to maxJSFiles requests, previously fired
	// one at a time — against a slow target that's maxJSFiles * timeout
	// instead of roughly one timeout, total.
	jsReqs := make([]engine.Request, 0, len(srcs))
	for _, src := range srcs {
		if jsURL := resolveScriptURL(baseURL, src); jsURL != "" {
			jsReqs = append(jsReqs, engine.Request{Method: "GET", URL: jsURL})
		}
	}
	jsFailed := 0
	for _, js := range eng.DoAll(ctx, jsReqs) {
		if js.Err == nil && js.Status == 200 {
			mined = append(mined, wordlist.PathToWords(wordlist.FromJS(js.Body))...)
		} else {
			jsFailed++
		}
	}
	if jsFailed > 0 {
		st.Failed = append(st.Failed, fmt.Sprintf("%d of %d linked script(s)", jsFailed, len(jsReqs)))
	}

	return wordlist.Merge(seed, mined), st
}

// shortErr names a request failure in a word or two.
func shortErr(err error) string {
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return "timeout"
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return "stopped"
	}
	return "no answer"
}

func scriptSrcs(body []byte) []string {
	matches := scriptSrcRe.FindAllSubmatch(body, -1)
	out := make([]string, 0, len(matches))
	for _, m := range matches {
		out = append(out, string(m[1]))
	}
	return out
}

// resolveScriptURL returns the absolute URL to fetch for a <script src="...">
// value, or "" to skip it. Cross-origin scripts (CDN-hosted libraries,
// protocol-relative URLs) are deliberately skipped: they aren't part of the
// target and mining them would pull in words from jQuery or React rather
// than the application under test. Page-relative paths (no leading "/")
// are also skipped rather than guessed at, since resolving them correctly
// would require knowing the exact page path, not just the origin.
func resolveScriptURL(baseURL, src string) string {
	switch {
	case strings.HasPrefix(src, "//"):
		return ""
	case strings.HasPrefix(src, "http://"), strings.HasPrefix(src, "https://"):
		if strings.HasPrefix(src, baseURL) {
			return src
		}
		return ""
	case strings.HasPrefix(src, "/"):
		return baseURL + src
	default:
		return ""
	}
}

const (
	maxSitemapFiles = 6       // sitemap documents fetched per run (index children included)
	maxSitemapPaths = 5000    // paths taken from sitemaps in total
	maxSitemapBytes = 4 << 20 // decompressed size cap per sitemap
)

var (
	sitemapLocRe    = regexp.MustCompile(`(?is)<loc>\s*(?:<!\[CDATA\[)?\s*([^<\]\s]+)`)
	robotsSitemapRe = regexp.MustCompile(`(?im)^\s*sitemap\s*:\s*(\S+)`)
)

// sitemapPaths returns the same-host paths listed in the target's sitemaps:
// /sitemap.xml (already fetched as first), any "Sitemap:" lines in
// robots.txt, and one level of sitemap-index children. Everything is
// bounded: files, paths and bytes.
func sitemapPaths(ctx context.Context, eng *engine.Engine, baseURL string, first engine.Response, robotsBody []byte) []string {
	base, err := url.Parse(baseURL)
	if err != nil {
		return nil
	}
	seenFile := map[string]bool{baseURL + "/sitemap.xml": true}
	var queue []string
	enqueue := func(raw string) {
		u, err := base.Parse(strings.TrimSpace(html.UnescapeString(raw)))
		if err != nil || u.Host != base.Host || (u.Scheme != "http" && u.Scheme != "https") {
			return
		}
		if s := u.String(); !seenFile[s] {
			seenFile[s] = true
			queue = append(queue, s)
		}
	}
	for _, m := range robotsSitemapRe.FindAllSubmatch(robotsBody, 20) {
		enqueue(string(m[1]))
	}

	seenPath := map[string]bool{}
	var paths []string
	fetched := 0
	process := func(resp engine.Response) {
		fetched++
		if resp.Err != nil || resp.Status != 200 {
			return
		}
		body := gunzipIfNeeded(resp.Body)
		isIndex := bytes.Contains(bytes.ToLower(body[:min(len(body), 2048)]), []byte("<sitemapindex"))
		for _, m := range sitemapLocRe.FindAllSubmatch(body, maxSitemapPaths) {
			loc := html.UnescapeString(string(m[1]))
			if isIndex {
				enqueue(loc)
				continue
			}
			u, err := base.Parse(loc)
			if err != nil || u.Host != base.Host || u.Path == "" || u.Path == "/" {
				continue
			}
			if !seenPath[u.Path] && len(paths) < maxSitemapPaths {
				seenPath[u.Path] = true
				paths = append(paths, u.Path)
			}
		}
	}
	process(first)
	for len(queue) > 0 && fetched < maxSitemapFiles && ctx.Err() == nil {
		n := min(len(queue), maxSitemapFiles-fetched)
		reqs := make([]engine.Request, n)
		for i := range reqs {
			reqs[i] = engine.Request{Method: "GET", URL: queue[i]}
		}
		queue = queue[n:]
		for _, r := range eng.DoAll(ctx, reqs) {
			process(r)
		}
	}
	return paths
}

// gunzipIfNeeded decompresses a .xml.gz sitemap body, up to maxSitemapBytes.
func gunzipIfNeeded(body []byte) []byte {
	if len(body) < 2 || body[0] != 0x1f || body[1] != 0x8b {
		return body
	}
	zr, err := gzip.NewReader(bytes.NewReader(body))
	if err != nil {
		return nil
	}
	defer zr.Close()
	out, _ := io.ReadAll(io.LimitReader(zr, maxSitemapBytes))
	return out
}
