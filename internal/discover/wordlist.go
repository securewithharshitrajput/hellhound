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
	"regexp"
	"strings"

	"github.com/securewithharshitrajput/hellhound/internal/engine"
	"github.com/securewithharshitrajput/hellhound/internal/wordlist"
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
	var mined []string

	first := eng.DoAll(ctx, []engine.Request{
		{Method: "GET", URL: baseURL + "/robots.txt"},
		{Method: "GET", URL: baseURL + "/"},
	})
	robots, home := first[0], first[1]

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
		return wordlist.Merge(seed, mined)
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
	for _, js := range eng.DoAll(ctx, jsReqs) {
		if js.Err == nil && js.Status == 200 {
			mined = append(mined, wordlist.PathToWords(wordlist.FromJS(js.Body))...)
		}
	}

	return wordlist.Merge(seed, mined)
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
