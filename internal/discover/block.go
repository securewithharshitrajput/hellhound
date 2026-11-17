package discover

import (
	"context"
	"fmt"
	"path"
	"strings"
	"time"

	"github.com/securewithharshitrajput/hellhound/internal/analyze"
	"github.com/securewithharshitrajput/hellhound/internal/engine"
)

// blockStatuses are the statuses firewalls and bot protection answer with
// when they refuse a client: Hostinger's hcdn and Cloudflare send 403,
// some WAFs 406, rate limiters 429, overloaded or protective proxies 503.
var blockStatuses = map[int]bool{403: true, 406: true, 429: true, 503: true}

// blockMinGroup is how many results must share one block-status page
// before the homepage is checked to see whether the scan itself is blocked.
const blockMinGroup = 3

// blockPause is how long every worker waits once a block is detected,
// giving the firewall time to calm down before the slower scan continues.
// A variable so tests do not wait.
var blockPause = 30 * time.Second

// sameShape reports whether two results look like the same page: same
// status and either the same body shape or exactly the same size (a block
// page usually carries a request id or timestamp but keeps its size).
func sameShape(a, b Result) bool {
	return a.Status == b.Status && (a.Length == b.Length || analyze.SimilarShape(a.Verdict.ClusterKey, b.Verdict.ClusterKey))
}

// largestBlockGroup returns one member of the largest set of results that
// share a block status and page shape, and the size of that set.
func largestBlockGroup(results []Result) (rep Result, n int) {
	for i, r := range results {
		if !blockStatuses[r.Status] {
			continue
		}
		c := 0
		for _, o := range results {
			if sameShape(r, o) {
				c++
			}
		}
		if c > n {
			rep, n = results[i], c
		}
	}
	return rep, n
}

// uniformBlockProbes reports whether every answered calibration probe got
// the same block-status page, and describes that page.
func uniformBlockProbes(probes []analyze.Probe) (rep Result, ok bool) {
	answered := 0
	for _, p := range probes {
		if p.Resp.Err != nil {
			continue
		}
		r := Result{Status: p.Resp.Status, Length: p.Resp.Length, Verdict: analyze.Verdict{ClusterKey: analyze.SimHash(p.Resp.Body)}}
		if !blockStatuses[r.Status] {
			return Result{}, false
		}
		if answered > 0 && !sameShape(rep, r) {
			return Result{}, false
		}
		if answered == 0 {
			rep = r
		}
		answered++
	}
	return rep, answered >= minAnswered
}

// HomeSnapshot is how the target's start page answered before the scan
// began. Block detection compares against it: a firewall that starts
// refusing this client changes the homepage too, while a site that simply
// answers 403 everywhere (homepage included) has always looked that way.
type HomeSnapshot struct {
	Status int
	Length int
	Hash   uint64
}

// SnapshotHome records a homepage response for Options.Home.
func SnapshotHome(r engine.Response) *HomeSnapshot {
	if r.Err != nil {
		return nil
	}
	return &HomeSnapshot{Status: r.Status, Length: r.Length, Hash: analyze.SimHash(r.Body)}
}

// homepageBlocked re-asks the one page that certainly exists — the
// target's start page — and reports whether it has turned into the
// suspicious page (or stopped answering) since the scan began. If it has,
// the suspicious page is the firewall talking about this client, not the
// server talking about those paths. Without a snapshot it cannot tell, and
// says no.
func (d *Discoverer) homepageBlocked(ctx context.Context, page Result) (bool, string) {
	before := d.opts.Home
	if before == nil || ctx.Err() != nil {
		return false, ""
	}
	was := Result{Status: before.Status, Length: before.Length, Verdict: analyze.Verdict{ClusterKey: before.Hash}}
	if sameShape(was, page) {
		return false, "" // the homepage always looked like this
	}
	resps := d.eng.DoAll(ctx, []engine.Request{{Method: "GET", URL: d.opts.BaseURL + "/"}})
	if ctx.Err() != nil || len(resps) != 1 {
		return false, ""
	}
	r := resps[0]
	if r.Err != nil {
		return true, fmt.Sprintf("the homepage, which answered %d at the start, no longer answers", before.Status)
	}
	now := Result{Status: r.Status, Length: r.Length, Verdict: analyze.Verdict{ClusterKey: analyze.SimHash(r.Body)}}
	if sameShape(now, page) {
		return true, fmt.Sprintf("the homepage, which answered %d at the start, now gets the same %d page", before.Status, r.Status)
	}
	return false, ""
}

// noteBlocked slows the scan down once a block is confirmed and returns
// the new rate.
func (d *Discoverer) noteBlocked() int {
	d.blocked = true
	return d.eng.SlowDown(blockPause)
}

// Blocked reports whether the target's firewall blocked the scan at any
// point; results from such a scan are incomplete.
func (d *Discoverer) Blocked() bool { return d.blocked }

// dropBlockPages removes results that are really the target's firewall
// block page. A real site answers different paths differently; when several
// paths suddenly get one identical 403/429/503 page and the homepage gets
// it too, those paths were never actually tested.
func (d *Discoverer) dropBlockPages(ctx context.Context, dir string, results []Result) []Result {
	rep, n := largestBlockGroup(results)
	if n < blockMinGroup || ctx.Err() != nil {
		return results
	}
	blocked, why := d.homepageBlocked(ctx, rep)
	if !blocked {
		return results
	}
	kept := results[:0:0]
	for _, r := range results {
		if !sameShape(r, rep) {
			kept = append(kept, r)
		}
	}
	rate := d.noteBlocked()
	d.opts.OnWarning(dir, fmt.Errorf("the target's firewall started blocking the scan: %d path(s) got its block page (status %d, %d bytes) and %s — those paths were NOT tested and were removed from the results; slowing down to %d request(s)/sec after a %s pause (re-run later with a lower -rate to cover them)",
		len(results)-len(kept), rep.Status, rep.Length, why, rate, blockPause))
	return kept
}

// checkDotfiles handles 401/403 answers for paths with a segment starting
// with '.' (/.env, /.git/config). Many servers refuse every such path
// (Apache and LiteSpeed "deny dotfiles" rules, Hostinger), so a 403 there
// says nothing about whether the file exists. One made-up dotfile tells the
// two cases apart: if it is refused too, those hits are dropped; if it gets
// a not-found answer, the refusal is specific and the file very likely
// exists.
func (d *Discoverer) checkDotfiles(ctx context.Context, dir string, results []Result) []Result {
	var idx []int
	for i, r := range results {
		if !r.forced && (r.Status == 401 || r.Status == 403) && hasDotSegment(urlPath(r.URL)) {
			idx = append(idx, i)
		}
	}
	if len(idx) == 0 || ctx.Err() != nil {
		return results
	}
	probe := d.opts.BaseURL + joinDir(dir, "."+analyze.RandomToken())
	resps := d.eng.DoAll(ctx, []engine.Request{{Method: "GET", URL: probe}})
	if len(resps) != 1 || resps[0].Err != nil {
		return results
	}
	control := resps[0].Status
	if control == 401 || control == 403 {
		drop := map[int]bool{}
		for _, i := range idx {
			drop[i] = true
		}
		kept := results[:0:0]
		for i, r := range results {
			if !drop[i] {
				kept = append(kept, r)
			}
		}
		if !d.warnedDotfiles {
			d.warnedDotfiles = true
			d.opts.OnWarning(dir, fmt.Errorf("this server refuses every path starting with '.' (a made-up one got %d too), so %d forbidden dotfile hit(s) such as %s prove nothing and were removed", control, len(idx), path.Base(urlPath(results[idx[0]].URL))))
		}
		return kept
	}
	for _, i := range idx {
		results[i].Verdict.Reason = fmt.Sprintf("forbidden (%d) while a made-up dotfile gets %d — this file very likely exists and is being protected", results[i].Status, control)
	}
	return results
}

// hasDotSegment reports whether any segment of p starts with '.'.
func hasDotSegment(p string) bool {
	for _, s := range strings.Split(p, "/") {
		if strings.HasPrefix(s, ".") && s != "." && s != ".." {
			return true
		}
	}
	return false
}

// describeHit replaces the analyzer's generic "does not match the
// baseline" reason with what the response actually is, so a reader can
// tell a login redirect from a directory, a JSON endpoint from an image.
func describeHit(p string, status int, contentType string, length int, redirectTo string) string {
	ct := strings.ToLower(contentType)
	size := humanSize(length)
	switch {
	case status >= 300 && status < 400:
		target := pathOnly(redirectTo)
		lower := strings.ToLower(redirectTo)
		switch {
		case target != "" && strings.TrimRight(target, "/") == strings.TrimRight(p, "/") && strings.HasSuffix(target, "/"):
			return "directory (redirects to " + target + ")"
		case strings.Contains(lower, "login") || strings.Contains(lower, "signin") || strings.Contains(lower, "sign-in") || strings.Contains(lower, "auth"):
			return "needs login (redirects to " + redirectTo + ")"
		case redirectTo != "":
			return fmt.Sprintf("redirects (%d) to %s", status, redirectTo)
		}
		return fmt.Sprintf("redirect (%d) with no Location", status)
	case status == 401:
		return "needs authentication (401) — exists but is protected"
	case status == 403:
		return "forbidden (403) — exists but access is denied"
	case status == 405:
		return "method not allowed (405) — exists, try other HTTP methods"
	case status >= 500:
		return fmt.Sprintf("server error (%d) — the path exists and something failed handling it", status)
	case status >= 400:
		return fmt.Sprintf("status %d, unlike this site's not-found answer", status)
	}
	ext := strings.ToLower(path.Ext(p))
	switch {
	case strings.Contains(ct, "json"):
		return "JSON endpoint, " + size
	case strings.Contains(ct, "xml") && !strings.Contains(ct, "html"):
		return "XML document, " + size
	case strings.HasPrefix(ct, "image/") || isAssetExt(ext, "image"):
		return "image, " + size
	case strings.Contains(ct, "javascript") || ext == ".js" || ext == ".mjs":
		return "JavaScript file, " + size
	case strings.Contains(ct, "css") || ext == ".css":
		return "stylesheet, " + size
	case strings.Contains(ct, "html"):
		return "page, " + size
	case strings.Contains(ct, "text/plain"):
		return "text file, " + size
	case ct == "":
		return "file with no content type, " + size
	}
	return ct + ", " + size
}

// isAssetExt reports whether ext belongs to the given asset kind.
func isAssetExt(ext, kind string) bool {
	switch kind {
	case "image":
		switch ext {
		case ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp", ".avif", ".bmp":
			return true
		}
	}
	return false
}

// IsStaticAsset reports whether a URL path names a static asset (image,
// script, stylesheet, font, manifest, media) rather than a page.
func IsStaticAsset(p string) bool {
	switch strings.ToLower(path.Ext(p)) {
	case ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp", ".avif", ".bmp",
		".js", ".mjs", ".css", ".woff", ".woff2", ".ttf", ".otf", ".eot",
		".webmanifest", ".mp4", ".webm", ".mp3", ".wav":
		return true
	}
	return false
}

func humanSize(n int) string {
	switch {
	case n >= 1<<20:
		return fmt.Sprintf("%.1f MB", float64(n)/(1<<20))
	case n >= 1024:
		return fmt.Sprintf("%d KB", n/1024)
	}
	return fmt.Sprintf("%d bytes", n)
}
