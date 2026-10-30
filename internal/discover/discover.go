// Package discover orchestrates content discovery: it calibrates each base
// directory before fuzzing it (so soft-404s are filtered from the start,
// not post-hoc), then recurses into directories that look "interesting"
// (status diversity, size entropy) rather than blindly recursing into every
// hit the way a naive ffuf -recursion run would.
package discover

import (
	"context"
	"fmt"
	"strings"

	"github.com/securewithharshitrajput/hellhound/internal/analyze"
	"github.com/securewithharshitrajput/hellhound/internal/engine"
)

// Options configures a discovery run.
type Options struct {
	BaseURL      string // e.g. https://target.tld
	Wordlist     []string
	CalibrationN int      // probes per directory during calibration (default 6)
	MaxDepth     int      // recursion depth cap
	Extensions   []string // appended to each word, e.g. []string{"", ".php", ".bak"}
	// OnWarning, if set, is called when scanning one directory fails (e.g.
	// a request-building error). The scan continues with the next queued
	// directory rather than aborting the whole run and discarding every
	// result already found — a single transient failure shouldn't cost you
	// everything found before it.
	OnWarning func(dir string, err error)
}

// Result is one classified discovery result, ready for reporting.
type Result struct {
	URL         string
	Status      int
	Length      int
	Words       int
	Lines       int
	Depth       int
	ContentType string
	RedirectTo  string
	Verdict     analyze.Verdict
}

// Discoverer runs calibrated discovery over one target using a shared
// engine and calibrator (so the "not found" baseline learned for one
// directory can inform related ones if desired later).
type Discoverer struct {
	eng  *engine.Engine
	cal  *analyze.Calibrator
	opts Options
}

func New(eng *engine.Engine, opts Options) *Discoverer {
	// CalibrationN and MaxDepth are deliberately NOT defaulted here when
	// zero. An earlier version did `if opts.CalibrationN == 0 { ... = 6 }`
	// (same for MaxDepth), which silently promoted an explicit, legitimate
	// "-depth 0" (scan only the root, no recursion — a perfectly normal
	// thing to ask for) up to MaxDepth=3, because Go's int zero value can't
	// distinguish "caller explicitly wants 0" from "caller left this
	// unset." Confirmed by running it: -depth 0 produced a 3-level-deep
	// scan (228 requests) instead of a root-only one (38 requests). The
	// CLI's own flag defaults (depth=2, calibrate=6 in cmd/hellhound) are
	// the actual default; every caller — CLI and tests alike — already
	// passes both fields explicitly, so 0 is always honored literally now.
	if len(opts.Extensions) == 0 {
		opts.Extensions = []string{""}
	}
	if opts.OnWarning == nil {
		opts.OnWarning = func(string, error) {}
	}
	return &Discoverer{
		eng:  eng,
		cal:  analyze.NewCalibrator(),
		opts: opts,
	}
}

// Run executes discovery starting at baseDir (e.g. "/") and returns all
// findings classified as interesting, across recursion up to MaxDepth.
func (d *Discoverer) Run(ctx context.Context, baseDir string) ([]Result, error) {
	var all []Result
	queue := []string{normalizeDir(baseDir)}
	depthOf := map[string]int{normalizeDir(baseDir): 0}

	for len(queue) > 0 {
		dir := queue[0]
		queue = queue[1:]
		depth := depthOf[dir]

		results, err := d.scanDir(ctx, dir, depth)
		all = append(all, results...) // keep whatever we got even if err != nil below
		if err != nil {
			d.opts.OnWarning(dir, err)
			continue // one bad directory doesn't abort the whole scan
		}
		if ctx.Err() != nil {
			break // caller cancelled; stop queueing new work
		}

		if depth >= d.opts.MaxDepth {
			continue
		}
		for _, next := range prioritizeRecursion(results) {
			if _, seen := depthOf[next]; !seen {
				depthOf[next] = depth + 1
				queue = append(queue, next)
			}
		}
	}
	return all, nil
}

// scanDir calibrates one directory, fuzzes it with the wordlist (x
// extensions), and classifies every response.
func (d *Discoverer) scanDir(ctx context.Context, dir string, depth int) ([]Result, error) {
	// Calibration: fire all N random-token probes CONCURRENTLY via DoAll,
	// then hand the batch to the analyzer. An earlier version called the
	// engine once per probe, sequentially, each call spinning up the
	// entire worker pool to service a single request — N network
	// round-trips back-to-back, N pool start/stop cycles, for work that
	// has no dependency between probes at all.
	probeReqs := make([]engine.Request, d.opts.CalibrationN)
	tokens := make([]string, d.opts.CalibrationN)
	for i := range probeReqs {
		tok := analyze.RandomToken()
		tokens[i] = tok
		probeReqs[i] = engine.Request{Method: "GET", URL: d.opts.BaseURL + joinDir(dir, tok)}
	}
	probeResps := d.eng.DoAll(ctx, probeReqs)
	probes := make([]analyze.Probe, len(probeResps))
	failed := 0
	var lastErr error
	for i, r := range probeResps {
		probes[i] = analyze.Probe{Token: tokens[i], Resp: r}
		if r.Err != nil {
			failed++
			lastErr = r.Err
		}
	}
	// If every single calibration probe failed (connection refused, DNS
	// failure, malformed URL, TLS error — anything that never got a real
	// HTTP response), the rest of this scan is almost certainly going to
	// silently report "0 findings" too, since every candidate request
	// will fail the exact same way and Classify treats a request error as
	// "not interesting". That looks identical to "scanned a clean target"
	// from the output alone — a real, confirmed case: pointing -u at a
	// URL missing its scheme produced a confident "0 findings, exit 0"
	// with zero indication anything was wrong. Surface it loudly instead
	// of letting a misconfigured run masquerade as a clean result.
	if len(probes) > 0 && failed == len(probes) {
		d.opts.OnWarning(dir, fmt.Errorf("all %d calibration probes failed — target may be unreachable, the URL may be malformed, or TLS verification is failing (use -k to skip it, only for authorized dev/staging testing): %w", failed, lastErr))
	}
	d.cal.Learn(dir, probes)

	candidates := make([]string, 0, len(d.opts.Wordlist)*len(d.opts.Extensions))
	for _, w := range d.opts.Wordlist {
		for _, ext := range d.opts.Extensions {
			candidates = append(candidates, joinDir(dir, w+ext))
		}
	}

	reqs := make(chan engine.Request, len(candidates))
	go func() {
		defer close(reqs)
		for _, c := range candidates {
			select {
			case <-ctx.Done():
				return
			case reqs <- engine.Request{Method: "GET", URL: d.opts.BaseURL + c, Meta: c}:
			}
		}
	}()

	var results []Result
	total := 0
	for resp := range d.eng.Run(ctx, reqs) {
		total++
		path, _ := resp.Req.Meta.(string)
		v := d.cal.Classify(dir, path, resp)
		if !v.Interesting {
			continue
		}
		results = append(results, Result{
			URL:         resp.Req.URL,
			Status:      resp.Status,
			Length:      resp.Length,
			Words:       resp.Words,
			Lines:       resp.Lines,
			Depth:       depth,
			ContentType: resp.Header.Get("Content-Type"),
			RedirectTo:  resp.RedirectTo,
			Verdict:     v,
		})
	}

	results = d.recalibrateIfDrifted(ctx, dir, results, total)
	return results, nil
}

const (
	// driftMinSample is how many candidates must be classified before the
	// hit-rate drift check is meaningful (too few and the ratio is noise).
	driftMinSample = 100
	// driftHitRate is the fraction of candidates classified "interesting"
	// above which we suspect the target changed behavior mid-scan (started
	// serving a bot-challenge / WAF block / wildcard page to everything).
	// Real content discovery hit rates are a fraction of a percent; 30% is
	// so far beyond plausible that it unambiguously means "the baseline
	// learned up front no longer describes what the target is returning."
	driftHitRate = 0.30
)

// recalibrateIfDrifted defends against a target that changes behavior
// partway through a scan — the exact failure seen live against a
// Vercel-hosted site, where bot-mitigation escalated after the first burst
// of requests and every subsequent path returned an identical "Security
// Checkpoint" challenge page. The up-front calibration can't know about a
// change that happens later, so everything after it looks like a brand-new
// finding and the report floods.
//
// When the hit rate for a directory is implausibly high, it re-calibrates
// RIGHT NOW (fresh probes capture the target's *current* behavior) and
// drops any collected finding whose shape matches that fresh baseline —
// i.e. anything that is really just the new block/challenge page. Findings
// from before the drift that are genuinely distinct from the new baseline
// survive. It compares via stored SimHash fingerprints (Verdict.ClusterKey)
// so it needs no response bodies and sends no extra requests beyond the
// handful of fresh probes — it will not re-hammer an already-struggling
// target.
func (d *Discoverer) recalibrateIfDrifted(ctx context.Context, dir string, results []Result, total int) []Result {
	if total < driftMinSample || len(results) == 0 {
		return results
	}
	if float64(len(results))/float64(total) <= driftHitRate {
		return results
	}

	n := d.opts.CalibrationN
	reqs := make([]engine.Request, n)
	tokens := make([]string, n)
	for i := range reqs {
		tok := analyze.RandomToken()
		tokens[i] = tok
		reqs[i] = engine.Request{Method: "GET", URL: d.opts.BaseURL + joinDir(dir, tok)}
	}
	var freshHashes []uint64
	for i, r := range d.eng.DoAll(ctx, reqs) {
		if r.Err != nil {
			continue
		}
		freshHashes = append(freshHashes, analyze.SimHash(r.Body, joinDir(dir, tokens[i]), tokens[i]))
	}
	if len(freshHashes) == 0 {
		return results // couldn't re-probe; leave results untouched
	}

	kept := results[:0]
	dropped := 0
	for _, res := range results {
		matchesNewBaseline := false
		for _, fh := range freshHashes {
			if analyze.SimilarShape(fh, res.Verdict.ClusterKey) {
				matchesNewBaseline = true
				break
			}
		}
		if matchesNewBaseline {
			dropped++
			continue
		}
		kept = append(kept, res)
	}
	if dropped > 0 {
		pct := 100 * float64(len(results)) / float64(total)
		d.opts.OnWarning(dir, fmt.Errorf("hit rate %.0f%% is implausibly high — target likely began serving a block/challenge/wildcard page mid-scan; re-calibrated and dropped %d finding(s) that match the target's new behavior", pct, dropped))
	}
	return kept
}

// prioritizeRecursion decides which hits are worth recursing into. Rather
// than recursing into everything (ffuf's -recursion default), we only queue
// paths that look like real browsable directories.
func prioritizeRecursion(results []Result) []string {
	var dirs []string
	for _, r := range results {
		if r.Status < 200 || r.Status >= 400 {
			continue
		}
		if !looksLikeDirectory(r) {
			continue
		}
		dirs = append(dirs, urlPath(r.URL))
	}
	return dedupe(dirs)
}

// looksLikeDirectory filters out hits that are clearly leaf
// endpoints/files rather than directories worth recursing into — recursing
// into every extensionless 200 (an earlier version's behavior) wastes an
// entire calibration + full-wordlist pass on things like a JSON API
// endpoint ("/graphql", "/api/v1/users") that structurally cannot have
// meaningful children.
func looksLikeDirectory(r Result) bool {
	seg := lastSeg(urlPath(r.URL))
	if strings.Contains(seg, ".") {
		return false // looks like a file (app.js, config.bak), not a directory
	}
	if r.Status >= 300 && r.Status < 400 {
		// Only a redirect that actually looks like "this is a directory,
		// go to the trailing-slash form" is worth recursing into — not
		// any redirect whatsoever. Found against a real wordlist
		// (SecLists common.txt): several entries contain "//" (e.g.
		// "render/https://www.google.com"), which net/http's own
		// ServeMux auto-redirects to its slash-collapsed form as a
		// built-in path-cleaning behavior — a mechanical artifact of the
		// request shape, not a real directory, and recursing into each
		// one multiplied a handful of malformed-looking wordlist entries
		// into dozens of full wordlist re-scans.
		return strings.HasSuffix(r.RedirectTo, "/")
	}
	ct := strings.ToLower(r.ContentType)
	for _, leafType := range []string{
		"application/json", "application/xml", "application/octet-stream",
		"application/zip", "application/pdf", "image/", "video/", "audio/", "font/",
	} {
		if strings.Contains(ct, leafType) {
			return false
		}
	}
	// An earlier version treated an ambiguous/missing Content-Type as
	// "assume directory" (erring toward not missing a real one). Flipped
	// to require an explicit, non-leaf Content-Type after a real
	// comparison run: a calibration false positive on ".git/config" (a
	// FILE, which this server happened to serve with no Content-Type set)
	// got recursed into, multiplying one bad classification into a full
	// extra wordlist pass. Missing a genuine directory that serves no
	// Content-Type is a real but rarer cost than that cascade.
	return ct != "" && !strings.Contains(ct, "text/plain")
}

func normalizeDir(p string) string {
	p = strings.TrimRight(p, "/")
	if p == "" {
		return "/"
	}
	return p
}

func joinDir(base, seg string) string {
	if base == "/" {
		return "/" + seg
	}
	return base + "/" + seg
}

func urlPath(fullURL string) string {
	// Strip scheme://host, keep only the path portion.
	if i := strings.Index(fullURL, "://"); i >= 0 {
		rest := fullURL[i+3:]
		if j := strings.Index(rest, "/"); j >= 0 {
			return rest[j:]
		}
		return "/"
	}
	return fullURL
}

func lastSeg(p string) string {
	p = strings.TrimRight(p, "/")
	if i := strings.LastIndex(p, "/"); i >= 0 {
		return p[i+1:]
	}
	return p
}

func dedupe(ss []string) []string {
	seen := make(map[string]bool, len(ss))
	out := make([]string, 0, len(ss))
	for _, s := range ss {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}
