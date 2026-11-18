// Package discover orchestrates content discovery: it calibrates each base
// directory before fuzzing it (so soft-404s are filtered from the start,
// not post-hoc), then recurses into directories that look "interesting"
// (status diversity, size entropy) rather than blindly recursing into every
// hit the way a naive ffuf -recursion run would.
package discover

import (
	"context"
	"fmt"
	"regexp"
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

	// Manual overrides, applied on top of calibration (ffuf's -mc/-fc/-fs).
	// MatchCodes: every response with one of these statuses is reported even
	// when calibration judged it to be the not-found page. FilterCodes and
	// FilterSizes: responses with these statuses / exact body sizes are
	// never reported. A filter always wins over a match.
	MatchCodes  map[int]bool
	FilterCodes map[int]bool
	FilterSizes map[int]bool
	// FilterWords / FilterLines hide responses with exactly this many words
	// / lines (ffuf's -fw / -fl); FilterRegex hides responses whose body
	// matches (-fr). MatchRegex reports a response whose body matches even
	// when calibration judged it to be the not-found page (-mr). Filters
	// win over matches.
	FilterWords map[int]bool
	FilterLines map[int]bool
	FilterRegex *regexp.Regexp
	MatchRegex  *regexp.Regexp

	// Expected lists wordlist entries taken from the target itself (its
	// sitemap, robots.txt, crawled links). They are SUPPOSED to exist, so
	// their hits do not count toward the "implausibly high hit rate" check
	// that otherwise mistakes a well-mined wordlist for a blocked scan.
	Expected map[string]bool

	// Home is how the target's homepage answered before the scan (see
	// SnapshotHome). With it, a firewall that starts blocking this client
	// partway through is recognised and its block pages are not reported;
	// without it that detection is off.
	Home *HomeSnapshot

	// OnProgress, if set, is called after every classified response with
	// the directory being scanned, how many of its candidates are done, how
	// many it has in total, and the hits so far in that directory. It is
	// called from a single goroutine and must be fast.
	OnProgress func(dir string, done, total, hits int)

	// OnCheckpoint, if set, is called each time a directory has been
	// scanned completely, with everything needed to continue the scan
	// later (see Resume).
	OnCheckpoint func(Checkpoint)
	// Resume, if set, continues a previous scan from its checkpoint instead
	// of starting at the base directory.
	Resume *Checkpoint
}

// Checkpoint is the resumable state of a discovery run, captured between
// directories: what is finished, what was found there, and what is still
// queued. A directory that was interrupted part-way is not in it and is
// scanned again from its start on resume.
type Checkpoint struct {
	Pending         []string       `json:"pending"`          // directories still to scan, in order
	Depths          map[string]int `json:"depths"`           // every directory seen so far -> its depth
	Results         []Result       `json:"results"`          // findings from completed directories
	DirsDone        int            `json:"dirs_done"`        // completed directory count
	CaseTested      bool           `json:"case_tested"`      // case-sensitivity already probed
	CaseInsensitive bool           `json:"case_insensitive"` // and its outcome
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
	// BodyPreview holds up to resultBodyPreviewCap bytes of the body (first
	// chunk only), text/html responses only, used by downstream Tier-A
	// classifiers (e.g. ClassifyDirListings) that need to look at content
	// without re-fetching. Nil for non-HTML or large/empty responses.
	BodyPreview []byte
	// Headers holds the small set of response headers hellhound classifies
	// as potentially information-disclosing (Server, X-Powered-By, etc.) —
	// not the full header map, to keep Results cheap.
	Headers map[string]string
	// path is the candidate path exactly as classified (before URL
	// encoding), kept so a finding can be re-requested and re-classified.
	path string
	// forced marks a result reported only because of a MatchCodes override;
	// the hit-rate safety nets neither count nor remove it.
	forced bool
	// expected marks a hit for a word taken from the target itself.
	expected bool
}

const resultBodyPreviewCap = 8 * 1024

// capturedHeaders is the fixed set hellhound stores on each Result for
// downstream info-disclosure classification. Everything outside this set
// stays off the Result to keep per-Result memory small.
var capturedHeaders = []string{
	"Server", "X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version",
	"X-Generator", "X-Runtime", "X-Rails-Version", "X-Drupal-Cache",
	"X-Drupal-Dynamic-Cache", "X-Application-Context", "X-Backend-Server",
	"X-Served-By", "X-Varnish", "Via",
}

// Discoverer runs calibrated discovery over one target using a shared
// engine and calibrator (so the "not found" baseline learned for one
// directory can inform related ones if desired later).
type Discoverer struct {
	eng  *engine.Engine
	cal  *analyze.Calibrator
	opts Options
	// basePath is the path component of opts.BaseURL ("" for a target at
	// the server root). Directories are tracked relative to it.
	basePath string
	// caseTested / caseInsensitive record whether the target treats paths
	// case-insensitively (IIS, many Windows and macOS-hosted apps), learned
	// once from the first suitable hit.
	caseTested      bool
	caseInsensitive bool
	warnedUnstable  bool
	warnedCatchAll  bool
	warnedDotfiles  bool
	// blocked records that the target's firewall blocked the scan.
	blocked bool
	// catchAll records directories whose not-found answer is a 2xx.
	catchAll map[string]bool
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
	opts.BaseURL = strings.TrimRight(opts.BaseURL, "/")
	base := strings.TrimRight(urlPath(opts.BaseURL), "/")
	return &Discoverer{
		eng:      eng,
		cal:      analyze.NewCalibrator(),
		opts:     opts,
		basePath: base,
	}
}

// Run executes discovery starting at baseDir (e.g. "/") and returns all
// findings classified as interesting, across recursion up to MaxDepth.
func (d *Discoverer) Run(ctx context.Context, baseDir string) ([]Result, error) {
	var all []Result
	queue := []string{normalizeDir(baseDir)}
	depthOf := map[string]int{normalizeDir(baseDir): 0}
	dirsDone := 0
	if cp := d.opts.Resume; cp != nil {
		queue = append([]string(nil), cp.Pending...)
		depthOf = make(map[string]int, len(cp.Depths))
		for k, v := range cp.Depths {
			depthOf[k] = v
		}
		all = append(all, cp.Results...)
		dirsDone = cp.DirsDone
		d.caseTested, d.caseInsensitive = cp.CaseTested, cp.CaseInsensitive
	}

	for len(queue) > 0 {
		dir := queue[0]
		depth := depthOf[dir]

		results, err := d.scanDir(ctx, dir, depth)
		if ctx.Err() != nil {
			// Interrupted part-way through this directory: show what it
			// found, but leave it queued (no checkpoint) so a resumed scan
			// covers it completely.
			all = append(all, results...)
			break
		}
		queue = queue[1:]
		d.detectCaseInsensitivity(ctx, results)
		if d.caseInsensitive {
			results = foldCase(all, results)
		}
		all = append(all, results...) // keep whatever we got even if err != nil below
		if err != nil {
			d.opts.OnWarning(dir, err) // one bad directory doesn't abort the whole scan
		}

		var recurse []string
		if depth < d.opts.MaxDepth {
			recurse = prioritizeRecursion(results)
			if d.catchAll[dir] {
				recurse = d.dropRoutes(ctx, dir, recurse)
			}
		}
		for _, next := range recurse {
			// Result URLs include the target's own base path; directories
			// are relative to it, or "-u http://host/app" would recurse
			// into /app/app/...
			next = normalizeDir(strings.TrimPrefix(next, d.basePath))
			key := next
			if d.caseInsensitive {
				key = strings.ToLower(next)
			}
			if _, seen := depthOf[key]; !seen {
				depthOf[key] = depth + 1
				if key != next {
					depthOf[next] = depth + 1
				}
				queue = append(queue, next)
			}
		}
		dirsDone++
		d.checkpoint(queue, depthOf, all, dirsDone)
	}
	return all, nil
}

// checkpoint hands the current resumable state to OnCheckpoint.
func (d *Discoverer) checkpoint(queue []string, depthOf map[string]int, all []Result, dirsDone int) {
	if d.opts.OnCheckpoint == nil {
		return
	}
	depths := make(map[string]int, len(depthOf))
	for k, v := range depthOf {
		depths[k] = v
	}
	d.opts.OnCheckpoint(Checkpoint{
		Pending:         append([]string(nil), queue...),
		Depths:          depths,
		Results:         append([]Result(nil), all...),
		DirsDone:        dirsDone,
		CaseTested:      d.caseTested,
		CaseInsensitive: d.caseInsensitive,
	})
}

// judge classifies one response: calibration first, then the operator's
// manual overrides. forced reports whether the response is kept only
// because of a MatchCodes override.
func (d *Discoverer) judge(dir, path string, resp engine.Response) (v analyze.Verdict, forced bool) {
	v = d.cal.Classify(dir, path, resp)
	if resp.Err != nil {
		return v, false
	}
	if d.opts.FilterCodes[resp.Status] {
		v.Interesting, v.Reason = false, fmt.Sprintf("status %d hidden by -fc", resp.Status)
		return v, false
	}
	if d.opts.FilterSizes[resp.Length] {
		v.Interesting, v.Reason = false, fmt.Sprintf("size %d hidden by -fs", resp.Length)
		return v, false
	}
	if d.opts.FilterWords[resp.Words] {
		v.Interesting, v.Reason = false, fmt.Sprintf("%d words hidden by -fw", resp.Words)
		return v, false
	}
	if d.opts.FilterLines[resp.Lines] {
		v.Interesting, v.Reason = false, fmt.Sprintf("%d lines hidden by -fl", resp.Lines)
		return v, false
	}
	if d.opts.FilterRegex != nil && d.opts.FilterRegex.Match(resp.Body) {
		v.Interesting, v.Reason = false, "body hidden by -fr"
		return v, false
	}
	if !v.Interesting && d.opts.MatchCodes[resp.Status] {
		v.Interesting, v.Reason = true, fmt.Sprintf("status %d shown because of -mc (calibration: %s)", resp.Status, v.Reason)
		return v, true
	}
	if !v.Interesting && d.opts.MatchRegex != nil && resp.Status != 404 && d.opts.MatchRegex.Match(resp.Body) {
		v.Interesting, v.Reason = true, fmt.Sprintf("body matches -mr (calibration: %s)", v.Reason)
		return v, true
	}
	return v, false
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
	// Probes that failed (timeouts on a struggling target, mostly) get one
	// more chance; a directory is only scanned when enough of them got a
	// real answer to learn what "not found" looks like here.
	if failed > 0 && ctx.Err() == nil {
		var retry []engine.Request
		var idx []int
		for i, p := range probes {
			if p.Resp.Err != nil {
				retry = append(retry, probeReqs[i])
				idx = append(idx, i)
			}
		}
		for j, r := range d.eng.DoAll(ctx, retry) {
			probes[idx[j]].Resp = r
			if r.Err == nil {
				failed--
			} else {
				lastErr = r.Err
			}
		}
	}
	if answered := len(probes) - failed; answered < minAnswered && len(probes) > 0 {
		if ctx.Err() != nil {
			return nil, nil
		}
		if answered == 0 {
			return nil, fmt.Errorf("skipped: all %d calibration probes failed, so nothing here could be verified — target may be unreachable or too slow (raise -timeout, lower -c/-rate), the URL may be malformed, or TLS verification is failing (use -k only for authorized dev/staging testing): %w", len(probes), lastErr)
		}
		return nil, fmt.Errorf("skipped: only %d of %d calibration probes got an answer, too few to tell real pages from not-found ones (last error: %v)", answered, len(probes), lastErr)
	}
	// Every probe got the same 403/429/503 page: either this directory
	// really answers that way, or a firewall is refusing this client. The
	// homepage tells them apart. Learning a block page as "not found" would
	// make every real not-found answer look like a finding.
	if page, ok := uniformBlockProbes(probes); ok && ctx.Err() == nil {
		if blocked, why := d.homepageBlocked(ctx, page); blocked {
			rate := d.noteBlocked()
			return nil, fmt.Errorf("skipped: the target's firewall or bot protection is blocking this scan — unknown paths get one identical %d page (%d bytes) and %s, so nothing here can be tested; slowed down to %d request(s)/sec — if this repeats, wait a few minutes and re-run with e.g. -rate 3 -c 2", page.Status, page.Length, why, rate)
		}
	}
	b := d.cal.Learn(dir, probes)
	if b.CatchAll() {
		if d.catchAll == nil {
			d.catchAll = map[string]bool{}
		}
		d.catchAll[dir] = true
	}
	if b.Unstable() && ctx.Err() == nil {
		// The not-found responses differ from one another, so one shape
		// cannot describe them. Double the sample so the vocabulary model
		// that takes over is built from enough pages, and say so: results
		// here are filtered more aggressively and may be incomplete.
		extra := d.opts.CalibrationN
		if extra < 6 {
			extra = 6
		}
		more := make([]engine.Request, extra)
		moreTokens := make([]string, len(more))
		for i := range more {
			moreTokens[i] = analyze.RandomToken()
			more[i] = engine.Request{Method: "GET", URL: d.opts.BaseURL + joinDir(dir, moreTokens[i])}
		}
		for i, r := range d.eng.DoAll(ctx, more) {
			probes = append(probes, analyze.Probe{Token: moreTokens[i], Resp: r})
		}
		d.cal.Learn(dir, probes)
		if !d.warnedUnstable {
			d.warnedUnstable = true
			d.opts.OnWarning(dir, fmt.Errorf("this target answers unknown paths with content that changes on every request; switched to vocabulary-based filtering — a real page that reuses the same wording may be missed"))
		}
	}

	candidates := make([]string, 0, len(d.opts.Wordlist)*len(d.opts.Extensions))
	expectedCand := map[string]bool{}
	for _, w := range d.opts.Wordlist {
		isExpected := d.opts.Expected[w]
		for _, ext := range d.opts.Extensions {
			if w = strings.TrimLeft(w, "/"); w == "" {
				continue
			}
			c := joinDir(dir, w+ext)
			candidates = append(candidates, c)
			if isExpected {
				expectedCand[c] = true
			}
		}
	}

	reqs := make(chan engine.Request, len(candidates))
	go func() {
		defer close(reqs)
		for _, c := range candidates {
			select {
			case <-ctx.Done():
				return
			case reqs <- engine.Request{Method: "GET", URL: d.opts.BaseURL + encodePath(c), Meta: c}:
			}
		}
	}()

	var results []Result
	total, rateLimited := 0, 0
	for resp := range d.eng.Run(ctx, reqs) {
		total++
		if resp.Err == nil && resp.Status == 429 {
			rateLimited++
		}
		path, _ := resp.Req.Meta.(string)
		v, forced := d.judge(dir, path, resp)
		if d.opts.OnProgress != nil {
			hits := len(results)
			if v.Interesting {
				hits++
			}
			d.opts.OnProgress(dir, total, len(candidates), hits)
		}
		if !v.Interesting {
			continue
		}
		if !forced && isGenericReason(v.Reason) {
			v.Reason = describeHit(path, resp.Status, resp.Header.Get("Content-Type"), resp.Length, resp.RedirectTo)
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
			BodyPreview: previewOf(resp.Body, resp.Header.Get("Content-Type")),
			Headers:     captureHeaders(resp.Header),
			path:        path,
			forced:      forced,
			expected:    expectedCand[path],
		})
	}

	if rateLimited > 0 {
		d.opts.OnWarning(dir, fmt.Errorf("%d of %d requests were still rate-limited (429) after backing off, so those paths were not checked — re-run with a lower -rate or -c", rateLimited, total))
	}
	results = d.dropBlockPages(ctx, dir, results)
	results = d.checkDotfiles(ctx, dir, results)
	results = d.recalibrateIfDrifted(ctx, dir, results, total-countExpected(expectedCand, total))
	return results, nil
}

// isGenericReason reports whether a verdict reason is one of the
// analyzer's generic "differs from the baseline" explanations, which
// describeHit replaces with what the response actually is.
func isGenericReason(r string) bool {
	return strings.Contains(r, "does not match any calibrated baseline") || strings.HasSuffix(r, ", not in baseline")
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
	// driftMinHits is how many hits a small scan needs before an
	// implausible hit rate triggers re-verification.
	driftMinHits = 5
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
	// Results kept only because of -mc are the operator's explicit choice:
	// set them aside so they neither trip nor get removed by the checks
	// below, and add them back at the end.
	var forcedResults []Result
	if len(d.opts.MatchCodes) > 0 {
		organic := results[:0:0]
		for _, r := range results {
			if r.forced {
				forcedResults = append(forcedResults, r)
			} else {
				organic = append(organic, r)
			}
		}
		results = organic
	}
	if len(forcedResults) > 0 {
		return append(d.driftCheck(ctx, dir, results, total), forcedResults...)
	}
	return d.driftCheck(ctx, dir, results, total)
}

// driftCheck is the body of recalibrateIfDrifted, run on calibrated
// (non-forced) results only.
func (d *Discoverer) driftCheck(ctx context.Context, dir string, results []Result, total int) []Result {
	unexpected := 0
	for _, r := range results {
		if !r.expected {
			unexpected++
		}
	}
	if unexpected == 0 || total <= 0 || float64(unexpected)/float64(total) <= driftHitRate {
		return results
	}
	if total < driftMinSample {
		// Too few candidates for the hit rate alone to prove drift (a short,
		// curated wordlist can legitimately hit often), but enough hits to
		// be worth confirming: re-checking costs a few requests and genuine
		// findings survive it.
		if unexpected >= driftMinHits {
			return d.reverify(ctx, dir, results, total)
		}
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
		pct := 100 * float64(unexpected) / float64(total)
		d.opts.OnWarning(dir, fmt.Errorf("hit rate %.0f%% is implausibly high — target likely began serving a block/challenge/wildcard page mid-scan; re-calibrated and dropped %d finding(s) that match the target's new behavior", pct, dropped))
	}
	stillUnexpected := 0
	for _, r := range kept {
		if !r.expected {
			stillUnexpected++
		}
	}
	if float64(stillUnexpected)/float64(total) > driftHitRate {
		kept = d.reverify(ctx, dir, kept, total)
	}
	return kept
}

// countExpected returns how many candidates came from the target's own
// word sources; they are excluded from the hit-rate denominator.
func countExpected(expected map[string]bool, total int) int {
	if n := len(expected); n < total {
		return n
	}
	return 0
}

// minAnswered is the fewest calibration probes that must get an answer
// before a directory's results can be trusted.
const minAnswered = 2

// dropRoutes filters directory candidates under a catch-all directory (one
// that answers paths that cannot exist with a success page). There every
// HTML page looks like a directory, and recursing into each one repeats the
// catch-all under every route: the single-page-app case, where a 45-product
// catalogue turned into 45 full wordlist passes. One request per candidate
// tells them apart: a framework route redirects "X/" to "X" (strips the
// slash), while a real directory serves "X/" or redirects "X" to "X/".
func (d *Discoverer) dropRoutes(ctx context.Context, dir string, candidates []string) []string {
	if len(candidates) == 0 || ctx.Err() != nil {
		return candidates
	}
	origin := strings.TrimSuffix(d.opts.BaseURL, d.basePath)
	reqs := make([]engine.Request, len(candidates))
	for i, c := range candidates {
		reqs[i] = engine.Request{Method: "GET", URL: origin + strings.TrimRight(c, "/") + "/"}
	}
	var keep []string
	dropped := 0
	for i, r := range d.eng.DoAll(ctx, reqs) {
		c := strings.TrimRight(candidates[i], "/")
		if r.Err == nil && r.Status >= 300 && r.Status < 400 && strings.TrimRight(pathOnly(r.RedirectTo), "/") == c && !strings.HasSuffix(pathOnly(r.RedirectTo), "/") {
			dropped++
			continue
		}
		keep = append(keep, candidates[i])
	}
	if dropped > 0 && !d.warnedCatchAll {
		d.warnedCatchAll = true
		d.opts.OnWarning(dir, fmt.Errorf("this site answers unknown paths with a success page and its pages strip a trailing slash (framework routes, typical of single-page apps such as Next.js) — %d such page(s) were not scanned as directories", dropped))
	}
	return keep
}

// pathOnly strips scheme, host, query and fragment from a Location value.
func pathOnly(loc string) string {
	if i := strings.Index(loc, "://"); i >= 0 {
		loc = loc[i+3:]
		if j := strings.Index(loc, "/"); j >= 0 {
			loc = loc[j:]
		} else {
			loc = "/"
		}
	}
	if i := strings.IndexAny(loc, "?#"); i >= 0 {
		loc = loc[:i]
	}
	return loc
}

// reverify is the last line of defence against a flood: the hit rate is
// still implausible after dropping findings that match fresh probes, which
// means the up-front calibration did not capture how this directory
// answers unknown paths (too few probes, or pages that vary more than the
// sample showed). It learns the baseline again from a larger sample and
// re-requests every remaining finding, keeping only those that still stand
// out.
func (d *Discoverer) reverify(ctx context.Context, dir string, results []Result, total int) []Result {
	n := 2 * d.opts.CalibrationN
	if n < 12 {
		n = 12
	}
	reqs := make([]engine.Request, n)
	tokens := make([]string, n)
	for i := range reqs {
		tokens[i] = analyze.RandomToken()
		reqs[i] = engine.Request{Method: "GET", URL: d.opts.BaseURL + joinDir(dir, tokens[i])}
	}
	probes := make([]analyze.Probe, 0, n)
	for i, r := range d.eng.DoAll(ctx, reqs) {
		probes = append(probes, analyze.Probe{Token: tokens[i], Resp: r})
	}
	guessed := 0
	for _, r := range results {
		if !r.expected {
			guessed++
		}
	}
	// The fresh probes all got one block page: the firewall is refusing
	// this client now. Learning that page as "not found" would turn every
	// real not-found answer into a finding (seen live: real 404s reported
	// as 403 hits), so keep the old baseline and drop the block pages.
	if page, ok := uniformBlockProbes(probes); ok && ctx.Err() == nil {
		if blocked, why := d.homepageBlocked(ctx, page); blocked {
			kept := results[:0:0]
			for _, r := range results {
				if !sameShape(r, page) {
					kept = append(kept, r)
				}
			}
			rate := d.noteBlocked()
			d.opts.OnWarning(dir, fmt.Errorf("the target's firewall started blocking the scan (status %d, %d bytes; %s) — %d hit(s) that were its block page were removed and paths after the block were not really tested; slowing down to %d request(s)/sec after a %s pause", page.Status, page.Length, why, len(results)-len(kept), rate, blockPause))
			return kept
		}
	}
	d.cal.Learn(dir, probes)

	again := make([]engine.Request, len(results))
	for i, res := range results {
		again[i] = engine.Request{Method: "GET", URL: res.URL}
	}
	kept := results[:0]
	for i, resp := range d.eng.DoAll(ctx, again) {
		res := results[i]
		if ctx.Err() != nil {
			kept = append(kept, res) // interrupted: keep what was not re-checked
			continue
		}
		p := res.path
		if p == "" {
			p = strings.TrimPrefix(urlPath(res.URL), d.basePath)
		}
		if v, forced := d.judge(dir, p, resp); v.Interesting {
			// Report what the re-check saw, not the stale first answer: a
			// path can answer differently the second time.
			if !forced && isGenericReason(v.Reason) {
				v.Reason = describeHit(p, resp.Status, resp.Header.Get("Content-Type"), resp.Length, resp.RedirectTo)
			}
			res.Verdict = v
			res.Status, res.Length, res.Words, res.Lines = resp.Status, resp.Length, resp.Words, resp.Lines
			res.ContentType, res.RedirectTo = resp.Header.Get("Content-Type"), resp.RedirectTo
			res.BodyPreview = previewOf(resp.Body, res.ContentType)
			res.Headers = captureHeaders(resp.Header)
			kept = append(kept, res)
		}
	}
	d.opts.OnWarning(dir, fmt.Errorf("%d of %d guessed paths looked like hits, which is implausible; learned the not-found answer again from %d probes and re-checked every hit — %d remain", guessed, total, n, len(kept)))
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
	if strings.ContainsAny(urlPath(r.URL), "?#") {
		return false // a URL with a query string is an endpoint, not a directory
	}
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

// previewOf returns up to resultBodyPreviewCap bytes of body, but ONLY for
// text/html responses — dir-listing detection needs HTML, and binary bodies
// (images, PDFs, octet-streams) just waste memory. Returns nil otherwise.
func previewOf(body []byte, contentType string) []byte {
	if len(body) == 0 {
		return nil
	}
	ct := strings.ToLower(contentType)
	if !strings.Contains(ct, "text/html") && !strings.Contains(ct, "text/plain") {
		return nil
	}
	n := len(body)
	if n > resultBodyPreviewCap {
		n = resultBodyPreviewCap
	}
	cp := make([]byte, n)
	copy(cp, body[:n])
	return cp
}

// captureHeaders stores only the headers hellhound classifies as potentially
// information-disclosing — a per-Result full-header map would waste memory
// at scan scale (thousands of Results).
func captureHeaders(h map[string][]string) map[string]string {
	if len(h) == 0 {
		return nil
	}
	var out map[string]string
	for _, name := range capturedHeaders {
		// http.Header is case-insensitive via its API; our storage is a flat
		// map[string][]string, so match case-insensitively ourselves.
		for storedName, vs := range h {
			if !strings.EqualFold(storedName, name) {
				continue
			}
			if len(vs) == 0 || vs[0] == "" {
				continue
			}
			if out == nil {
				out = map[string]string{}
			}
			out[name] = vs[0]
			break
		}
	}
	return out
}

// detectCaseInsensitivity learns, once, whether the target serves the same
// resource for a path regardless of letter case. It re-requests one real
// hit with its case flipped; the same status and shape means the server
// folds case, and "/Admin", "/ADMIN" and "/admin" are one finding.
func (d *Discoverer) detectCaseInsensitivity(ctx context.Context, results []Result) {
	if d.caseTested || ctx.Err() != nil {
		return
	}
	for _, r := range results {
		if r.Status < 200 || r.Status >= 300 {
			continue
		}
		p := urlPath(r.URL)
		if strings.ContainsAny(p, "?#") {
			continue
		}
		flipped := flipCase(p)
		if flipped == p {
			continue
		}
		d.caseTested = true
		origin := strings.TrimSuffix(d.opts.BaseURL, d.basePath)
		resps := d.eng.DoAll(ctx, []engine.Request{{Method: "GET", URL: origin + flipped}})
		if len(resps) != 1 || resps[0].Err != nil || resps[0].Status != r.Status {
			return
		}
		h := analyze.SimHash(resps[0].Body, flipped, lastSeg(flipped))
		d.caseInsensitive = analyze.SimilarShape(h, r.Verdict.ClusterKey)
		if d.caseInsensitive {
			d.opts.OnWarning("/", fmt.Errorf("target treats paths case-insensitively; findings that differ only by letter case are merged"))
		}
		return
	}
}

// flipCase swaps the case of every ASCII letter in the last path segment.
func flipCase(p string) string {
	i := strings.LastIndex(p, "/") + 1
	b := []byte(p)
	for j := i; j < len(b); j++ {
		switch c := b[j]; {
		case c >= 'a' && c <= 'z':
			b[j] = c - 32
		case c >= 'A' && c <= 'Z':
			b[j] = c + 32
		}
	}
	return string(b)
}

// foldCase drops results whose URL differs only by letter case from one
// already kept (in earlier directories or earlier in this batch), keeping
// the all-lowercase spelling when the batch offers one.
func foldCase(kept, batch []Result) []Result {
	seen := make(map[string]bool, len(kept))
	for _, r := range kept {
		seen[strings.ToLower(r.URL)] = true
	}
	idx := map[string]int{}
	var out []Result
	for _, r := range batch {
		k := strings.ToLower(r.URL)
		if seen[k] {
			continue
		}
		if i, ok := idx[k]; ok {
			if r.URL == k && out[i].URL != k {
				out[i] = r
			}
			continue
		}
		idx[k] = len(out)
		out = append(out, r)
	}
	return out
}

// encodePath makes a candidate path safe to put in a request URL without
// changing what the wordlist author meant. '/' and an existing query string
// are kept, valid %XX escapes are kept (wordlists ship pre-encoded
// entries), and everything a URL cannot carry literally — spaces, '#'
// (which would silently truncate the path into a fragment), control and
// non-ASCII bytes, a stray '%' — is percent-encoded.
func encodePath(p string) string {
	const hex = "0123456789ABCDEF"
	isHex := func(c byte) bool {
		return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
	}
	var b strings.Builder
	b.Grow(len(p) + 8)
	for i := 0; i < len(p); i++ {
		c := p[i]
		switch {
		case c == '%' && i+2 < len(p) && isHex(p[i+1]) && isHex(p[i+2]):
			b.WriteByte(c)
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9',
			strings.IndexByte("-._~/?=&!$'()*+,;:@", c) >= 0:
			b.WriteByte(c)
		default:
			b.WriteByte('%')
			b.WriteByte(hex[c>>4])
			b.WriteByte(hex[c&15])
		}
	}
	return b.String()
}
