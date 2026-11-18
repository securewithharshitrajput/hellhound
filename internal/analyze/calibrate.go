// Package analyze is hellhound's core differentiator versus ffuf: instead of
// requiring the operator to manually pass -fc/-fs after eyeballing a few
// responses, it probes the target with random, almost-certainly-nonexistent
// paths up front, learns what "not found" looks like per base directory
// (status code + size bucket + SimHash shape), and then classifies every
// real result against that baseline. It also clusters near-identical hits
// together so one template rendered 40 times doesn't read as 40 findings.
package analyze

import (
	"bytes"
	"fmt"
	"math/rand"
	"strings"

	"github.com/securewithharshitrajput/hellhound/internal/engine"
)

// Baseline is the learned "not found" fingerprint for one base path.
type Baseline struct {
	BaseDir    string
	Signatures []Signature // usually 1, but a target can have >1 soft-404 shape (e.g. different for /api/ vs /)
	// dynamic holds, per status code, a token-vocabulary model of the
	// "not found" responses. It is only built when the probes for that
	// status do NOT share one stable shape (see Unstable).
	dynamic map[int]*vocabModel
	// unstable is set when same-status probes disagree in shape, even if
	// there were too few of them to build a vocabulary model.
	unstable bool
}

// Unstable reports whether this directory's "not found" responses differ
// from each other beyond what shape hashing tolerates (rotating content,
// per-request tokens on a short page, randomized recommendations). Callers
// can use it to send more calibration probes and to warn the operator.
func (b *Baseline) Unstable() bool {
	return b != nil && (b.unstable || len(b.dynamic) > 0)
}

// CatchAll reports whether this directory answers paths that cannot exist
// with a success status (2xx) — typical of single-page apps and catch-all
// routers. Under such a directory every page looks like a "directory", so
// callers should not recurse on content type alone.
func (b *Baseline) CatchAll() bool {
	if b == nil {
		return false
	}
	for _, sig := range b.Signatures {
		if sig.Status >= 200 && sig.Status < 300 {
			return true
		}
	}
	for st := range b.dynamic {
		if st >= 200 && st < 300 {
			return true
		}
	}
	return false
}

// vocabModel describes a family of dynamic "not found" responses by the
// words they are made of rather than by their shape.
type vocabModel struct {
	vocab     map[string]struct{} // every token seen in any probe
	threshold float64             // novelty at or below this is "still the not-found page"
}

const (
	// minDynamicProbes is the fewest same-status probes needed before a
	// vocabulary model is trusted.
	minDynamicProbes = 3
	// noveltyMargin is added to the highest novelty any probe showed
	// against the others. A not-found page built from the same template
	// and vocabulary stays under it; a real page brings its own words.
	noveltyMargin = 0.15
)

// Signature is one observed (status, size-bucket, simhash) combination.
//
// rawBody/probeToken/probeSeg retain one representative calibration probe
// (body capped at maxTemplateBody) so Classify can re-derive this
// baseline's hash with the CANDIDATE's word also redacted — the symmetric
// check that defeats chrome-collision false positives (see Classify). Hash
// stays as the cheap first-pass filter (candidate-word-independent), so the
// expensive symmetric re-hash only runs for the small fraction of
// candidates that the cheap filter flags as potentially interesting.
type Signature struct {
	Status     int
	Size       int
	Hash       uint64
	rawBody    []byte
	probeToken string
	probeSeg   string
}

// maxTemplateBody caps the representative probe body stored per signature.
// Soft-404 templates are small; 64 KiB is far more than enough to
// fingerprint one, and it bounds memory even with deep recursion × several
// signatures per directory.
const maxTemplateBody = 64 * 1024

// Verdict is the analyzer's classification of a single response.
type Verdict struct {
	Interesting bool
	Reason      string // human-readable justification, e.g. "status 200, shape differs from baseline"
	ClusterKey  uint64 // responses with the same ClusterKey are near-duplicates
}

// simThreshold is the Hamming-distance cutoff (out of 64 bits) below which
// two bodies are considered "the same template". Measured empirically: two
// realistic templated pages differing only in a title + date (each
// appearing twice) land around Hamming 6; genuinely unrelated content lands
// in the high 30s/40s. 8 keeps a comfortable margin above the former while
// staying far below the latter.
const simThreshold = 8

// Calibrator holds learned baselines per base directory and is safe for
// concurrent read access once calibration completes (calibration itself is
// sequential per directory).
type Calibrator struct {
	baselines map[string]*Baseline
}

func NewCalibrator() *Calibrator {
	return &Calibrator{baselines: make(map[string]*Baseline)}
}

// RandomToken produces a path segment that will not exist on any real
// target, used to sample the server's "not found" behavior honestly.
// Exported so callers (discover) can build a batch of probe requests to
// fire concurrently, rather than calibration forcing one request at a time.
func RandomToken() string {
	const letters = "abcdefghijklmnopqrstuvwxyz0123456789"
	b := make([]byte, 12)
	for i := range b {
		b[i] = letters[rand.Intn(len(letters))]
	}
	return "zz" + string(b) + "zz"
}

// Probe pairs one calibration request's token with its response, so Learn
// can redact the right token from the right body.
type Probe struct {
	Token string
	Resp  engine.Response
}

// Learn builds and stores the soft-404 baseline for baseDir from a batch of
// already-fetched calibration probes.
//
// This replaced an earlier Calibrate(baseDir, n, fetch) method that took a
// synchronous fetch callback and looped n times *sequentially* — forcing n
// network round-trips back-to-back for every single directory scanned, for
// no reason: the probes don't depend on each other. Separating "decide what
// to probe" (RandomToken) from "learn from what came back" (Learn) lets the
// caller fetch all n probes concurrently (see engine.DoAll) and hand the
// results here as a batch.
func (c *Calibrator) Learn(baseDir string, probes []Probe) *Baseline {
	baseDir = normalizeDir(baseDir)
	seen := make(map[string]Signature)
	for _, p := range probes {
		if p.Resp.Err != nil {
			continue // transient errors during calibration are skipped, not fatal
		}
		probePath := joinDir(baseDir, p.Token)
		// Redact both the full probe path and the bare token, mirroring
		// exactly what Classify redacts (full path + last segment) so the
		// two sides normalize identically and aren't thrown off by, e.g., a
		// leftover "/" where the token used to be.
		sig := Signature{
			Status:     p.Resp.Status,
			Size:       sizeBucket(p.Resp.Length),
			Hash:       SimHash(p.Resp.Body, probePath, p.Token),
			rawBody:    capBytes(p.Resp.Body, maxTemplateBody),
			probeToken: probePath,
			probeSeg:   p.Token,
		}
		key := fmt.Sprintf("%d:%d", sig.Status, sig.Size)
		seen[key] = sig // last one wins per bucket; shape compared via Hamming at classify time
	}
	b := &Baseline{BaseDir: baseDir}
	for _, sig := range seen {
		b.Signatures = append(b.Signatures, sig)
	}
	b.dynamic, b.unstable = buildDynamicModels(baseDir, probes)
	if len(b.Signatures) == 0 {
		// Target never responded during calibration (all errors) — treat
		// everything as potentially interesting rather than silently
		// dropping the directory.
		b.Signatures = nil
	}
	c.baselines[baseDir] = b
	return b
}

// Classify judges whether resp looks like a genuine hit or matches the
// learned soft-404 baseline for its base directory. path is the exact
// candidate path that was requested (e.g. "/admin" or the fuzzed
// word) — it is redacted from the body before hashing, since a "not
// found" template commonly echoes the requested path/segment back
// verbatim, which would otherwise make every miss look unique.
func (c *Calibrator) Classify(baseDir, path string, resp engine.Response) Verdict {
	baseDir = normalizeDir(baseDir)
	echoed := echoedPath(path)
	hash := SimHash(resp.Body, echoed, lastSegment(echoed))
	b := c.baselines[baseDir]

	if resp.Err != nil {
		return Verdict{Interesting: false, Reason: "request error: " + resp.Err.Error(), ClusterKey: hash}
	}

	// 429 means the target refused to answer (rate limiting), still, after
	// the engine's backoff and retry. It says nothing about the path.
	if resp.Status == 429 {
		return Verdict{Interesting: false, Reason: "rate limited (429) — the target did not answer for this path", ClusterKey: hash}
	}

	// A 404 or 410 is the definition of "not found": never a discovery on
	// its own, whatever the calibrated baseline looks like. This matters
	// when a site's not-found answer is a soft-200 (single-page apps, many
	// Next.js sites): the baseline is then a 200 shape, so a genuine hard
	// 404 for a truly-absent path looks "different from the baseline" and
	// floods the report (seen live: /_next, /sitemap.xml reported as hits).
	// -mc 404 can still surface them when an operator explicitly wants them.
	if resp.Status == 404 || resp.Status == 410 {
		return Verdict{Interesting: false, Reason: fmt.Sprintf("not found (%d)", resp.Status), ClusterKey: hash}
	}

	// Hard-404s with no baseline match are boring regardless of calibration.
	if b == nil {
		return Verdict{Interesting: true, Reason: "no baseline (uncalibrated directory)", ClusterKey: hash}
	}

	// Note: we deliberately do NOT require resp.Length's size bucket to match
	// the baseline's here. Paths of different lengths legitimately produce
	// slightly different body sizes for the *same* soft-404 template (the
	// echoed path is part of the body), so shape (hash) is the authoritative
	// signal; size bucket is only used to deduplicate signatures during
	// Calibrate itself.
	// Cheap first pass: candidate hash (its own path redacted) vs the
	// baseline's stored hash (the probe's path redacted). Matches the vast
	// majority of real soft-404s instantly.
	for _, sig := range b.Signatures {
		if sig.Status == resp.Status && Hamming(sig.Hash, hash) <= simThreshold {
			return Verdict{Interesting: false, Reason: fmt.Sprintf("matches soft-404 baseline (status %d, shape dist %d)", sig.Status, Hamming(sig.Hash, hash)), ClusterKey: hash}
		}
	}

	// Symmetric second pass: only reached for candidates the cheap pass
	// flagged. The cheap pass can produce a false positive when the
	// candidate WORD coincidentally collides with the template's own fixed
	// chrome text — e.g. fuzzing "page" against a "Page not found"
	// template, or "ref" against "ref=...": the candidate side redacts
	// that word (turning "Page not found" into "~ not found") while the
	// baseline, calibrated with random tokens that never collide, kept it
	// — so an otherwise-identical soft-404 looks different. Here we redact
	// the CANDIDATE's word from the baseline body TOO, so the collision
	// cancels out on both sides; a genuine hit (real content, not the
	// template at all) still differs and stays flagged. This is the fix
	// for the dominant remaining false-positive class found in the
	// head-to-head comparison against ffuf/katana on a real wordlist.
	echoedSeg := lastSegment(echoed)
	candCapped := SimHash(capBytes(resp.Body, maxTemplateBody), echoed, echoedSeg)
	for _, sig := range b.Signatures {
		if sig.Status != resp.Status || len(sig.rawBody) == 0 {
			continue
		}
		baseAdj := SimHash(sig.rawBody, sig.probeToken, sig.probeSeg, echoed, echoedSeg)
		if Hamming(baseAdj, candCapped) <= simThreshold {
			return Verdict{Interesting: false, Reason: fmt.Sprintf("matches soft-404 baseline after symmetric redaction (status %d, shape dist %d) — candidate word collided with template chrome", sig.Status, Hamming(baseAdj, candCapped)), ClusterKey: hash}
		}
	}

	// Dynamic-baseline pass: when this directory's not-found responses do
	// not share one stable shape, shape hashing cannot recognise them, and
	// every miss would be reported. Judge by vocabulary instead: a response
	// made almost entirely of words already seen in the not-found probes is
	// another not-found page.
	if m := b.dynamic[resp.Status]; m != nil {
		toks := tokenSet(capBytes(resp.Body, maxTemplateBody), echoed, echoedSeg)
		if len(toks) > 0 {
			novel := 0
			for t := range toks {
				if _, ok := m.vocab[t]; !ok {
					novel++
				}
			}
			ratio := float64(novel) / float64(len(toks))
			if ratio <= m.threshold {
				return Verdict{Interesting: false, Reason: fmt.Sprintf("matches dynamic soft-404 baseline (status %d, %.0f%% new words, limit %.0f%%)", resp.Status, 100*ratio, 100*m.threshold), ClusterKey: hash}
			}
		}
	}

	// Redirects to a login/error page are often soft-404s in disguise —
	// flag as lower-confidence rather than dropping, since this is common
	// on auth-gated apps and worth a human glance. BUT suppress a pure
	// path-normalization redirect: a 3xx whose target is just the
	// requested path with consecutive slashes collapsed is the web
	// server's own path cleaning (net/http's ServeMux, nginx merge_slashes,
	// etc.), triggered by a malformed wordlist entry containing "//" (e.g.
	// SecLists' "render/https://www.google.com"), not a real resource. A
	// meaningful redirect — "/admin" -> "/login", or "/foo" -> "/foo/"
	// revealing a directory — changes the path in a way slash-collapsing
	// alone doesn't, so those are still reported.
	if resp.Status >= 300 && resp.Status < 400 {
		if isSlashNormalizationRedirect(echoed, resp.RedirectTo) {
			return Verdict{Interesting: false, Reason: "path-normalization redirect (server collapsed // in the requested path), not a real resource", ClusterKey: hash}
		}
		return Verdict{Interesting: true, Reason: fmt.Sprintf("redirect (%d) -> %s, not in baseline", resp.Status, resp.RedirectTo), ClusterKey: hash}
	}

	return Verdict{Interesting: true, Reason: fmt.Sprintf("status %d does not match any calibrated baseline shape", resp.Status), ClusterKey: hash}
}

// isSlashNormalizationRedirect reports whether a redirect from reqPath to
// location is nothing but the server collapsing duplicate slashes in the
// requested path — a mechanical artifact, not a navigation to a different
// resource. True only when the two paths differ AND become identical once
// consecutive slashes are collapsed (so a trailing-slash-added directory
// redirect, "/foo" -> "/foo/", is NOT matched and stays reportable).
func isSlashNormalizationRedirect(reqPath, location string) bool {
	loc := pathOnly(location)
	if loc == "" || loc == reqPath {
		return false
	}
	return collapseSlashes(reqPath) == collapseSlashes(loc) && reqPath != loc
}

// pathOnly extracts the path portion of a possibly-absolute-or-relative URL
// reference (dropping scheme+host, query, and fragment), without importing
// net/url for this one small job.
func pathOnly(ref string) string {
	if i := strings.Index(ref, "://"); i >= 0 {
		rest := ref[i+3:]
		if j := strings.IndexByte(rest, '/'); j >= 0 {
			ref = rest[j:]
		} else {
			return "/"
		}
	}
	if i := strings.IndexAny(ref, "?#"); i >= 0 {
		ref = ref[:i]
	}
	return ref
}

// collapseSlashes replaces runs of consecutive '/' with a single '/'. A
// trailing slash is preserved (it's significant: it distinguishes a
// directory redirect from a slash-cleaning one).
func collapseSlashes(p string) string {
	if !strings.Contains(p, "//") {
		return p
	}
	var b strings.Builder
	b.Grow(len(p))
	prevSlash := false
	for i := 0; i < len(p); i++ {
		c := p[i]
		if c == '/' {
			if prevSlash {
				continue
			}
			prevSlash = true
		} else {
			prevSlash = false
		}
		b.WriteByte(c)
	}
	return b.String()
}

// capBytes returns b unchanged when it's already within n (soft-404 bodies,
// the common case, are tiny), otherwise a COPY of its first n bytes — a
// copy rather than a sub-slice so truncating a large body doesn't leave the
// stored baseline pinning the whole original response via a shared backing
// array.
func capBytes(b []byte, n int) []byte {
	if len(b) <= n {
		return b
	}
	out := make([]byte, n)
	copy(out, b[:n])
	return out
}

// sizeBucket coarsens length so that +/- a few bytes of per-request noise
// (e.g. an echoed random token in the path) doesn't create a new bucket.
func sizeBucket(n int) int {
	switch {
	case n < 256:
		return n // small pages: exact match matters more
	case n < 4096:
		return (n / 32) * 32
	default:
		return (n / 256) * 256
	}
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

// lastSegment returns the final path component, e.g. "/a/b/c" -> "c", so the
// bare segment name (without slashes) can also be redacted — templates often
// echo just the segment rather than the full path.
func lastSegment(path string) string {
	path = strings.TrimRight(path, "/")
	if i := strings.LastIndex(path, "/"); i >= 0 {
		return path[i+1:]
	}
	return path
}

// echoedPath strips a query-string suffix from a candidate path, giving
// back the portion a server actually sees as r.URL.Path (and so the
// portion a "page X not found" template would actually echo back).
//
// Found against a real wordlist (SecLists' common.txt) containing entries
// like "dns-query?dns=AAAA...": joinDir concatenates this directly into
// the request URL, and Go's HTTP layer correctly treats everything after
// "?" as a query string — so the server only ever echoes "/dns-query" in
// its response, never the literal "?dns=AAAA..." suffix. Classify was
// redacting the FULL candidate string including the query part, which
// never appears in the body verbatim, so the redaction silently matched
// nothing, left "/dns-query" un-redacted in the normalized text, and
// desynced that candidate's hash from the baseline — a real false
// positive on roughly 0.06% of a 4,751-word real-world list (3 entries),
// but each one also triggered the costly cascade of looking like a new
// "directory" worth recursing into.
func echoedPath(path string) string {
	if i := strings.IndexByte(path, '?'); i >= 0 {
		return path[:i]
	}
	return path
}

// buildDynamicModels groups probes by status and, for each status whose
// probes do not all share one shape, builds a vocabulary model.
func buildDynamicModels(baseDir string, probes []Probe) (map[int]*vocabModel, bool) {
	type probeInfo struct {
		hash uint64
		toks map[string]struct{}
	}
	byStatus := map[int][]probeInfo{}
	for _, p := range probes {
		if p.Resp.Err != nil {
			continue
		}
		probePath := joinDir(baseDir, p.Token)
		byStatus[p.Resp.Status] = append(byStatus[p.Resp.Status], probeInfo{
			hash: SimHash(p.Resp.Body, probePath, p.Token),
			toks: tokenSet(capBytes(p.Resp.Body, maxTemplateBody), probePath, p.Token),
		})
	}
	var out map[int]*vocabModel
	unstable := false
	for status, infos := range byStatus {
		stable := true
		for i := 1; i < len(infos) && stable; i++ {
			if Hamming(infos[0].hash, infos[i].hash) > simThreshold {
				stable = false
			}
		}
		if stable {
			continue
		}
		unstable = true
		if len(infos) < minDynamicProbes {
			continue // caller should send more probes and Learn again
		}
		// How many probes contain each token.
		counts := map[string]int{}
		for _, in := range infos {
			for t := range in.toks {
				counts[t]++
			}
		}
		// Leave-one-out novelty: the share of a probe's words that no
		// other probe has. Its maximum is how "new" a not-found page can
		// look on this target.
		maxNovelty := 0.0
		for _, in := range infos {
			if len(in.toks) == 0 {
				continue
			}
			unique := 0
			for t := range in.toks {
				if counts[t] == 1 {
					unique++
				}
			}
			if r := float64(unique) / float64(len(in.toks)); r > maxNovelty {
				maxNovelty = r
			}
		}
		m := &vocabModel{vocab: make(map[string]struct{}, len(counts)), threshold: maxNovelty + noveltyMargin}
		for t := range counts {
			m.vocab[t] = struct{}{}
		}
		if out == nil {
			out = map[int]*vocabModel{}
		}
		out[status] = m
	}
	return out, unstable
}

// tokenSet returns the distinct words of body after the same redaction
// Normalize applies (volatile values and the requested path removed).
// Tokens containing a digit are dropped: counters, ids, timestamps and
// hashes change per request and would read as "new words" every time.
func tokenSet(body []byte, extra ...string) map[string]struct{} {
	norm := bytes.ToLower(Normalize(body, extra...))
	out := map[string]struct{}{}
	start, hasDigit := -1, false
	flush := func(end int) {
		if start >= 0 && !hasDigit {
			if n := end - start; n >= 2 && n <= 24 {
				out[string(norm[start:end])] = struct{}{}
			}
		}
		start, hasDigit = -1, false
	}
	for i, c := range norm {
		switch {
		case c >= '0' && c <= '9':
			if start < 0 {
				start = i
			}
			hasDigit = true
		case (c >= 'a' && c <= 'z') || c >= 0x80:
			if start < 0 {
				start = i
			}
		default:
			flush(i)
		}
	}
	flush(len(norm))
	return out
}
