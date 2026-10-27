// Package analyze is hellhound's core differentiator versus ffuf: instead of
// requiring the operator to manually pass -fc/-fs after eyeballing a few
// responses, it probes the target with random, almost-certainly-nonexistent
// paths up front, learns what "not found" looks like per base directory
// (status code + size bucket + SimHash shape), and then classifies every
// real result against that baseline. It also clusters near-identical hits
// together so one template rendered 40 times doesn't read as 40 findings.
package analyze

import (
	"fmt"
	"math/rand"
	"strings"

	"hellhound/internal/engine"
)

// Baseline is the learned "not found" fingerprint for one base path.
type Baseline struct {
	BaseDir    string
	Signatures []Signature // usually 1, but a target can have >1 soft-404 shape (e.g. different for /api/ vs /)
}

// Signature is one observed (status, size-bucket, simhash) combination.
type Signature struct {
	Status int
	Size   int
	Hash   uint64
}

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
			Status: p.Resp.Status,
			Size:   sizeBucket(p.Resp.Length),
			Hash:   SimHash(p.Resp.Body, probePath, p.Token),
		}
		key := fmt.Sprintf("%d:%d", sig.Status, sig.Size)
		seen[key] = sig // last one wins per bucket; shape compared via Hamming at classify time
	}
	b := &Baseline{BaseDir: baseDir}
	for _, sig := range seen {
		b.Signatures = append(b.Signatures, sig)
	}
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
	hash := SimHash(resp.Body, path, lastSegment(path))
	b := c.baselines[baseDir]

	if resp.Err != nil {
		return Verdict{Interesting: false, Reason: "request error: " + resp.Err.Error(), ClusterKey: hash}
	}

	// Hard-404s with no baseline match are boring regardless of calibration.
	if b == nil {
		return Verdict{Interesting: resp.Status != 404, Reason: "no baseline (uncalibrated directory)", ClusterKey: hash}
	}

	// Note: we deliberately do NOT require resp.Length's size bucket to match
	// the baseline's here. Paths of different lengths legitimately produce
	// slightly different body sizes for the *same* soft-404 template (the
	// echoed path is part of the body), so shape (hash) is the authoritative
	// signal; size bucket is only used to deduplicate signatures during
	// Calibrate itself.
	for _, sig := range b.Signatures {
		if sig.Status == resp.Status && Hamming(sig.Hash, hash) <= simThreshold {
			return Verdict{Interesting: false, Reason: fmt.Sprintf("matches soft-404 baseline (status %d, shape dist %d)", sig.Status, Hamming(sig.Hash, hash)), ClusterKey: hash}
		}
	}

	// Redirects to a login/error page are often soft-404s in disguise —
	// flag as lower-confidence rather than dropping, since this is common
	// on auth-gated apps and worth a human glance.
	if resp.Status >= 300 && resp.Status < 400 {
		return Verdict{Interesting: true, Reason: fmt.Sprintf("redirect (%d) -> %s, not in baseline", resp.Status, resp.RedirectTo), ClusterKey: hash}
	}

	return Verdict{Interesting: true, Reason: fmt.Sprintf("status %d does not match any calibrated baseline shape", resp.Status), ClusterKey: hash}
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
