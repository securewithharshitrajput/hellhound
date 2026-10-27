package analyze

import (
	"fmt"
	"strings"
	"testing"

	"hellhound/internal/engine"
)

// softFake simulates a server whose "not found" page embeds a per-request
// timestamp and random request-id, exactly the case that defeats naive
// exact-match 404 detection.
func softFake(path string) (engine.Response, error) {
	if path == "/app.js" || path == "/admin" {
		return engine.Response{Status: 200, Body: []byte("real content for " + path), Length: 20}, nil
	}
	body := []byte(fmt.Sprintf("<html><body>Sorry, the page %s could not be found. ref=%08x ts=1732012345</body></html>", path, hashPath(path)))
	return engine.Response{Status: 200, Body: body, Length: len(body)}, nil
}

func hashPath(p string) uint32 {
	var h uint32 = 2166136261
	for _, c := range p {
		h ^= uint32(c)
		h *= 16777619
	}
	return h
}

func TestCalibrationFiltersSoftNotFound(t *testing.T) {
	c := NewCalibrator()
	probes := make([]Probe, 10)
	for i := range probes {
		tok := RandomToken()
		resp, _ := softFake("/" + tok)
		probes[i] = Probe{Token: tok, Resp: resp}
	}
	c.Learn("/", probes)

	// A genuinely nonexistent path should be classified boring.
	resp, _ := softFake("/totally-made-up-path-xyz")
	v := c.Classify("/", "/totally-made-up-path-xyz", resp)
	if v.Interesting {
		t.Errorf("expected soft-404 to be filtered, got interesting=%v reason=%q", v.Interesting, v.Reason)
	}

	// A real hit should be classified interesting.
	resp2, _ := softFake("/admin")
	v2 := c.Classify("/", "/admin", resp2)
	if !v2.Interesting {
		t.Errorf("expected real hit /admin to be interesting, got reason=%q", v2.Reason)
	}
}

// TestRedactionDoesNotMangleUnrelatedSubstrings locks in a real bug fix: a
// bare substring replace of a short fuzzed word like "admin" would also
// strike it out of unrelated static text that happens to contain it as a
// substring, e.g. "administrator" inside a WAF's static deny page. That
// desyncs the hash of a page that is actually byte-identical to the
// calibration baseline, producing a false positive on every word that
// happens to be a prefix of some other word in the page.
func TestRedactionDoesNotMangleUnrelatedSubstrings(t *testing.T) {
	body := []byte("Contact your administrator for access. Administration staff only.")
	got := Normalize(body, "/admin", "admin")
	want := string(body) // nothing should change: "admin" never appears as a standalone word here
	if string(got) != want {
		t.Errorf("Normalize mangled unrelated text:\n got:  %q\n want: %q", got, want)
	}

	// Sanity check the other direction: "admin" AS A STANDALONE WORD must
	// still be redacted (this is the whole point of redaction).
	standalone := []byte("Welcome, admin! You have admin access.")
	got2 := Normalize(standalone, "admin")
	if strings.Contains(string(got2), "admin") {
		t.Errorf("expected standalone 'admin' to be redacted, got %q", got2)
	}
}

// TestRedactionOrderHandlesHexLikeWords locks in a real bug fix found by
// stress-testing against a 50,000-word random wordlist: when a fuzzed
// word itself happens to look like a generic volatile token (6+ hex
// characters, here), volatileRe used to strike it out BEFORE the
// path-specific redaction ran, consuming the bare word without its
// leading "/" and leaving that slash stranded — a real ~0.1%
// false-positive rate on soft-404 pages that echo the requested path.
func TestRedactionOrderHandlesHexLikeWords(t *testing.T) {
	soft404 := func(path string) []byte {
		return []byte(fmt.Sprintf(`<html><body><h1>Oops!</h1><p>We could not find the page you were looking for: %s</p>
		<p>Request ID: 9793bb1f</p><p>Server time: 2026-10-27T17:51:42+05:30</p>
		<p>If you believe this is an error, please contact support.</p></body></html>`, path))
	}
	c := NewCalibrator()
	var probes []Probe
	for i := 0; i < 6; i++ {
		tok := RandomToken()
		probes = append(probes, Probe{Token: tok, Resp: fakeResp(200, soft404("/"+tok))})
	}
	c.Learn("/", probes)

	// A fuzzed word that happens to be 6+ hex-looking characters — exactly
	// the shape that collided with volatileRe's generic pattern.
	v := c.Classify("/", "/004cc4", fakeResp(200, soft404("/004cc4")))
	if v.Interesting {
		t.Errorf("hex-like candidate word wrongly classified as interesting: %q", v.Reason)
	}
}

func TestSimHashSimilarity(t *testing.T) {
	a := SimHash([]byte("the quick brown fox jumps over the lazy dog ref=12345678 ts=2024-01-01 10:00:00"))
	b := SimHash([]byte("the quick brown fox jumps over the lazy dog ref=87654321 ts=2024-06-15 09:30:00"))
	c := SimHash([]byte("completely different content about something else entirely unrelated to foxes"))

	if d := Hamming(a, b); d > simThreshold {
		t.Errorf("expected near-identical templated bodies to be close, got Hamming=%d", d)
	}
	if d := Hamming(a, c); d <= simThreshold {
		t.Errorf("expected unrelated bodies to be far apart, got Hamming=%d", d)
	}
}

func TestClusterFindings(t *testing.T) {
	mk := func(url string, body string) Finding {
		h := SimHash([]byte(body))
		return Finding{URL: url, Status: 200, Verdict: Verdict{Interesting: true, ClusterKey: h}}
	}
	// Realistic-length bodies: a shared template shell with only the title
	// and date varying, same as two posts rendered by the same blog engine.
	// (A toy 9-word fixture would make 1-2 differing words dominate the
	// shingle set and wrongly look like a big change — real templates carry
	// enough shared boilerplate that a couple of varying words stays a small
	// fraction of the whole, which is exactly the case clustering targets.)
	post := func(title, date string) string {
		return fmt.Sprintf(`<html><head><title>%s - My Blog</title></head><body>
		<nav><a href="/">Home</a> <a href="/about">About</a> <a href="/archive">Archive</a></nav>
		<article><h1>%s</h1><p class="meta">Posted on %s by the author</p>
		<div class="content">This is a sample blog post body with some filler
		text that stays the same across every post rendered by this template,
		since only the title and date actually change between entries.</div>
		<footer>Copyright %s - All rights reserved</footer></article></body></html>`, title, title, date, date)
	}
	findings := []Finding{
		mk("/post/1", post("First Post", "2024-01-01")),
		mk("/post/2", post("Second Post", "2024-02-02")),
		mk("/admin/config", "totally unrelated admin configuration panel with login form and settings table that has nothing to do with blog posts"),
	}
	clusters := ClusterFindings(findings)
	if len(clusters) != 2 {
		t.Fatalf("expected 2 clusters (2 blog posts + 1 admin page), got %d", len(clusters))
	}
	if len(clusters[0].Members) != 2 {
		t.Errorf("expected largest cluster to have 2 members, got %d", len(clusters[0].Members))
	}
}

// TestClusterFindingsDoesNotMergeDifferentStatusCodes locks in a real bug
// fix: a 500 error page can share almost all of its HTML chrome (same
// nav/footer/layout) with an unrelated 200 page rendered by the same site
// template. Clustering on body shape alone would bury that 500 as "+1
// similar" under the 200's representative, hiding a finding that matters.
func TestClusterFindingsDoesNotMergeDifferentStatusCodes(t *testing.T) {
	shell := func(status string) string {
		return fmt.Sprintf(`<html><head><title>My Site</title></head><body>
		<nav><a href="/">Home</a> <a href="/about">About</a></nav>
		<main><h1>%s</h1><p>Some shared layout text that every page on this
		site renders identically, since it comes from the same base template
		regardless of what the page actually is or what happened.</p></main>
		<footer>Copyright 2024 - All rights reserved</footer></body></html>`, status)
	}
	mk := func(url string, status int, body string) Finding {
		return Finding{URL: url, Status: status, Verdict: Verdict{Interesting: true, ClusterKey: SimHash([]byte(body))}}
	}
	findings := []Finding{
		mk("/ok-page", 200, shell("Everything is fine")),
		mk("/crash", 500, shell("Internal Server Error")),
	}
	clusters := ClusterFindings(findings)
	if len(clusters) != 2 {
		t.Fatalf("expected the 200 and 500 to stay in separate clusters despite near-identical body shape, got %d cluster(s)", len(clusters))
	}
	for _, c := range clusters {
		if len(c.Members) != 1 {
			t.Errorf("expected each cluster to have exactly 1 member, got %d (status %d merged with something)", len(c.Members), c.Representative.Status)
		}
	}
}
