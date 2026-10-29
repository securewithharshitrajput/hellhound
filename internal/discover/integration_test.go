// End-to-end integration tests: a real httptest.Server + real Engine +
// real Discoverer, exercising scenarios that unit tests on individual
// functions can't catch — calibration and classification only show their
// real behavior when wired together against an actual server.
package discover

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/securewithharshitrajput/hellhound/internal/engine"
)

func testEngine() *engine.Engine {
	cfg := engine.DefaultConfig()
	cfg.Concurrency = 10
	cfg.Timeout = 5 * time.Second
	return engine.New(cfg)
}

// TestRedirectEverythingTargetDoesNotFloodFindings covers a very common
// real-world case ffuf/katana users hit constantly: a reverse proxy or
// load balancer that 301-redirects EVERY path (real or not) to HTTPS, or
// to a canonical host, with an identical tiny body regardless of whether
// the path exists. A tool that can't tell "every path redirects the same
// way" from "this specific path is interesting" floods the operator with
// one line per fuzzed word. Calibration should learn the redirect as the
// baseline and suppress it just like any other soft-404 shape.
func TestRedirectEverythingTargetDoesNotFloodFindings(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", "https://example.com"+r.URL.Path)
		w.WriteHeader(301)
		w.Write([]byte("Moved Permanently"))
	}))
	defer srv.Close()

	d := New(testEngine(), Options{
		BaseURL:      srv.URL,
		Wordlist:     []string{"admin", "backup", "config", "test", "login", "api", "secret"},
		CalibrationN: 6,
		MaxDepth:     0, // no recursion needed for this check
	})
	results, err := d.Run(context.Background(), "/")
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(results) != 0 {
		t.Errorf("expected 0 findings against a target that redirects everything identically, got %d: %+v", len(results), results)
	}
}

// TestAlwaysForbiddenTargetDoesNotFloodFindings covers a WAF/auth-gate
// scenario: every path, real or fake, comes back 403 with the same deny
// page. This should calibrate out exactly like a soft-404 does.
func TestAlwaysForbiddenTargetDoesNotFloodFindings(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(403)
		w.Write([]byte("<html><body>Access Denied by WAF policy. Contact your administrator for access.</body></html>"))
	}))
	defer srv.Close()

	d := New(testEngine(), Options{
		BaseURL:      srv.URL,
		Wordlist:     []string{"admin", "backup", "config", "test", "login", "api", "secret"},
		CalibrationN: 6,
		MaxDepth:     0,
	})
	results, err := d.Run(context.Background(), "/")
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(results) != 0 {
		t.Errorf("expected 0 findings against an always-403 WAF, got %d: %+v", len(results), results)
	}
}

// TestBinaryBodyDoesNotCrashAnalysis ensures a target returning raw binary
// (an image, a compiled asset, truncated/invalid UTF-8) is handled without
// panicking anywhere in the calibrate -> SimHash -> classify pipeline, and
// that a genuinely different binary file is still flagged as interesting
// against an otherwise-soft-404 baseline.
func TestBinaryBodyDoesNotCrashAnalysis(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("panic while handling binary bodies: %v", r)
		}
	}()

	binaryNotFound := []byte{0xff, 0xfe, 0x00, 0x01, 0x02, 0xc0, 0xc1, 0xf5, 0x00, 0x00, 0x00, 0x00, 0x89, 0x50, 0x4e, 0x47}
	binaryHit := []byte{0x50, 0x4b, 0x03, 0x04, 0x14, 0x00, 0x00, 0x00, 0x08, 0x00, 'z', 'i', 'p', '-', 'c', 'o', 'n', 't', 'e', 'n', 't', 's', '-', 'h', 'e', 'r', 'e'}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/real.bin" {
			w.Write(binaryHit)
			return
		}
		w.Write(binaryNotFound)
	}))
	defer srv.Close()

	d := New(testEngine(), Options{
		BaseURL:      srv.URL,
		Wordlist:     []string{"real", "fake1", "fake2"},
		Extensions:   []string{".bin"},
		CalibrationN: 6,
		MaxDepth:     0,
	})
	results, err := d.Run(context.Background(), "/")
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	found := false
	for _, r := range results {
		if strings.HasSuffix(r.URL, "/real.bin") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected /real.bin to be flagged as a real hit among binary soft-404 noise, results: %+v", results)
	}
}

// TestMaxDepthZeroMeansNoRecursion locks in a real bug fix: Options{}
// used to silently promote an explicit MaxDepth: 0 up to 3 (Go's int zero
// value couldn't distinguish "caller wants 0" from "caller left it
// unset"), so "-depth 0" recursed anyway. Here, a directory-like hit at
// the root ("/api") has its OWN real sub-hit ("/api/internal") that only
// a second scanDir pass would ever find — with MaxDepth: 0 honored
// correctly, that sub-hit must never appear.
func TestMaxDepthZeroMeansNoRecursion(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api":
			w.Write([]byte("<html><body>API index</body></html>"))
		case "/api/internal":
			w.Write([]byte("<html><body>Should never be reached with depth=0</body></html>"))
		default:
			w.WriteHeader(404)
		}
	}))
	defer srv.Close()

	d := New(testEngine(), Options{
		BaseURL:      srv.URL,
		Wordlist:     []string{"api", "internal"},
		CalibrationN: 3,
		MaxDepth:     0,
	})
	results, err := d.Run(context.Background(), "/")
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	for _, r := range results {
		if strings.Contains(r.URL, "/api/internal") {
			t.Fatalf("MaxDepth: 0 should mean NO recursion, but found %s (recursed into /api anyway)", r.URL)
		}
	}
	foundAPI := false
	for _, r := range results {
		if strings.HasSuffix(r.URL, "/api") {
			foundAPI = true
		}
	}
	if !foundAPI {
		t.Error("expected /api itself to still be found at the root level (depth=0 means no recursion, not no scanning)")
	}
}

// TestAllCalibrationProbesFailingWarnsLoudly locks in a real UX fix: a
// dead/unreachable/malformed target used to produce a confident-looking
// "0 findings, exit 0" with zero indication anything was wrong —
// indistinguishable from a genuinely clean scan. A target where every
// single calibration probe errors out (connection refused, here) must now
// trigger OnWarning instead of failing silently.
func TestAllCalibrationProbesFailingWarnsLoudly(t *testing.T) {
	var warnings []string
	d := New(testEngine(), Options{
		BaseURL:      "http://127.0.0.1:1", // nothing listens on port 1; connection refused
		Wordlist:     []string{"admin"},
		CalibrationN: 3,
		MaxDepth:     0,
		OnWarning: func(dir string, err error) {
			warnings = append(warnings, err.Error())
		},
	})
	_, err := d.Run(context.Background(), "/")
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(warnings) == 0 {
		t.Fatal("expected a warning when every calibration probe fails, got none")
	}
	if !strings.Contains(warnings[0], "all 3 calibration probes failed") {
		t.Errorf("warning text doesn't explain the failure clearly: %q", warnings[0])
	}
}

// TestPerDirectoryCalibrationAdaptsToDifferentTemplates is a core
// architectural claim that had never been directly tested: a real
// multi-tier app commonly has a totally different "not found" shape per
// section — an HTML 404 page on the static frontend, a JSON {"error":
// "not found"} on the API backend. Calibration happens once PER
// directory (a fresh Learn() call inside each scanDir), not once
// globally, so each section's noise should be filtered using ITS OWN
// baseline rather than whichever was learned first. This verifies both
// halves: genuine hits are found in each section, and section-appropriate
// noise is filtered in each section, including noise that is
// structurally similar to the OTHER section's real content (JSON-shaped
// noise under /api/ versus a JSON-shaped real hit also under /api/).
func TestPerDirectoryCalibrationAdaptsToDifferentTemplates(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/api":
			w.Write([]byte("<html><body>API index</body></html>"))
		case r.URL.Path == "/api/users":
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"users": [{"id": 1, "name": "alice"}, {"id": 2, "name": "bob"}]}`))
		case strings.HasPrefix(r.URL.Path, "/api/"):
			// JSON-shaped soft-404 under the API section.
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"error": "not found", "path": "` + r.URL.Path + `"}`))
		case r.URL.Path == "/admin":
			w.Write([]byte("<html><body><h1>Admin Panel</h1></body></html>"))
		default:
			// HTML-shaped soft-404 under the root section.
			w.Write([]byte("<html><body><h1>404</h1><p>Page " + r.URL.Path + " was not found on this server.</p></body></html>"))
		}
	}))
	defer srv.Close()

	d := New(testEngine(), Options{
		BaseURL:      srv.URL,
		Wordlist:     []string{"admin", "api", "users", "fakeword1", "fakeword2"},
		CalibrationN: 6,
		MaxDepth:     1, // allow recursion into /api so it gets its own calibration pass
	})
	results, err := d.Run(context.Background(), "/")
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	found := map[string]bool{}
	for _, r := range results {
		found[r.URL] = true
	}

	mustFind := []string{"/admin", "/api", "/api/users"}
	for _, want := range mustFind {
		if !found[srv.URL+want] {
			t.Errorf("expected to find %s, results: %+v", want, resultURLs(results))
		}
	}

	mustNotFind := []string{"/fakeword1", "/fakeword2", "/api/fakeword1", "/api/fakeword2"}
	for _, bad := range mustNotFind {
		if found[srv.URL+bad] {
			t.Errorf("wrongly flagged soft-404 noise as a finding: %s (calibration failed to adapt to this directory's template)", bad)
		}
	}
}

func resultURLs(results []Result) []string {
	out := make([]string, len(results))
	for i, r := range results {
		out[i] = r.URL
	}
	return out
}

// TestEmptyWordlistDoesNotPanic is a basic robustness check: calling Run
// with no words configured should calibrate (harmlessly) and return no
// results, not panic or hang.
func TestEmptyWordlistDoesNotPanic(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(404)
	}))
	defer srv.Close()

	d := New(testEngine(), Options{
		BaseURL:      srv.URL,
		Wordlist:     nil,
		CalibrationN: 3,
		MaxDepth:     0,
	})
	results, err := d.Run(context.Background(), "/")
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(results) != 0 {
		t.Errorf("expected 0 results with an empty wordlist, got %d", len(results))
	}
}
