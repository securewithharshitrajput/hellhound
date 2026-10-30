package discover

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestScanSensitiveReportsOnlyConfirmedHits verifies the sensitive-file
// detector: real content behind a sensitive path must be flagged, and a
// soft-404 (200 with HTML but no file-shaped markers) at the same path must
// NOT be. This is the critical invariant — a target that returns 200 for
// everything would otherwise flood the report with phantom "exposed .env"
// findings.
func TestScanSensitiveReportsOnlyConfirmedHits(t *testing.T) {
	mux := http.NewServeMux()
	// A real .env file: KEY=value syntax that passes the marker check.
	mux.HandleFunc("/.env", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("APP_ENV=production\nDB_PASSWORD=hunter2\nSECRET_KEY=abc123"))
	})
	// A real .git/config: ini-style syntax that passes the marker check.
	mux.HandleFunc("/.git/config", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("[core]\n\trepositoryformatversion = 0\n[remote \"origin\"]\n\turl = git@github.com:x/y"))
	})
	// Soft-404 for everything else: 200 + HTML, but no marker-matching content.
	// Critically, this includes paths like /credentials.json, /secrets.json
	// that we probe but should NOT flag.
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte("<html><body><h1>Page not found</h1><p>Sorry, nothing here.</p></body></html>"))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	findings := ScanSensitive(context.Background(), testEngine(), srv.URL)

	// Must find .env and .git/config and NOTHING ELSE despite 200s everywhere.
	gotTypes := map[string]bool{}
	for _, f := range findings {
		if f.Type != "sensitive-file" {
			t.Errorf("expected only sensitive-file findings, got %q", f.Type)
		}
		gotTypes[f.URL] = true
	}
	if !gotTypes[srv.URL+"/.env"] {
		t.Errorf("expected .env to be reported, findings: %v", findings)
	}
	if !gotTypes[srv.URL+"/.git/config"] {
		t.Errorf("expected .git/config to be reported, findings: %v", findings)
	}
	// Soft-404s must NOT produce false positives.
	for _, bad := range []string{"/credentials.json", "/secrets.json", "/aws.json", "/id_rsa"} {
		if gotTypes[srv.URL+bad] {
			t.Errorf("soft-404 at %s was falsely reported as sensitive — this would flood the report against real targets", bad)
		}
	}
}

// TestScanSensitiveEvidenceIsSafelyTruncated proves that even a huge
// matching body produces short, printable evidence — no 2MB SQL dump pasted
// into terminal output.
func TestScanSensitiveEvidenceIsSafelyTruncated(t *testing.T) {
	bigDump := make([]byte, 2*1024*1024)
	copy(bigDump, []byte("CREATE TABLE users (id INT, password VARCHAR(255));"))
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/backup.sql" {
			w.Write(bigDump)
			return
		}
		w.WriteHeader(404)
	}))
	defer srv.Close()

	findings := ScanSensitive(context.Background(), testEngine(), srv.URL)
	var found *SecurityFinding
	for i, f := range findings {
		if f.URL == srv.URL+"/backup.sql" {
			found = &findings[i]
			break
		}
	}
	if found == nil {
		t.Fatalf("expected /backup.sql to be reported, got %v", findings)
	}
	if len(found.Evidence) > 200 {
		t.Errorf("evidence should be short (got %d bytes) — a huge dump should not pollute output", len(found.Evidence))
	}
	if found.Severity != "high" {
		t.Errorf("sql dump should be severity 'high', got %q", found.Severity)
	}
}
