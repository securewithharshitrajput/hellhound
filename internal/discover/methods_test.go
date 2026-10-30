package discover

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestScanDangerousMethodsFlagsOnlyRealOnes verifies that an endpoint
// advertising PUT/DELETE/PATCH is flagged, an endpoint advertising only
// GET/POST is NOT flagged (every REST API ever would be a false positive
// otherwise), and TRACE alone collapses to "low" severity rather than
// "medium" since on its own it's just an XST primitive, not an unauth
// write path.
func TestScanDangerousMethodsFlagsOnlyRealOnes(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "OPTIONS" {
			w.Write([]byte("ok"))
			return
		}
		switch r.URL.Path {
		case "/dangerous":
			w.Header().Set("Allow", "GET, POST, PUT, DELETE, PATCH, OPTIONS")
			w.WriteHeader(204)
		case "/trace-only":
			w.Header().Set("Allow", "GET, POST, TRACE, OPTIONS")
			w.WriteHeader(204)
		case "/safe":
			w.Header().Set("Allow", "GET, POST, OPTIONS")
			w.WriteHeader(204)
		case "/no-allow":
			// No Allow header at all; must not be flagged.
			w.WriteHeader(204)
		default:
			w.WriteHeader(405)
		}
	}))
	defer srv.Close()

	urls := []string{
		srv.URL + "/dangerous",
		srv.URL + "/trace-only",
		srv.URL + "/safe",
		srv.URL + "/no-allow",
	}
	findings := ScanDangerousMethods(context.Background(), testEngine(), urls)

	byURL := map[string]SecurityFinding{}
	for _, f := range findings {
		byURL[f.URL] = f
	}

	if _, ok := byURL[srv.URL+"/dangerous"]; !ok {
		t.Errorf("expected /dangerous (PUT+DELETE+PATCH) to be flagged, got %v", findings)
	} else if byURL[srv.URL+"/dangerous"].Severity != "medium" {
		t.Errorf("PUT+DELETE+PATCH severity should be medium, got %q", byURL[srv.URL+"/dangerous"].Severity)
	}

	if f, ok := byURL[srv.URL+"/trace-only"]; !ok {
		t.Errorf("expected /trace-only to be flagged, got %v", findings)
	} else if f.Severity != "low" {
		t.Errorf("TRACE-only severity should be low (XST only, not write), got %q", f.Severity)
	}

	if _, ok := byURL[srv.URL+"/safe"]; ok {
		t.Errorf("/safe (GET+POST only) was falsely flagged — this would flag every REST API ever: %v", byURL[srv.URL+"/safe"])
	}
	if _, ok := byURL[srv.URL+"/no-allow"]; ok {
		t.Errorf("/no-allow (missing Allow header) was falsely flagged")
	}
}

// TestScanDangerousMethodsDedupesURLs confirms duplicate URLs don't produce
// duplicate findings (common when a cluster contains many identical hits).
func TestScanDangerousMethodsDedupesURLs(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Allow", "GET, PUT")
		w.WriteHeader(204)
	}))
	defer srv.Close()
	urls := []string{srv.URL + "/a", srv.URL + "/a", srv.URL + "/a"}
	findings := ScanDangerousMethods(context.Background(), testEngine(), urls)
	if len(findings) != 1 {
		t.Errorf("expected 1 deduped finding, got %d: %v", len(findings), findings)
	}
}

func TestParseAllowHeader(t *testing.T) {
	got := parseAllowHeader("GET, post , PUT ,  OPTIONS")
	for _, m := range []string{"GET", "POST", "PUT", "OPTIONS"} {
		if !got[m] {
			t.Errorf("expected %q to parse, got %v", m, got)
		}
	}
}
