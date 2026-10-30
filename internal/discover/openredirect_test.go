package discover

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestScanOpenRedirectsFlagsReflectedExternal verifies the detector catches
// a real reflection (query param pasted straight into Location) and does
// NOT flag an endpoint that correctly validates the redirect to stay
// internal — the common correct implementation.
func TestScanOpenRedirectsFlagsReflectedExternal(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/vulnerable":
			// Reflects whatever the operator typed — classic open-redirect
			dest := r.URL.Query().Get("url")
			if dest != "" {
				w.Header().Set("Location", dest)
				w.WriteHeader(302)
				return
			}
		case "/safe":
			// Correctly rewrites any external destination to an internal path
			w.Header().Set("Location", "/dashboard")
			w.WriteHeader(302)
			return
		}
		w.WriteHeader(200)
	}))
	defer srv.Close()

	candidates := []string{
		srv.URL + "/vulnerable?url=https://legit.example.com/dashboard",
		srv.URL + "/safe?next=https://legit.example.com/dashboard",
		srv.URL + "/noparam", // no query at all, must be skipped
	}
	findings := ScanOpenRedirects(context.Background(), testEngine(), candidates)

	foundVuln := false
	for _, f := range findings {
		if strings.Contains(f.URL, "/vulnerable") {
			foundVuln = true
			if f.Severity != "medium" {
				t.Errorf("open-redirect severity should be medium, got %q", f.Severity)
			}
		}
		if strings.Contains(f.URL, "/safe") {
			t.Errorf("/safe (validated redirect) was falsely flagged — real app pattern misclassified: %v", f)
		}
	}
	if !foundVuln {
		t.Errorf("expected /vulnerable to be flagged as open-redirect, got %v", findings)
	}
}

// TestRedirectsExternally probes the location-classification helper
// independently — a protocol-relative // path pointing at the canary host
// is attacker-controllable even though it has no scheme.
func TestRedirectsExternally(t *testing.T) {
	cases := []struct {
		loc  string
		want bool
	}{
		{"https://example.org/path", true},
		{"//example.org/path", true}, // protocol-relative, browser treats as external
		{"https://trusted.internal/path", false},
		{"/dashboard", false},
		{"", false},
	}
	for _, c := range cases {
		if got := redirectsExternally(c.loc); got != c.want {
			t.Errorf("redirectsExternally(%q) = %v, want %v", c.loc, got, c.want)
		}
	}
}
