package discover

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestVHostScanFindsRealVHostAmongDefaultNoise simulates a server that
// serves one generic "default site" page for any Host header it doesn't
// recognize, plus one real internal vhost ("admin-internal.corp.invalid")
// that serves different content. A tool that just diffs against a single
// hardcoded expectation would need the operator to notice the default
// page's shape by hand; this should find the one real vhost and nothing
// else, out of the calibration noise plus several decoy candidates.
func TestVHostScanFindsRealVHostAmongDefaultNoise(t *testing.T) {
	const realVHost = "admin-internal.corp.invalid"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Host == realVHost {
			w.Write([]byte("<html><body><h1>Internal Admin Console</h1><p>Restricted access panel for staff only, do not share this URL.</p></body></html>"))
			return
		}
		w.Write([]byte("<html><body><h1>Default Site</h1><p>Welcome to our main public website, nothing special here.</p></body></html>"))
	}))
	defer srv.Close()

	candidates := []string{
		"www.corp.invalid", "mail.corp.invalid", "ftp.corp.invalid", // decoys matching the default page
		realVHost, // the one that should stand out
	}

	results := VHostScan(context.Background(), testEngine(), srv.URL, candidates, 6)

	if len(results) != 1 {
		t.Fatalf("expected exactly 1 vhost result, got %d: %+v", len(results), results)
	}
	if results[0].Host != realVHost {
		t.Errorf("got host %q, want %q", results[0].Host, realVHost)
	}
}
