package discover

import "testing"

// TestDetectDirListingAcceptsRealListings verifies the fingerprints match
// the common three (Apache, nginx, python http.server) and don't match
// normal content pages, which would otherwise flood the report.
func TestDetectDirListingAcceptsRealListings(t *testing.T) {
	hits := []string{
		`<html><head><title>Index of /uploads</title></head><body><h1>Index of /uploads</h1><pre><a href="../">Parent Directory</a></pre></body></html>`,
		`<html><body><h1>Index of /backup</h1><pre><a href="file.tar.gz">file.tar.gz</a></pre></body></html>`,
		`<html><title>Directory listing for /logs</title><body>...</body></html>`,
	}
	for i, h := range hits {
		if _, ok := DetectDirListing([]byte(h)); !ok {
			t.Errorf("case %d: expected dir-listing fingerprint to match, body=%q", i, h)
		}
	}

	misses := []string{
		`<html><body><h1>Welcome</h1><p>Normal content page</p></body></html>`,
		`<html><body><h1>404 Not Found</h1></body></html>`,
		`{"users": [{"id": 1, "name": "alice"}]}`,
	}
	for i, m := range misses {
		if _, ok := DetectDirListing([]byte(m)); ok {
			t.Errorf("case %d: content page falsely matched dir-listing fingerprint, body=%q", i, m)
		}
	}
}

// TestClassifyDirListingsRequires200 confirms a 403 or 301 page that happens
// to contain the words "Index of /" (e.g. an error page saying "Index of /
// disabled") is NOT falsely flagged.
func TestClassifyDirListingsRequires200(t *testing.T) {
	results := []Result{
		{URL: "http://x/listing", Status: 200, BodyPreview: []byte("<title>Index of /uploads</title>")},
		{URL: "http://x/forbidden", Status: 403, BodyPreview: []byte("<title>Index of /</title> is forbidden")},
	}
	findings := ClassifyDirListings(results)
	if len(findings) != 1 {
		t.Fatalf("expected exactly 1 finding, got %d: %v", len(findings), findings)
	}
	if findings[0].URL != "http://x/listing" {
		t.Errorf("got %q, want http://x/listing", findings[0].URL)
	}
}
