package discover

import "testing"

func TestLooksLikeDirectoryRejectsLeafAPIEndpoints(t *testing.T) {
	cases := []struct {
		name string
		r    Result
		want bool
	}{
		{"html directory", Result{URL: "http://x/admin", Status: 200, ContentType: "text/html; charset=utf-8"}, true},
		{"json api leaf", Result{URL: "http://x/graphql", Status: 200, ContentType: "application/json"}, false},
		{"json api with nested-looking path", Result{URL: "http://x/api/v1/users", Status: 200, ContentType: "application/json"}, false},
		{"file with extension", Result{URL: "http://x/app.js", Status: 200, ContentType: "text/html"}, false},
		{"zip download", Result{URL: "http://x/export", Status: 200, ContentType: "application/zip"}, false},
		{"ambiguous no content-type", Result{URL: "http://x/weird", Status: 200, ContentType: ""}, true},
		{"redirect regardless of content-type", Result{URL: "http://x/admin", Status: 301, ContentType: "application/json"}, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := looksLikeDirectory(c.r)
			if got != c.want {
				t.Errorf("looksLikeDirectory(%+v) = %v, want %v", c.r, got, c.want)
			}
		})
	}
}

func TestPrioritizeRecursionDedupesAndFiltersLeaves(t *testing.T) {
	results := []Result{
		{URL: "http://x/admin", Status: 200, ContentType: "text/html"},
		{URL: "http://x/admin", Status: 200, ContentType: "text/html"}, // duplicate
		{URL: "http://x/graphql", Status: 200, ContentType: "application/json"},
		{URL: "http://x/backup.zip", Status: 200, ContentType: "application/zip"},
		{URL: "http://x/moved", Status: 404}, // not a hit, excluded by status
	}
	got := prioritizeRecursion(results)
	if len(got) != 1 || got[0] != "/admin" {
		t.Errorf("got %v, want exactly [\"/admin\"]", got)
	}
}
