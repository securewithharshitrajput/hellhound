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
		// Both of these expectations flipped after a real comparison run
		// against SecLists' common.txt exposed the cost of the old,
		// permissive defaults: an ambiguous-Content-Type false positive
		// (".git/config", served with no Content-Type) got recursed into
		// and multiplied into a full extra wordlist pass, and several
		// malformed wordlist entries containing "//" triggered net/http's
		// own ServeMux auto-redirect (to the slash-collapsed path) —
		// mechanical artifacts, not real directories, that each spawned
		// another full re-scan when any redirect was treated as
		// recursable. Missing an occasional real directory that serves no
		// Content-Type, or a genuine redirect-without-trailing-slash, is a
		// real but much smaller cost than that cascade.
		{"ambiguous no content-type now defaults to NOT recursing", Result{URL: "http://x/weird", Status: 200, ContentType: ""}, false},
		{"a redirect only counts if it targets a trailing slash", Result{URL: "http://x/admin", Status: 301, ContentType: "application/json", RedirectTo: "/admin/"}, true},
		{"a redirect to a non-trailing-slash target does not count", Result{URL: "http://x/weird", Status: 301, RedirectTo: "/weird-cleaned-path"}, false},
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
