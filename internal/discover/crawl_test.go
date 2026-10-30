package discover

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// TestCrawlFollowsMultiHopLinks proves the thing a wordlist fuzzer
// structurally cannot do: reach a page that is only LINKED (not guessable)
// and is more than one hop from the start. The link graph here is
//
//	/  ->  /hub  ->  /deep-a1b2c3-report  (unguessable slug, depth 2)
//
// with the deep page linking nowhere further. A fuzzer never finds
// /deep-a1b2c3-report; a single-hop homepage scrape never finds it either
// (it's not linked from "/"); only real multi-hop crawling reaches it.
func TestCrawlFollowsMultiHopLinks(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(`<html><body><a href="/hub">hub</a> <a href="/about">about</a></body></html>`))
	})
	mux.HandleFunc("/hub", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(`<html><body><a href="/deep-a1b2c3-report">secret report</a></body></html>`))
	})
	mux.HandleFunc("/about", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(`<html><body>about us</body></html>`))
	})
	mux.HandleFunc("/deep-a1b2c3-report", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(`<html><body>CONFIDENTIAL quarterly report</body></html>`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	results := Crawl(context.Background(), testEngine(), srv.URL, 3, 100)

	got := map[string]int{}
	for _, r := range results {
		got[r.URL] = r.Depth
	}
	if _, ok := got[srv.URL+"/hub"]; !ok {
		t.Errorf("expected to crawl /hub (depth 1), results: %v", got)
	}
	if _, ok := got[srv.URL+"/about"]; !ok {
		t.Errorf("expected to crawl /about (depth 1), results: %v", got)
	}
	if d, ok := got[srv.URL+"/deep-a1b2c3-report"]; !ok {
		t.Errorf("expected to reach the 2-hop-only /deep-a1b2c3-report, results: %v", got)
	} else if d != 2 {
		t.Errorf("/deep-a1b2c3-report found at depth %d, want 2", d)
	}
	// The start page itself is never reported as a finding.
	if _, ok := got[srv.URL]; ok {
		t.Errorf("start page should not be reported as a crawl finding")
	}
}

// TestCrawlStaysInScope verifies cross-origin links are never followed.
func TestCrawlStaysInScope(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(`<html><body>
			<a href="/local-page">local</a>
			<a href="https://evil.example.com/external">external</a>
			<a href="//cdn.example.com/lib.js">protocol-relative external</a>
		</body></html>`))
	})
	mux.HandleFunc("/local-page", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(`<html><body>local page</body></html>`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	results := Crawl(context.Background(), testEngine(), srv.URL, 3, 100)
	for _, r := range results {
		if !strings.HasPrefix(r.URL, srv.URL) {
			t.Errorf("crawled an out-of-scope URL: %s", r.URL)
		}
	}
	found := false
	for _, r := range results {
		if r.URL == srv.URL+"/local-page" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected the in-scope /local-page to be crawled, got %v", results)
	}
}

// TestCrawlRespectsMaxDepth confirms the depth bound actually stops the walk.
func TestCrawlRespectsMaxDepth(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(`<html><body><a href="/one">one</a></body></html>`))
	})
	mux.HandleFunc("/one", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(`<html><body><a href="/two">two</a></body></html>`))
	})
	mux.HandleFunc("/two", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(`<html><body>too deep</body></html>`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	results := Crawl(context.Background(), testEngine(), srv.URL, 1, 100)
	for _, r := range results {
		if r.URL == srv.URL+"/two" {
			t.Errorf("/two is 2 hops deep but was reached with maxDepth=1")
		}
	}
}

func TestExtractLinksSkipsNonNavigableSchemes(t *testing.T) {
	body := []byte(`<html><body>
		<a href="/real">real</a>
		<a href="mailto:x@y.com">mail</a>
		<a href="tel:+123">call</a>
		<a href="javascript:void(0)">js</a>
		<img src="data:image/png;base64,AAAA">
		<form action="/submit">
	</body></html>`)
	got := extractLinks(body)
	want := map[string]bool{"/real": true, "/submit": true}
	if len(got) != len(want) {
		t.Fatalf("got %v, want keys %v", got, want)
	}
	for _, g := range got {
		if !want[g] {
			t.Errorf("unexpected link extracted: %q", g)
		}
	}
}

// TestCrawlHandlesLinkCycles ensures a page graph with cycles (A links B,
// B links back to A, A links to itself) terminates instead of looping
// forever — the `seen` set must dedupe already-visited URLs.
func TestCrawlHandlesLinkCycles(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(`<html><body><a href="/">self</a> <a href="/b">b</a></body></html>`))
	})
	mux.HandleFunc("/b", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(`<html><body><a href="/">home</a> <a href="/b">self</a></body></html>`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	done := make(chan []CrawlResult, 1)
	go func() {
		done <- Crawl(context.Background(), testEngine(), srv.URL, 5, 100)
	}()
	select {
	case results := <-done:
		// /b visited exactly once despite being linked from multiple places.
		count := 0
		for _, r := range results {
			if r.URL == srv.URL+"/b" {
				count++
			}
		}
		if count != 1 {
			t.Errorf("/b should be reported exactly once despite cycles, got %d", count)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Crawl did not terminate on a cyclic link graph within 5s")
	}
}

func TestWordsFromCrawl(t *testing.T) {
	results := []CrawlResult{
		{URL: "http://t/api/v2/billing-export"},
		{URL: "http://t/about"},
		{URL: "http://t/static/app.js"}, // app.js has a dot -> skipped as a leaf asset
		{URL: "http://t/api/v2/users"},  // "api","v2" already seen; "users" new
	}
	got := WordsFromCrawl(results)
	want := map[string]bool{"api": true, "v2": true, "billing-export": true, "about": true, "static": true, "users": true}
	if len(got) != len(want) {
		t.Fatalf("got %v (%d), want %d distinct segments", got, len(got), len(want))
	}
	for _, g := range got {
		if !want[g] {
			t.Errorf("unexpected segment %q", g)
		}
		if g == "app.js" {
			t.Errorf("file-like segment app.js should have been skipped")
		}
	}
}
