package discover

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/securewithharshitrajput/hellhound/internal/engine"
)

// TestBuildWordlistFetchesRobotsAndHomepageConcurrently locks in a real
// bug fix found against a live, slow/rate-limited target: robots.txt and
// the homepage used to be fetched one after another, so a slow target
// cost 2x its response time just for this step, before calibration or
// fuzzing even started. Using a server where each endpoint deliberately
// takes 300ms, concurrent fetches should take ~300ms total; sequential
// fetches would take ~600ms+.
func TestBuildWordlistFetchesRobotsAndHomepageConcurrently(t *testing.T) {
	const delay = 300 * time.Millisecond
	var concurrentPeak atomic.Int32
	var inFlight atomic.Int32

	mux := http.NewServeMux()
	slow := func(body string) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			n := inFlight.Add(1)
			for {
				cur := concurrentPeak.Load()
				if n <= cur || concurrentPeak.CompareAndSwap(cur, n) {
					break
				}
			}
			time.Sleep(delay)
			inFlight.Add(-1)
			w.Write([]byte(body))
		}
	}
	mux.HandleFunc("/robots.txt", slow("User-agent: *\n"))
	mux.HandleFunc("/", slow("<html><body>home</body></html>"))
	srv := httptest.NewServer(mux)
	defer srv.Close()

	start := time.Now()
	BuildWordlist(context.Background(), testEngine(), srv.URL, nil)
	elapsed := time.Since(start)

	if concurrentPeak.Load() < 2 {
		t.Errorf("robots.txt and homepage were never in flight at the same time (peak concurrency = %d) — fetched sequentially, not concurrently", concurrentPeak.Load())
	}
	if elapsed > delay+200*time.Millisecond {
		t.Errorf("took %s, want close to %s (concurrent) not ~%s (sequential)", elapsed, delay, 2*delay)
	}
}

// TestBuildWordlistMinesTargetSpecificWords proves the "learn from the
// target" step actually works end-to-end against a real HTTP server: a
// word that exists ONLY in robots.txt and ONLY in a linked JS bundle must
// come back out, and it must not simply be the static seed unchanged.
func TestBuildWordlistMinesTargetSpecificWords(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/robots.txt", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("User-agent: *\nDisallow: /secret-reports\n"))
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`<html><head><script src="/static/app.js"></script></head><body>hi</body></html>`))
	})
	mux.HandleFunc("/static/app.js", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`fetch("/api/internal/billing-export").then(x=>x)`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	cfg := engine.DefaultConfig()
	eng := engine.New(cfg)

	seed := []string{"admin", "login"}
	got := BuildWordlist(context.Background(), eng, srv.URL, seed)

	wantAny := func(words []string, needle string) bool {
		for _, w := range words {
			if w == needle {
				return true
			}
		}
		return false
	}

	if !wantAny(got, "secret-reports") {
		t.Errorf("expected 'secret-reports' (from robots.txt) in mined wordlist, got %v", got)
	}
	if !wantAny(got, "billing-export") {
		t.Errorf("expected 'billing-export' (from linked JS) in mined wordlist, got %v", got)
	}
	if !wantAny(got, "admin") {
		t.Errorf("expected seed word 'admin' to survive the merge, got %v", got)
	}
	if len(got) <= len(seed) {
		t.Errorf("expected mining to grow the wordlist beyond the %d seed words, got %d total", len(seed), len(got))
	}
}

func TestResolveScriptURLSkipsCrossOrigin(t *testing.T) {
	base := "http://target.tld"
	cases := []struct {
		src  string
		want string
	}{
		{"/static/app.js", "http://target.tld/static/app.js"},
		{"https://cdn.example.com/react.js", ""},
		{"//cdn.example.com/react.js", ""},
		{"app.js", ""}, // page-relative, deliberately not guessed at
	}
	for _, c := range cases {
		if got := resolveScriptURL(base, c.src); got != c.want {
			t.Errorf("resolveScriptURL(%q, %q) = %q, want %q", base, c.src, got, c.want)
		}
	}
}
