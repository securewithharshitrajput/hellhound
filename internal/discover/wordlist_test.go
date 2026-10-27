package discover

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"hellhound/internal/engine"
)

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
