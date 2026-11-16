package engine

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

// A URL the Allow guard rejects must never reach the network, on any of the
// engine's request paths.
func TestAllowGuardBlocksBeforeSending(t *testing.T) {
	var seen atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "forbidden") {
			seen.Add(1)
		}
		w.Write([]byte("ok"))
	}))
	defer srv.Close()
	cfg := DefaultConfig()
	cfg.Allow = func(u string) bool { return !strings.Contains(u, "forbidden") }
	e := New(cfg)
	defer e.Close()
	ctx := context.Background()

	if r := e.Do(ctx, Request{URL: srv.URL + "/forbidden"}); !errors.Is(r.Err, ErrOutOfScope) {
		t.Errorf("Do: err = %v, want ErrOutOfScope", r.Err)
	}
	rs := e.DoAll(ctx, []Request{{URL: srv.URL + "/ok"}, {URL: srv.URL + "/forbidden/x"}, {Method: "OPTIONS", URL: srv.URL + "/a/forbidden"}})
	if rs[0].Err != nil || !errors.Is(rs[1].Err, ErrOutOfScope) || !errors.Is(rs[2].Err, ErrOutOfScope) {
		t.Errorf("DoAll: %v / %v / %v", rs[0].Err, rs[1].Err, rs[2].Err)
	}
	ch := make(chan Request, 2)
	ch <- Request{URL: srv.URL + "/forbidden-run"}
	ch <- Request{URL: srv.URL + "/fine"}
	close(ch)
	blocked := 0
	for r := range e.Run(ctx, ch) {
		if errors.Is(r.Err, ErrOutOfScope) {
			blocked++
		}
	}
	if blocked != 1 {
		t.Errorf("Run: %d blocked, want 1", blocked)
	}
	if seen.Load() != 0 {
		t.Errorf("%d out-of-scope request(s) reached the server", seen.Load())
	}
	if e.Blocked.Load() != 4 {
		t.Errorf("Blocked = %d, want 4", e.Blocked.Load())
	}
}
