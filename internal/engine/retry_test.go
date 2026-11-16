package engine

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

// A connection reset on the first attempt must be retried, so a flaky
// link does not turn into a silently missed path.
func TestDroppedConnectionIsRetriedOnce(t *testing.T) {
	var n atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if n.Add(1) == 1 {
			c, _, _ := w.(http.Hijacker).Hijack()
			if tc, ok := c.(*net.TCPConn); ok {
				tc.SetLinger(0)
			}
			c.Close()
			return
		}
		w.Write([]byte("ok"))
	}))
	defer srv.Close()
	e := New(DefaultConfig())
	defer e.Close()
	resp := e.DoAll(context.Background(), []Request{{URL: srv.URL + "/x"}})[0]
	if resp.Err != nil || resp.Status != 200 {
		t.Fatalf("want 200 after one retry, got status=%d err=%v", resp.Status, resp.Err)
	}
	if n.Load() != 2 {
		t.Errorf("server saw %d attempts, want 2", n.Load())
	}
}

// A timeout must NOT be retried: a hanging path would cost double.
func TestTimeoutIsNotRetried(t *testing.T) {
	var n atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n.Add(1)
		<-r.Context().Done()
	}))
	defer srv.Close()
	cfg := DefaultConfig()
	cfg.Timeout = 200 * time.Millisecond
	e := New(cfg)
	defer e.Close()
	start := time.Now()
	resp := e.DoAll(context.Background(), []Request{{URL: srv.URL + "/x"}})[0]
	if resp.Err == nil {
		t.Fatal("want a timeout error")
	}
	if n.Load() != 1 {
		t.Errorf("server saw %d attempts, want 1", n.Load())
	}
	if time.Since(start) > 600*time.Millisecond {
		t.Errorf("took %v; a timeout was retried", time.Since(start))
	}
}

// 429 is retried until it clears (up to three times).
func TestRateLimitRetriedUntilClear(t *testing.T) {
	var n atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if n.Add(1) <= 3 {
			w.Header().Set("Retry-After", "0")
			w.WriteHeader(429)
			return
		}
		w.Write([]byte("ok"))
	}))
	defer srv.Close()
	e := New(DefaultConfig())
	defer e.Close()
	resp := e.DoAll(context.Background(), []Request{{URL: srv.URL + "/x"}})[0]
	if resp.Status != 200 {
		t.Errorf("status = %d after %d attempts, want 200", resp.Status, n.Load())
	}
}

// Zero or negative settings must be clamped, not deadlock or panic.
func TestDegenerateConfigIsClamped(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("ok")) }))
	defer srv.Close()
	for _, c := range []int{0, -5} {
		e := New(Config{Concurrency: c, Timeout: 0, MaxBodyBytes: -1})
		done := make(chan []Response, 1)
		go func() { done <- e.DoAll(context.Background(), []Request{{URL: srv.URL}, {URL: srv.URL}}) }()
		select {
		case resps := <-done:
			for _, r := range resps {
				if r.Err != nil || string(r.Body) != "ok" {
					t.Errorf("concurrency %d: status=%d body=%q err=%v", c, r.Status, r.Body, r.Err)
				}
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("concurrency %d: DoAll deadlocked", c)
		}
		e.Close()
	}
}

// Cancelling must release DoAll even while every worker slot is held by a
// hanging request.
func TestDoAllReturnsPromptlyOnCancel(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { <-r.Context().Done() }))
	defer srv.Close()
	cfg := DefaultConfig()
	cfg.Concurrency = 2
	cfg.Timeout = 30 * time.Second
	e := New(cfg)
	defer e.Close()
	reqs := make([]Request, 50)
	for i := range reqs {
		reqs[i] = Request{URL: srv.URL}
	}
	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(200*time.Millisecond, cancel)
	start := time.Now()
	resps := e.DoAll(ctx, reqs)
	if d := time.Since(start); d > 3*time.Second {
		t.Fatalf("DoAll took %v after cancel", d)
	}
	for i, r := range resps {
		if r.Err == nil {
			t.Fatalf("response %d has no error after cancellation", i)
		}
	}
}
