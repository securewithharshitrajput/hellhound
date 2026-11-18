package engine

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func hangingServer(t *testing.T) *httptest.Server {
	t.Helper()
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-release:
		case <-r.Context().Done():
		case <-time.After(5 * time.Second):
		}
	}))
	t.Cleanup(func() { close(release); srv.Close() })
	return srv
}

func throttleEngine(timeout time.Duration, throttled *atomic.Int64) *Engine {
	cfg := DefaultConfig()
	cfg.Concurrency = 10
	cfg.Timeout = timeout
	cfg.AutoThrottle = true
	cfg.OnThrottle = func(int, int) { throttled.Add(1) }
	return New(cfg)
}

// A burst of ordinary timeouts slows the scan down.
func TestAutoThrottleTriggersOnTimeoutBurst(t *testing.T) {
	srv := hangingServer(t)
	var throttled atomic.Int64
	eng := throttleEngine(150*time.Millisecond, &throttled)
	reqs := make([]Request, 8)
	for i := range reqs {
		reqs[i] = Request{Method: "GET", URL: srv.URL}
	}
	eng.DoAll(context.Background(), reqs)
	if throttled.Load() == 0 || eng.Throttles.Load() == 0 {
		t.Errorf("8 timeouts did not trigger a slowdown (callbacks=%d)", throttled.Load())
	}
}

// Optional probes with their own short timeout expire without counting as
// the target struggling, and expire at their own limit, not the engine's.
func TestPerRequestTimeoutDoesNotThrottle(t *testing.T) {
	srv := hangingServer(t)
	var throttled atomic.Int64
	eng := throttleEngine(5*time.Second, &throttled)
	reqs := make([]Request, 8)
	for i := range reqs {
		reqs[i] = Request{Method: "POST", URL: srv.URL, Timeout: 100 * time.Millisecond}
	}
	start := time.Now()
	resps := eng.DoAll(context.Background(), reqs)
	if d := time.Since(start); d > 2*time.Second {
		t.Errorf("short per-request timeout was not honoured: took %s", d)
	}
	for _, r := range resps {
		if r.Err == nil {
			t.Fatal("expected a timeout error")
		}
	}
	if throttled.Load() != 0 || eng.Throttles.Load() != 0 {
		t.Errorf("optional-probe timeouts slowed the scan down")
	}
}

// A per-request timeout can only shorten the engine's, never lengthen it.
func TestPerRequestTimeoutCannotExceedEngineTimeout(t *testing.T) {
	srv := hangingServer(t)
	var throttled atomic.Int64
	eng := throttleEngine(150*time.Millisecond, &throttled)
	start := time.Now()
	r := eng.Do(context.Background(), Request{Method: "GET", URL: srv.URL, Timeout: time.Minute})
	if r.Err == nil || time.Since(start) > 2*time.Second {
		t.Errorf("engine timeout not enforced: err=%v after %s", r.Err, time.Since(start))
	}
}
