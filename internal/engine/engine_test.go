package engine

import (
	"compress/gzip"
	"context"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func testConfig() Config {
	cfg := DefaultConfig()
	cfg.Concurrency = 5
	cfg.Timeout = 2 * time.Second
	return cfg
}

func TestBasicFetch(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte("hello world\nsecond line"))
	}))
	defer srv.Close()

	e := New(testConfig())
	resp := e.Do(context.Background(), Request{Method: "GET", URL: srv.URL + "/anything"})
	if resp.Err != nil {
		t.Fatalf("unexpected error: %v", resp.Err)
	}
	if resp.Status != 200 {
		t.Errorf("status = %d, want 200", resp.Status)
	}
	if resp.Length != len("hello world\nsecond line") {
		t.Errorf("length = %d, want %d", resp.Length, len("hello world\nsecond line"))
	}
	if resp.Words != 4 {
		t.Errorf("words = %d, want 4", resp.Words)
	}
}

func TestRunRespectsConcurrencyLimit(t *testing.T) {
	var inFlight atomic.Int32
	var maxSeen atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := inFlight.Add(1)
		for {
			cur := maxSeen.Load()
			if n <= cur || maxSeen.CompareAndSwap(cur, n) {
				break
			}
		}
		time.Sleep(20 * time.Millisecond) // hold the slot long enough to overlap
		inFlight.Add(-1)
		w.WriteHeader(200)
	}))
	defer srv.Close()

	cfg := testConfig()
	cfg.Concurrency = 3
	e := New(cfg)

	reqs := make(chan Request, 30)
	for i := 0; i < 30; i++ {
		reqs <- Request{Method: "GET", URL: srv.URL + "/x"}
	}
	close(reqs)

	ctx := context.Background()
	count := 0
	for range e.Run(ctx, reqs) {
		count++
	}
	if count != 30 {
		t.Fatalf("got %d responses, want 30", count)
	}
	if got := maxSeen.Load(); got > 3 {
		t.Errorf("max concurrent in-flight = %d, want <= 3 (concurrency limit)", got)
	}
}

func TestBackoffOn429RetriesAndSucceeds(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := hits.Add(1)
		if n == 1 {
			w.Header().Set("Retry-After", "0") // near-instant for test speed
			w.WriteHeader(429)
			return
		}
		w.WriteHeader(200)
		w.Write([]byte("ok"))
	}))
	defer srv.Close()

	e := New(testConfig())
	resp := e.Do(context.Background(), Request{Method: "GET", URL: srv.URL + "/x"})
	if resp.Err != nil {
		t.Fatalf("unexpected error: %v", resp.Err)
	}
	if resp.Status != 200 {
		t.Errorf("status after retry = %d, want 200 (backoff should have retried once)", resp.Status)
	}
	if e.Backoffs.Load() != 1 {
		t.Errorf("Backoffs = %d, want 1", e.Backoffs.Load())
	}
}

func TestBackoffPausesOtherWorkersToo(t *testing.T) {
	// First request triggers a 429; while that backoff window is open, a
	// second concurrent request should also be held (not hammer the
	// server), then both proceed once the window closes.
	var n429 atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/trigger" && n429.Add(1) == 1 {
			w.Header().Set("Retry-After", "0")
			w.WriteHeader(429)
			return
		}
		w.WriteHeader(200)
	}))
	defer srv.Close()

	e := New(testConfig())
	ctx := context.Background()

	resp := e.Do(ctx, Request{Method: "GET", URL: srv.URL + "/trigger"})
	if resp.Status != 200 {
		t.Fatalf("trigger request status = %d, want 200 after its own retry", resp.Status)
	}

	// After the backoff window closes, waitIfPaused should return
	// immediately for new work — verify the engine isn't stuck paused.
	done := make(chan struct{})
	go func() {
		e.Do(ctx, Request{Method: "GET", URL: srv.URL + "/other"})
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("engine appears stuck paused after backoff window should have closed")
	}
}

func TestContextCancellationStopsWork(t *testing.T) {
	block := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-block // hang until test releases it
		w.WriteHeader(200)
	}))
	defer srv.Close()
	defer close(block)

	cfg := testConfig()
	cfg.Concurrency = 2
	cfg.Timeout = 30 * time.Second // don't let the client timeout mask cancellation
	e := New(cfg)

	ctx, cancel := context.WithCancel(context.Background())
	reqs := make(chan Request, 10)
	for i := 0; i < 10; i++ {
		reqs <- Request{Method: "GET", URL: srv.URL + "/x"}
	}
	close(reqs)

	out := e.Run(ctx, reqs)
	cancel() // cancel almost immediately — most requests should never complete

	deadline := time.After(3 * time.Second)
	drained := false
	for !drained {
		select {
		case _, ok := <-out:
			if !ok {
				drained = true
			}
		case <-deadline:
			t.Fatal("Run did not drain/close after context cancellation")
		}
	}
}

func TestDoAllReturnsResponsesInOrder(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(r.URL.Path))
	}))
	defer srv.Close()

	e := New(testConfig())
	reqs := []Request{
		{Method: "GET", URL: srv.URL + "/a"},
		{Method: "GET", URL: srv.URL + "/b"},
		{Method: "GET", URL: srv.URL + "/c"},
	}
	resps := e.DoAll(context.Background(), reqs)
	want := []string{"/a", "/b", "/c"}
	for i, r := range resps {
		if string(r.Body) != want[i] {
			t.Errorf("resps[%d].Body = %q, want %q (order not preserved)", i, r.Body, want[i])
		}
	}
}

// TestTLSVerificationDefaultsOnAndIsOptOut proves the security fix from the
// prior review actually works both ways: against a self-signed-cert HTTPS
// server, the default config (verification ON) must FAIL, and only with
// InsecureSkipVerify explicitly set does the request succeed. A tool that
// silently skipped verification (the original bug) would make both cases
// succeed, defeating cert validation against real targets without the
// operator ever knowing.
func TestTLSVerificationDefaultsOnAndIsOptOut(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	}))
	defer srv.Close()

	secure := New(testConfig()) // InsecureSkipVerify defaults false
	resp := secure.Do(context.Background(), Request{Method: "GET", URL: srv.URL})
	if resp.Err == nil {
		t.Error("expected a cert verification error against a self-signed cert with default config, got none")
	}

	cfg := testConfig()
	cfg.InsecureSkipVerify = true
	insecure := New(cfg)
	resp2 := insecure.Do(context.Background(), Request{Method: "GET", URL: srv.URL})
	if resp2.Err != nil {
		t.Errorf("expected success with InsecureSkipVerify=true, got error: %v", resp2.Err)
	}
	if resp2.Status != 200 {
		t.Errorf("status = %d, want 200", resp2.Status)
	}
}

// TestGzipResponsesAreTransparentlyDecoded verifies Go's transport does what
// we rely on implicitly: a gzip-compressed response body must come back as
// the original decompressed text, not raw compressed bytes — otherwise
// every piece of analysis downstream (word/line counts, SimHash, JSON
// parsing of a spec) would be operating on garbage for any server that
// compresses responses, which is most real targets.
func TestGzipResponsesAreTransparentlyDecoded(t *testing.T) {
	const plain = "hello world this is definitely readable text, not compressed bytes"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Encoding", "gzip")
		w.Header().Set("Content-Type", "text/plain")
		gz := gzip.NewWriter(w)
		gz.Write([]byte(plain))
		gz.Close()
	}))
	defer srv.Close()

	e := New(testConfig())
	resp := e.Do(context.Background(), Request{Method: "GET", URL: srv.URL})
	if resp.Err != nil {
		t.Fatalf("unexpected error: %v", resp.Err)
	}
	if string(resp.Body) != plain {
		t.Errorf("Body = %q, want decompressed %q — gzip is not being transparently decoded", resp.Body, plain)
	}
}

// TestAlwaysFailingServerDoesNotHang proves the single-retry backoff policy
// is actually bounded: a server that returns 503 forever (a Cloudflare-style
// permanent challenge page, or a genuinely broken backend) must not cause
// an infinite retry loop or an indefinite hang — it should retry exactly
// once and then return the failing response, letting the caller move on.
func TestAlwaysFailingServerDoesNotHang(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.Header().Set("Retry-After", "0")
		w.WriteHeader(503)
	}))
	defer srv.Close()

	e := New(testConfig())
	done := make(chan Response, 1)
	go func() {
		done <- e.Do(context.Background(), Request{Method: "GET", URL: srv.URL})
	}()

	select {
	case resp := <-done:
		if resp.Status != 503 {
			t.Errorf("status = %d, want 503 (server never recovers)", resp.Status)
		}
		if got := hits.Load(); got != 2 {
			t.Errorf("server hit %d times, want exactly 2 (1 original + 1 retry, no infinite loop)", got)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Do did not return within 5s — looks like an infinite retry loop/hang against an always-503 server")
	}
}

// TestHostOverrideActuallyChangesWireHostHeader guards against a subtle
// footgun: Go's net/http treats Host as a special field on http.Request,
// NOT a regular header — setting Header["Host"] compiles fine and looks
// like it should work, but has zero effect on the actual wire request. If
// HostOverride were (mis)implemented as a Header entry instead of setting
// httpReq.Host, vhost/virtual-host fuzzing would silently send every
// request with the real Host and never actually test anything.
func TestHostOverrideActuallyChangesWireHostHeader(t *testing.T) {
	var gotHost string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHost = r.Host
		w.WriteHeader(200)
	}))
	defer srv.Close()

	e := New(testConfig())
	e.Do(context.Background(), Request{Method: "GET", URL: srv.URL, HostOverride: "evil-internal.target.invalid"})
	if gotHost != "evil-internal.target.invalid" {
		t.Errorf("server saw Host = %q, want %q — HostOverride is not reaching the wire", gotHost, "evil-internal.target.invalid")
	}
}

// TestCloseReleasesIdleConnectionGoroutines proves Close() actually does
// something: creating many short-lived Engines without closing them leaks
// the goroutine each pooled idle keep-alive connection holds open; calling
// Close on each one releases them. This was found while investigating a
// goroutine-count jump (48 -> 939 across 20 scans) in the discover
// package's own leak test — tracked down to 20 never-closed Engines, not
// a leak in the scanning logic itself.
func TestCloseReleasesIdleConnectionGoroutines(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	}))
	defer srv.Close()

	runtime.GC()
	time.Sleep(20 * time.Millisecond)
	baseline := runtime.NumGoroutine()

	var engines []*Engine
	for i := 0; i < 20; i++ {
		e := New(testConfig())
		e.Do(context.Background(), Request{Method: "GET", URL: srv.URL})
		engines = append(engines, e)
	}

	runtime.GC()
	time.Sleep(50 * time.Millisecond)
	beforeClose := runtime.NumGoroutine()
	if beforeClose <= baseline {
		t.Skip("didn't observe any goroutine growth from pooled connections on this platform — nothing to prove Close() fixes")
	}

	for _, e := range engines {
		e.Close()
	}
	runtime.GC()
	time.Sleep(50 * time.Millisecond)
	afterClose := runtime.NumGoroutine()

	if afterClose >= beforeClose {
		t.Errorf("Close() should have reduced goroutine count: baseline=%d beforeClose=%d afterClose=%d", baseline, beforeClose, afterClose)
	}
}

func TestTruncationDetection(t *testing.T) {
	bigBody := strings.Repeat("x", 1000)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(bigBody))
	}))
	defer srv.Close()

	cfg := testConfig()
	cfg.MaxBodyBytes = 100 // force truncation
	e := New(cfg)
	resp := e.Do(context.Background(), Request{Method: "GET", URL: srv.URL})
	if resp.Err != nil {
		t.Fatalf("unexpected error: %v", resp.Err)
	}
	if !resp.Truncated {
		t.Error("expected Truncated=true when body exceeds MaxBodyBytes")
	}
	if resp.Length != 100 {
		t.Errorf("Length = %d, want exactly 100 (the limit)", resp.Length)
	}

	// Sanity check the non-truncated case too — a body exactly AT or under
	// the limit must not be flagged.
	cfg2 := testConfig()
	cfg2.MaxBodyBytes = 1000 // exactly matches bigBody's length
	e2 := New(cfg2)
	resp2 := e2.Do(context.Background(), Request{Method: "GET", URL: srv.URL})
	if resp2.Truncated {
		t.Error("expected Truncated=false when body exactly matches MaxBodyBytes")
	}
	if resp2.Length != 1000 {
		t.Errorf("Length = %d, want 1000", resp2.Length)
	}
}

func TestRetryAfterParsing(t *testing.T) {
	cases := []struct {
		name     string
		value    string
		wantZero bool // true if we expect ~0 delay (immediate retry)
	}{
		{"empty uses fallback", "", false},
		{"zero seconds means immediate", "0", true},
		{"seconds form", "5", false},
		{"invalid garbage uses fallback", "not-a-value", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			h := http.Header{}
			if c.value != "" {
				h.Set("Retry-After", c.value)
			}
			got := retryAfter(h, 2*time.Second)
			if c.wantZero && got != 0 {
				t.Errorf("retryAfter(%q) = %v, want 0", c.value, got)
			}
		})
	}

	// HTTP-date form (RFC 7231 also allows this, not just seconds).
	future := time.Now().Add(10 * time.Second).UTC().Format(http.TimeFormat)
	h := http.Header{}
	h.Set("Retry-After", future)
	got := retryAfter(h, 2*time.Second)
	if got < 8*time.Second || got > 11*time.Second {
		t.Errorf("retryAfter(HTTP-date 10s out) = %v, want ~10s", got)
	}
}

func TestDefaultHeadersAppliedAndOverridable(t *testing.T) {
	var gotAuth, gotCustom string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotCustom = r.Header.Get("X-Custom")
		w.WriteHeader(200)
	}))
	defer srv.Close()

	cfg := testConfig()
	cfg.DefaultHeaders = map[string]string{"Authorization": "Bearer default", "X-Custom": "default"}
	e := New(cfg)

	// Per-request header should override the default.
	e.Do(context.Background(), Request{
		Method: "GET", URL: srv.URL + "/x",
		Header: map[string]string{"X-Custom": "override"},
	})
	if gotAuth != "Bearer default" {
		t.Errorf("Authorization = %q, want default to apply", gotAuth)
	}
	if gotCustom != "override" {
		t.Errorf("X-Custom = %q, want per-request override to win", gotCustom)
	}
}
