package discover

import (
	"context"
	"net/http"
	"net/http/httptest"
	"runtime"
	"testing"
	"time"
)

// TestRunDoesNotLeakGoroutines runs several full scans back to back and
// checks the goroutine count settles back down afterward. The engine
// spawns worker pools (Run) and bounded goroutine batches (DoAll) per
// scanDir call; a leak here would mean every scan leaves worker
// goroutines parked forever, growing unbounded in a long-lived process
// (e.g. embedding this package in a long-running service, or a `-loop`
// style wrapper script).
func TestRunDoesNotLeakGoroutines(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/admin" {
			w.Write([]byte("<html>admin panel</html>"))
			return
		}
		w.WriteHeader(404)
	}))
	defer srv.Close()

	words := make([]string, 50)
	for i := range words {
		words[i] = "word"
	}
	words[0] = "admin"

	// One engine reused across every scan — matching how the real CLI
	// actually works (cmd/hellhound constructs exactly one engine.Engine
	// per process invocation, then exits). A fresh engine per call would
	// also create a fresh http.Transport each time, whose pooled
	// keep-alive connections carry their own background reader
	// goroutines that persist until that Transport's idle connections are
	// explicitly closed — a real thing to know about for anyone embedding
	// this package in a long-running service, but a test artifact here,
	// not a scanDir/Run leak. Reusing one engine isolates the question
	// that actually matters for the CLI: does repeated scanning leak
	// goroutines within a single engine's lifetime?
	eng := testEngine()
	runOnce := func() {
		d := New(eng, Options{
			BaseURL:      srv.URL,
			Wordlist:     words,
			CalibrationN: 6,
			MaxDepth:     0,
		})
		if _, err := d.Run(context.Background(), "/"); err != nil {
			t.Fatalf("Run: %v", err)
		}
	}

	// Warm up once so any one-time setup goroutines (e.g. the Go runtime's
	// own internal pools) don't get mistaken for a leak from our code.
	runOnce()
	runtime.GC()
	time.Sleep(50 * time.Millisecond)
	baseline := runtime.NumGoroutine()

	for i := 0; i < 20; i++ {
		runOnce()
	}
	runtime.GC()
	time.Sleep(100 * time.Millisecond) // let any slow-to-exit goroutines finish
	after := runtime.NumGoroutine()

	// Allow a small margin (a few goroutines) for scheduler/runtime noise,
	// but 20 scans leaking even a handful of goroutines each would show up
	// as a large, unmistakable jump, not noise.
	if after > baseline+5 {
		t.Errorf("goroutine count grew from %d to %d after 20 scans — possible leak", baseline, after)
	}
}
