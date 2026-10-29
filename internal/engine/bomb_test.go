package engine

import (
	"compress/gzip"
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// TestDecompressionBombIsBounded verifies that MaxBodyBytes limits the
// DECOMPRESSED size of a response, not just the compressed wire size. Go's
// http.Transport auto-decompresses a gzip response transparently before
// once() ever sees it, so io.LimitReader(hr.Body, ...) is already reading
// post-decompression bytes — but this was never verified directly. A
// malicious or just-misconfigured target serving a small gzip payload that
// expands to gigabytes (a classic "zip bomb") must not blow up memory or
// hang the scanner; it should be truncated exactly like any other
// oversized response.
func TestDecompressionBombIsBounded(t *testing.T) {
	const decompressedSize = 50 * 1024 * 1024 // 50MB decompressed from a tiny payload

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Encoding", "gzip")
		gz := gzip.NewWriter(w)
		defer gz.Close()
		// Highly compressible: one repeated byte compresses to a tiny
		// wire payload (gzip handles long runs extremely efficiently).
		buf := make([]byte, 1<<20) // write in 1MB chunks
		remaining := decompressedSize
		for remaining > 0 {
			n := len(buf)
			if remaining < n {
				n = remaining
			}
			gz.Write(buf[:n])
			remaining -= n
		}
	}))
	defer srv.Close()

	cfg := DefaultConfig()
	cfg.MaxBodyBytes = 1024 * 1024 // 1MB cap — far below the 50MB decompressed size
	cfg.Timeout = 10 * time.Second
	e := New(cfg)

	start := time.Now()
	resp := e.Do(context.Background(), Request{Method: "GET", URL: srv.URL})
	elapsed := time.Since(start)

	if resp.Err != nil {
		t.Fatalf("unexpected error: %v", resp.Err)
	}
	if !resp.Truncated {
		t.Error("expected Truncated=true for a decompression bomb exceeding MaxBodyBytes")
	}
	if int64(resp.Length) > cfg.MaxBodyBytes {
		t.Errorf("Body length %d exceeds MaxBodyBytes %d — decompression bomb was NOT bounded", resp.Length, cfg.MaxBodyBytes)
	}
	if elapsed > 5*time.Second {
		t.Errorf("took %s to handle a bounded read — too slow, something is reading past the limit before truncating", elapsed)
	}
}
