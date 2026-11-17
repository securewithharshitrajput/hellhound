package main

import (
	"fmt"
	"io"
	"os"
	"sync"
	"time"
)

// progress draws one self-overwriting status line on a terminal while the
// scan runs: which directory, how far through it, request rate, time left
// for that directory, and hits so far. It is only active when the stream
// is a terminal; into a file or a pipe it prints nothing, so logs stay
// clean. Everything else written to the same stream during the scan must
// go through Println, which clears the line first.
type progress struct {
	mu       sync.Mutex
	w        io.Writer
	enabled  bool
	sent     func() int64 // total requests sent so far
	start    time.Time
	lastDraw time.Time
	lastSent int64
	lastAt   time.Time
	rps      float64
	dirStart time.Time
	dir      string
	dirsDone int
	hitsPrev int // hits in completed directories
	drawn    bool
	width    int
}

func newProgress(w *os.File, enabled bool, sent func() int64) *progress {
	now := time.Now()
	return &progress{w: w, enabled: enabled && isTerminal(w), sent: sent, start: now, lastAt: now, width: 110}
}

func isTerminal(f *os.File) bool {
	info, err := f.Stat()
	return err == nil && info.Mode()&os.ModeCharDevice != 0
}

// Update is called for every classified response.
func (p *progress) Update(dir string, done, total, hits int) {
	if !p.enabled {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	now := time.Now()
	if dir != p.dir {
		p.dir, p.dirStart = dir, now
	}
	if now.Sub(p.lastDraw) < 200*time.Millisecond && done != total {
		return
	}
	p.lastDraw = now
	if dt := now.Sub(p.lastAt).Seconds(); dt >= 0.5 {
		cur := p.sent()
		inst := float64(cur-p.lastSent) / dt
		if p.rps == 0 {
			p.rps = inst
		} else {
			p.rps = 0.6*p.rps + 0.4*inst
		}
		p.lastSent, p.lastAt = cur, now
	}
	fmt.Fprint(p.w, "\r\x1b[K"+formatProgress(dir, done, total, p.hitsPrev+hits, p.dirsDone, p.rps, now.Sub(p.dirStart), p.width))
	p.drawn = true
}

// DirDone records a finished directory and its hit count.
func (p *progress) DirDone(hits int) {
	p.mu.Lock()
	p.dirsDone++
	p.hitsPrev = hits
	p.mu.Unlock()
}

// Println writes a full line, clearing the status line first.
func (p *progress) Println(format string, a ...any) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.drawn {
		fmt.Fprint(p.w, "\r\x1b[K")
		p.drawn = false
	}
	fmt.Fprintf(p.w, format+"\n", a...)
}

// Clear removes the status line.
func (p *progress) Clear() {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.drawn {
		fmt.Fprint(p.w, "\r\x1b[K")
		p.drawn = false
	}
}

// formatProgress renders the status line (no control characters), cut to
// width so it never wraps.
func formatProgress(dir string, done, total, hits, dirsDone int, rps float64, elapsed time.Duration, width int) string {
	pct := 0.0
	if total > 0 {
		pct = 100 * float64(done) / float64(total)
	}
	eta := "--"
	if done > 0 && done < total && elapsed > 0 {
		left := time.Duration(float64(elapsed) * float64(total-done) / float64(done))
		eta = left.Round(time.Second).String()
	} else if done >= total {
		eta = "0s"
	}
	if len(dir) > 40 {
		dir = "…" + dir[len(dir)-39:]
	}
	s := fmt.Sprintf("[%s] %d/%d (%.0f%%) | %.0f req/s | ETA %s | %d hit(s) to verify | %d dir(s) done", dir, done, total, pct, rps, eta, hits, dirsDone)
	if r := []rune(s); width > 0 && len(r) > width {
		s = string(r[:width-1]) + "…"
	}
	return s
}
