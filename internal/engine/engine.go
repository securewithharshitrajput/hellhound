// Package engine is the concurrent HTTP request layer: a worker pool that
// fetches URLs with bounded concurrency and backs off when the target pushes
// back (429 / 503). It knows nothing about discovery logic — it just fetches.
package engine

import (
	"context"
	"crypto/tls"
	"io"
	"net/http"
	"sync"
	"sync/atomic"
	"time"
)

// Request is a unit of work for the engine.
type Request struct {
	Method string
	URL    string
	Header map[string]string
	Body   []byte
	// HostOverride, if set, sends this value as the request's Host header
	// (virtual-host / SNI-style fuzzing: hitting one IP with many candidate
	// hostnames). This is deliberately a dedicated field rather than just
	// Header["Host"] — Go's net/http treats Host as a special field on
	// http.Request, not a regular header; setting Header["Host"] has no
	// effect on the wire at all, so without this field vhost fuzzing would
	// silently do nothing.
	HostOverride string
	// Meta rides along so callers can correlate responses with their intent
	// (e.g. "this was a recursion probe for /admin").
	Meta any
}

// Response is the captured result of a Request. Body is read fully and the
// connection reused; for content discovery the bodies are small.
type Response struct {
	Req        Request
	Status     int
	Header     http.Header
	Body       []byte
	Length     int
	Words      int
	Lines      int
	Duration   time.Duration
	RedirectTo string
	// Truncated is true if the body was cut off at cfg.MaxBodyBytes rather
	// than ending naturally. A truncated body commonly breaks downstream
	// JSON parsing (an OpenAPI/GraphQL spec parse failing with no obvious
	// reason) — callers that parse structured content should check this
	// before assuming "parse failed" means "not actually a spec".
	Truncated bool
	Err       error
}

// Config tunes engine behavior.
type Config struct {
	Concurrency    int
	Timeout        time.Duration
	FollowRedirect bool
	MaxBodyBytes   int64
	UserAgent      string
	// RetryOn429 enables adaptive backoff: on a 429/503 the engine pauses all
	// workers, waits (honoring Retry-After when present), and retries once.
	RetryOn429 bool
	// InsecureSkipVerify disables TLS certificate verification. Defaults to
	// false (verify certs) — only set true deliberately, e.g. an operator
	// explicitly opting in via -k to test a dev/staging host with a
	// self-signed cert. Earlier builds of this engine hardcoded this to
	// true unconditionally, which silently defeated certificate validation
	// against every target including production ones; that was wrong and
	// is fixed here.
	InsecureSkipVerify bool
	// DefaultHeaders are merged into every request (lowest precedence —
	// a per-Request.Header entry with the same key wins). Used for
	// operator-supplied headers (-H) such as an auth token or a custom
	// User-Agent override.
	DefaultHeaders map[string]string
}

// DefaultConfig returns sane defaults for authorized scanning.
func DefaultConfig() Config {
	return Config{
		Concurrency:        40,
		Timeout:            10 * time.Second,
		FollowRedirect:     false,
		MaxBodyBytes:       512 * 1024,
		UserAgent:          "hellhound/0.2 (+authorized-testing)",
		RetryOn429:         true,
		InsecureSkipVerify: false,
	}
}

// Engine runs requests. It is safe to reuse across phases.
type Engine struct {
	cfg       Config
	client    *http.Client
	transport *http.Transport
	// pause gates all workers during backoff. When closed, work proceeds.
	pauseMu sync.RWMutex
	paused  chan struct{}

	Sent     atomic.Int64
	Backoffs atomic.Int64
}

// New builds an Engine with a tuned transport (connection reuse, HTTP/2).
func New(cfg Config) *Engine {
	tr := &http.Transport{
		MaxIdleConns:        cfg.Concurrency * 2,
		MaxIdleConnsPerHost: cfg.Concurrency * 2,
		IdleConnTimeout:     30 * time.Second,
		ForceAttemptHTTP2:   true,
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: cfg.InsecureSkipVerify},
	}
	e := &Engine{
		cfg:       cfg,
		transport: tr,
		client: &http.Client{
			Transport: tr,
			Timeout:   cfg.Timeout,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				if cfg.FollowRedirect {
					return nil
				}
				return http.ErrUseLastResponse
			},
		},
	}
	ready := make(chan struct{})
	close(ready)
	e.paused = ready
	return e
}

// Close releases pooled idle connections. The CLI itself never needs to
// call this — cmd/hellhound creates exactly one Engine per process and the
// OS reclaims everything on exit — but a long-lived caller that creates
// and discards multiple Engines (a library embedder, a service handling
// many scan requests) must call Close on each one when done with it, or
// its kept-alive idle connections — and the background goroutines each
// one holds open waiting to read a response — persist forever. Confirmed
// directly: creating 20 Engines without closing any of them leaked ~45
// goroutines each (900+ total) in a test run; reusing one Engine across
// the same 20 scans leaked none.
func (e *Engine) Close() {
	e.transport.CloseIdleConnections()
}

// Run consumes reqs and emits responses. It blocks until reqs is closed and
// all in-flight work drains, then closes the returned channel.
func (e *Engine) Run(ctx context.Context, reqs <-chan Request) <-chan Response {
	out := make(chan Response, e.cfg.Concurrency)
	var wg sync.WaitGroup
	for i := 0; i < e.cfg.Concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for req := range reqs {
				select {
				case <-ctx.Done():
					return
				default:
				}
				e.waitIfPaused(ctx)
				out <- e.do(ctx, req)
			}
		}()
	}
	go func() {
		wg.Wait()
		close(out)
	}()
	return out
}

// Do fetches a single request directly, going through the same backoff/retry
// path as pooled work but WITHOUT spinning up the full worker pool. Use this
// for one-off requests (calibration probes, spec/GraphQL discovery) — routing
// those through Run would launch cfg.Concurrency goroutines to service a
// single item, which is pure overhead repeated on every call.
func (e *Engine) Do(ctx context.Context, r Request) Response {
	e.waitIfPaused(ctx)
	return e.do(ctx, r)
}

// DoAll fetches multiple one-off requests concurrently (bounded by
// cfg.Concurrency) and returns responses in the same order as reqs. Use this
// instead of N sequential Do calls when you have a batch ready up front
// (e.g. calibration's N random-token probes) — sequential Do calls would pay
// N network round-trips back-to-back for no reason.
func (e *Engine) DoAll(ctx context.Context, reqs []Request) []Response {
	out := make([]Response, len(reqs))
	sem := make(chan struct{}, e.cfg.Concurrency)
	var wg sync.WaitGroup
	for i, r := range reqs {
		wg.Add(1)
		sem <- struct{}{}
		go func(i int, r Request) {
			defer wg.Done()
			defer func() { <-sem }()
			out[i] = e.Do(ctx, r)
		}(i, r)
	}
	wg.Wait()
	return out
}

func (e *Engine) waitIfPaused(ctx context.Context) {
	e.pauseMu.RLock()
	ch := e.paused
	e.pauseMu.RUnlock()
	select {
	case <-ch:
	case <-ctx.Done():
	}
}

// triggerBackoff pauses all workers for d, then resumes them. Concurrent
// callers collapse into a single pause window.
func (e *Engine) triggerBackoff(d time.Duration) {
	e.pauseMu.Lock()
	select {
	case <-e.paused:
		// Not currently paused — open a new pause window.
		e.Backoffs.Add(1)
		gate := make(chan struct{})
		e.paused = gate
		e.pauseMu.Unlock()
		time.AfterFunc(d, func() { close(gate) })
		return
	default:
		// Already paused; let the existing window handle it.
		e.pauseMu.Unlock()
	}
}

func (e *Engine) do(ctx context.Context, r Request) Response {
	resp := e.once(ctx, r)
	if e.cfg.RetryOn429 && (resp.Status == 429 || resp.Status == 503) {
		d := retryAfter(resp.Header, 2*time.Second)
		e.triggerBackoff(d)
		e.waitIfPaused(ctx)
		resp = e.once(ctx, r)
	}
	return resp
}

func (e *Engine) once(ctx context.Context, r Request) Response {
	method := r.Method
	if method == "" {
		method = http.MethodGet
	}
	var bodyReader io.Reader
	if len(r.Body) > 0 {
		bodyReader = byteReader(r.Body)
	}
	httpReq, err := http.NewRequestWithContext(ctx, method, r.URL, bodyReader)
	if err != nil {
		return Response{Req: r, Err: err}
	}
	if r.HostOverride != "" {
		httpReq.Host = r.HostOverride
	}
	httpReq.Header.Set("User-Agent", e.cfg.UserAgent)
	for k, v := range e.cfg.DefaultHeaders { // lowest precedence
		httpReq.Header.Set(k, v)
	}
	for k, v := range r.Header { // per-request overrides defaults
		httpReq.Header.Set(k, v)
	}
	start := time.Now()
	hr, err := e.client.Do(httpReq)
	e.Sent.Add(1)
	if err != nil {
		return Response{Req: r, Err: err, Duration: time.Since(start)}
	}
	defer hr.Body.Close()
	// Read one byte beyond the limit so we can tell "body was exactly
	// MaxBodyBytes long" apart from "body was truncated" — io.LimitReader
	// alone can't distinguish those, and silently truncating a large
	// OpenAPI/GraphQL spec produces invalid JSON with no indication of why.
	raw, readErr := io.ReadAll(io.LimitReader(hr.Body, e.cfg.MaxBodyBytes+1))
	// readErr is nil for the intentional case (hitting our own
	// MaxBodyBytes cap — io.LimitReader just signals a clean EOF there,
	// handled below via `truncated`). A NON-nil readErr means the read
	// genuinely failed partway through: the connection stalled past the
	// client timeout, was reset, chunked encoding was cut off mid-stream,
	// etc. An earlier version discarded this error entirely, so a
	// response that failed to fully arrive looked identical to a
	// complete, successful one — confirmed directly: a target that sends
	// a partial body and then stalls past the timeout came back as a
	// normal 200 with no error, carrying only the bytes that happened to
	// arrive before the stall. Treating that as a real request error
	// (like any other failed fetch) is what makes Classify correctly
	// treat it as uninteresting instead of analyzing truncated-by-failure
	// content as if it were a genuine, complete response.
	if readErr != nil {
		return Response{Req: r, Err: readErr, Duration: time.Since(start)}
	}
	truncated := int64(len(raw)) > e.cfg.MaxBodyBytes
	body := raw
	if truncated {
		body = raw[:e.cfg.MaxBodyBytes]
	}
	resp := Response{
		Req:       r,
		Status:    hr.StatusCode,
		Header:    hr.Header,
		Body:      body,
		Length:    len(body),
		Words:     countWords(body),
		Lines:     countLines(body),
		Duration:  time.Since(start),
		Truncated: truncated,
	}
	if loc := hr.Header.Get("Location"); loc != "" {
		resp.RedirectTo = loc
	}
	return resp
}

// retryAfter parses the Retry-After header, which per RFC 7231/9110 may be
// EITHER a delay in seconds OR an HTTP-date. The earlier version only
// handled the seconds form and silently fell back to a fixed 2s wait for
// any server using the date form, under-respecting an explicit "wait until
// <time>" instruction from the target.
func retryAfter(h http.Header, fallback time.Duration) time.Duration {
	v := h.Get("Retry-After")
	if v == "" {
		return fallback
	}
	// A successfully parsed "0" legitimately means "retry immediately" —
	// treat any non-negative parse as authoritative rather than requiring
	// secs > 0, which would wrongly discard that value and fall back to a
	// needless default wait.
	if secs, err := time.ParseDuration(v + "s"); err == nil {
		if secs < 0 {
			secs = 0
		}
		return secs
	}
	if t, err := http.ParseTime(v); err == nil {
		if d := time.Until(t); d > 0 {
			return d
		}
		return 0
	}
	return fallback
}

func countWords(b []byte) int {
	n, inWord := 0, false
	for _, c := range b {
		if c == ' ' || c == '\t' || c == '\n' || c == '\r' {
			inWord = false
		} else if !inWord {
			inWord = true
			n++
		}
	}
	return n
}

func countLines(b []byte) int {
	if len(b) == 0 {
		return 0
	}
	n := 1
	for _, c := range b {
		if c == '\n' {
			n++
		}
	}
	return n
}

type byteReader []byte

func (b byteReader) Read(p []byte) (int, error) {
	if len(b) == 0 {
		return 0, io.EOF
	}
	n := copy(p, b)
	return n, nil
}
