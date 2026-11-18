// Package engine is the concurrent HTTP request layer: a worker pool that
// fetches URLs with bounded concurrency and backs off when the target pushes
// back (429 / 503). It knows nothing about discovery logic — it just fetches.
package engine

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

// limiter enforces a minimum spacing between request STARTS so no more than
// ratePerSec requests begin per second, shared across all workers. It's a
// small dependency-free token-spacing limiter (the project pulls in no
// external modules): each caller reserves the next time slot under a brief
// lock, then sleeps until it, so in-flight concurrency is unaffected — only
// the rate at which new requests launch is capped.
type limiter struct {
	mu       sync.Mutex
	interval time.Duration
	next     time.Time
}

func newLimiter(ratePerSec int) *limiter {
	return &limiter{interval: time.Second / time.Duration(ratePerSec)}
}

// setRate changes the limit; it applies to the next reservation.
func (l *limiter) setRate(ratePerSec int) {
	l.mu.Lock()
	l.interval = time.Second / time.Duration(ratePerSec)
	l.mu.Unlock()
}

// perSec returns the current limit in requests per second.
func (l *limiter) perSec() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return int(time.Second / l.interval)
}

// wait blocks until this caller's reserved slot, or until ctx is done.
func (l *limiter) wait(ctx context.Context) {
	l.mu.Lock()
	now := time.Now()
	slot := l.next
	if slot.Before(now) {
		slot = now
	}
	l.next = slot.Add(l.interval)
	l.mu.Unlock()

	d := time.Until(slot)
	if d <= 0 {
		return
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
	case <-ctx.Done():
	}
}

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
	// Timeout, if set, shortens this request's timeout below the engine's
	// (it can never lengthen it). A request that times out under its own
	// short limit is an optional probe the server ignored, not a sign the
	// target is struggling, so it does not feed auto-throttling.
	Timeout time.Duration
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
	// ProxyURL, when non-empty, routes every request through this HTTP(S)
	// proxy — the standard way to pipe recon through Burp Suite / ZAP for
	// inspection during an engagement (e.g. "http://127.0.0.1:8080").
	// Invalid values are reported by New via NewErr; an empty value means
	// no proxy. Proxying HTTPS through Burp usually also needs
	// InsecureSkipVerify (-k), since Burp presents its own CA.
	ProxyURL string
	// AutoThrottle halves the request rate (and pauses briefly) whenever
	// requests start timing out in bursts — the sign of a target that is
	// struggling or quietly throttling the scan. The rate never goes back
	// up during the run, and never drops below 1 request per second.
	AutoThrottle bool
	// OnThrottle, if set, is told each time AutoThrottle slows down.
	OnThrottle func(newRatePerSec, timeouts int)
	// RatePerSec caps the number of requests STARTED per second across all
	// workers (0 = unlimited, bounded only by Concurrency). A real
	// requests/sec ceiling, separate from concurrency: it's what keeps a
	// scan under a target's rate-based bot-mitigation / WAF thresholds
	// instead of tripping them, and what makes "slow and quiet" possible.
	RatePerSec int
	// Allow, if set, is consulted before every request; a URL it rejects
	// is never sent and comes back as ErrOutOfScope. This is where scope
	// rules are enforced, so every phase is covered by construction.
	Allow func(rawURL string) bool
}

// ErrOutOfScope is the error of a request the scope guard refused to send.
var ErrOutOfScope = errors.New("out of scope: request not sent")

// DefaultConfig returns sane defaults for authorized scanning.
func DefaultConfig() Config {
	return Config{
		Concurrency:        40,
		Timeout:            10 * time.Second,
		FollowRedirect:     false,
		MaxBodyBytes:       512 * 1024,
		UserAgent:          "hellhound/0.8 (+authorized-testing)",
		RetryOn429:         true,
		InsecureSkipVerify: false,
		AutoThrottle:       true,
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
	// rate gates request STARTS across all workers; nil when unlimited.
	// Swapped atomically because auto-throttling can install one mid-scan.
	rate atomic.Pointer[limiter]

	// Auto-throttle state.
	thrMu        sync.Mutex
	timeoutTimes []time.Time
	lastThrottle time.Time
	winStart     time.Time
	winSent      int64
	// Throttles counts how many times auto-throttling slowed the scan.
	Throttles atomic.Int64

	Sent     atomic.Int64
	Backoffs atomic.Int64
	// Blocked counts requests refused by cfg.Allow.
	Blocked atomic.Int64
}

// New builds an Engine with a tuned transport (connection reuse, HTTP/2).
// It ignores an invalid ProxyURL (falling back to no proxy); use NewErr if
// you want a malformed proxy value to be reported rather than silently
// dropped.
func New(cfg Config) *Engine {
	e, _ := NewErr(cfg)
	return e
}

// NewErr is New but returns an error for a malformed ProxyURL. The Engine
// is still returned (usable, just without the bad proxy) so a caller can
// choose to warn-and-continue; the CLI treats a bad -x as fatal.
func NewErr(cfg Config) (*Engine, error) {
	// Clamp values that would otherwise deadlock (zero workers), panic
	// (negative channel size) or hang forever (no timeout). The CLI rejects
	// these up front; this keeps library callers safe too.
	def := DefaultConfig()
	if cfg.Concurrency < 1 {
		cfg.Concurrency = 1
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = def.Timeout
	}
	if cfg.MaxBodyBytes <= 0 {
		cfg.MaxBodyBytes = def.MaxBodyBytes
	}
	if cfg.UserAgent == "" {
		cfg.UserAgent = def.UserAgent
	}
	tr := &http.Transport{
		MaxIdleConns:        cfg.Concurrency * 2,
		MaxIdleConnsPerHost: cfg.Concurrency * 2,
		IdleConnTimeout:     30 * time.Second,
		ForceAttemptHTTP2:   true,
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: cfg.InsecureSkipVerify},
	}
	var proxyErr error
	if cfg.ProxyURL != "" {
		pu, err := url.Parse(cfg.ProxyURL)
		if err != nil || pu.Host == "" {
			proxyErr = fmt.Errorf("invalid proxy URL %q (expected e.g. http://127.0.0.1:8080)", cfg.ProxyURL)
		} else {
			// HTTP/2 to the ORIGIN plus an HTTP/1.1 CONNECT proxy can
			// interact badly in net/http; disabling forced-HTTP2 when a
			// proxy is set keeps the common Burp/ZAP path reliable (they
			// speak HTTP/1.1 anyway).
			tr.ForceAttemptHTTP2 = false
			tr.Proxy = http.ProxyURL(pu)
		}
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
	if cfg.RatePerSec > 0 {
		e.rate.Store(newLimiter(cfg.RatePerSec))
	}
	e.winStart = time.Now()
	ready := make(chan struct{})
	close(ready)
	e.paused = ready
	return e, proxyErr
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
		// Stop launching once the caller cancels; the remaining requests
		// report the cancellation instead of waiting for a free slot.
		select {
		case sem <- struct{}{}:
		case <-ctx.Done():
			out[i] = Response{Req: r, Err: ctx.Err()}
			continue
		}
		wg.Add(1)
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
	if e.cfg.Allow != nil && !e.cfg.Allow(r.URL) {
		e.Blocked.Add(1)
		return Response{Req: r, Err: ErrOutOfScope}
	}
	resp := e.once(ctx, r)
	// A connection that was reset or closed mid-exchange is a transport
	// hiccup, not an answer about the path. Retry it once so one dropped
	// connection does not become one silently missed endpoint. Timeouts
	// are not retried: a path that hangs will hang again, and retrying
	// would double the cost of every slow target.
	if resp.Err != nil && ctx.Err() == nil && isDroppedConnection(resp.Err) {
		resp = e.once(ctx, r)
	}
	if resp.Err != nil && ctx.Err() == nil && e.cfg.AutoThrottle && r.Timeout == 0 && isTimeout(resp.Err) {
		e.noteTimeout()
	}
	// 429 is retried up to three times: after a pause every worker resumes
	// at once, and that burst alone can trip the limit again, so a single
	// retry leaves a tail of paths unchecked. 503 gets one retry — it can
	// be a path's genuine answer, and each retry pauses the whole scan.
	for attempt := 0; e.cfg.RetryOn429 && ctx.Err() == nil; attempt++ {
		if !(resp.Status == 429 && attempt < 3) && !(resp.Status == 503 && attempt < 1) {
			break
		}
		d := retryAfter(resp.Header, 2*time.Second)
		e.triggerBackoff(d)
		e.waitIfPaused(ctx)
		resp = e.once(ctx, r)
	}
	return resp
}

const (
	throttleWindow   = 15 * time.Second // timeouts are counted over this window
	throttleTimeouts = 5                // this many in the window triggers a slowdown
	throttlePause    = 5 * time.Second  // all workers pause this long on a slowdown
)

func isTimeout(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

// noteTimeout records a request timeout and, when they come in a burst,
// halves the request rate and pauses every worker briefly. The rate it
// halves is the configured one, or — when none was set — the rate the scan
// has actually been achieving since the last slowdown.
func (e *Engine) noteTimeout() {
	e.thrMu.Lock()
	now := time.Now()
	keep := e.timeoutTimes[:0]
	for _, t := range e.timeoutTimes {
		if now.Sub(t) <= throttleWindow {
			keep = append(keep, t)
		}
	}
	e.timeoutTimes = append(keep, now)
	n := len(e.timeoutTimes)
	if n < throttleTimeouts || now.Sub(e.lastThrottle) < throttleWindow {
		e.thrMu.Unlock()
		return
	}
	next := e.halveRateLocked(now)
	e.timeoutTimes = nil
	e.thrMu.Unlock()

	e.triggerBackoff(throttlePause)
	if e.cfg.OnThrottle != nil {
		e.cfg.OnThrottle(next, n)
	}
}

// halveRateLocked halves the request rate (the configured one, or the rate
// actually achieved since the last slowdown when none was set) and returns
// the new rate. thrMu must be held.
func (e *Engine) halveRateLocked(now time.Time) int {
	current := 0
	if l := e.rate.Load(); l != nil {
		current = l.perSec()
	} else if el := now.Sub(e.winStart).Seconds(); el > 0 {
		current = int(float64(e.Sent.Load()-e.winSent) / el)
	}
	next := current / 2
	if next < 1 {
		next = 1
	}
	if l := e.rate.Load(); l != nil {
		l.setRate(next)
	} else {
		e.rate.Store(newLimiter(next))
	}
	e.lastThrottle = now
	e.winStart, e.winSent = now, e.Sent.Load()
	e.Throttles.Add(1)
	return next
}

// SlowDown halves the request rate and pauses every worker for pause. It is
// for callers that recognise trouble the engine cannot see on its own, such
// as a firewall answering every path with the same block page. It returns
// the new rate in requests per second.
func (e *Engine) SlowDown(pause time.Duration) int {
	e.thrMu.Lock()
	next := e.halveRateLocked(time.Now())
	e.thrMu.Unlock()
	if pause > 0 {
		e.triggerBackoff(pause)
	}
	return next
}

// RatePerSec returns the current request-rate limit, 0 when unlimited.
func (e *Engine) RatePerSec() int {
	if l := e.rate.Load(); l != nil {
		return l.perSec()
	}
	return 0
}

// isDroppedConnection reports whether err is a connection that was reset,
// refused mid-scan or closed before a full response arrived — as opposed to
// a timeout, a TLS failure or a malformed URL.
func isDroppedConnection(err error) bool {
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return false
	}
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) ||
		errors.Is(err, syscall.ECONNRESET) || errors.Is(err, syscall.EPIPE) {
		return true
	}
	msg := err.Error()
	return strings.Contains(msg, "connection reset") || strings.Contains(msg, "server closed idle connection") ||
		strings.Contains(msg, "unexpected EOF") || strings.HasSuffix(msg, ": EOF")
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
	if r.Timeout > 0 && r.Timeout < e.cfg.Timeout {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, r.Timeout)
		defer cancel()
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
	// Rate gate goes here — immediately before the actual network call, and
	// inside once() rather than do() — so a post-backoff retry also counts
	// against the ceiling, and a request held by the limiter isn't counted
	// as Sent until it truly fires.
	if l := e.rate.Load(); l != nil {
		l.wait(ctx)
		if ctx.Err() != nil {
			return Response{Req: r, Err: ctx.Err()}
		}
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
