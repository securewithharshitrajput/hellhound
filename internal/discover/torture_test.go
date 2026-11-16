package discover

import (
	"context"
	"fmt"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/securewithharshitrajput/hellhound/internal/engine"
)

func page(w http.ResponseWriter, code int, inner string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(code)
	fmt.Fprint(w, "<html><head><title>t</title></head><body>"+inner+"</body></html>")
}

// realPages serves the ground truth shared by the torture tests and reports
// whether it handled the request.
func realPages(w http.ResponseWriter, path string) bool {
	switch path {
	case "/admin":
		page(w, 200, "<h1>Admin console</h1><p>restricted staff area with many controls and settings</p>")
	case "/admin/users":
		page(w, 200, "<h1>User list</h1><table><tr><td>alice</td><td>bob</td><td>carol</td></tr></table>")
	default:
		return false
	}
	return true
}

var noise = strings.Fields("aaa backup config test login api secret images css js static old new tmp dev stage data files docs help search about contact news blog shop cart")

func foundPaths(base string, results []Result) []string {
	var out []string
	for _, r := range results {
		out = append(out, strings.TrimPrefix(r.URL, base))
	}
	sort.Strings(out)
	return out
}

func runScan(t *testing.T, base string, words []string, depth int) ([]Result, []string) {
	t.Helper()
	var warnings []string
	d := New(testEngine(), Options{
		BaseURL: base, Wordlist: words, CalibrationN: 6, MaxDepth: depth,
		OnWarning: func(dir string, err error) { warnings = append(warnings, err.Error()) },
	})
	results, err := d.Run(context.Background(), "/")
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	return results, warnings
}

// A target whose "not found" page is a 200 filled with a random amount of
// random words: no two misses share a shape. Must find the real pages and
// nothing else, and tell the operator filtering changed.
func TestRandomContentSoft404DoesNotFlood(t *testing.T) {
	vocab := strings.Fields("alpha beta gamma delta epsilon zeta eta theta iota kappa lambda mu nu xi omicron pi rho sigma tau upsilon phi chi psi omega offer deal sport weather stock trend video photo story")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if realPages(w, r.URL.Path) {
			return
		}
		var b strings.Builder
		for i, n := 0, 20+rand.Intn(400); i < n; i++ {
			b.WriteString(vocab[rand.Intn(len(vocab))] + " ")
		}
		page(w, 200, "<h1>Recommended for you</h1><p>"+b.String()+"</p>")
	}))
	defer srv.Close()

	words := append([]string{"admin", "users"}, noise...)
	for i := 0; i < 300; i++ {
		words = append(words, fmt.Sprintf("word%d", i))
	}
	results, warnings := runScan(t, srv.URL, words, 2)
	got := foundPaths(srv.URL, results)
	if fmt.Sprint(got) != "[/admin /admin/users]" {
		t.Errorf("want exactly [/admin /admin/users], got %d findings: %v", len(got), got)
	}
	n := 0
	for _, w := range warnings {
		if strings.Contains(w, "changes on every request") {
			n++
		}
	}
	if n != 1 {
		t.Errorf("want the changing-content warning exactly once, got %d", n)
	}
}

// A 200 "not found" page that echoes the path and carries a fresh token,
// timestamp and request number each time, on a page short enough that
// those few changes shift its shape.
func TestPathEchoingTokenSoft404DoesNotFlood(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if realPages(w, r.URL.Path) {
			return
		}
		page(w, 200, fmt.Sprintf(`<h1>Oops</h1><p>The page %s could not be found on this server.</p><input type=hidden name=csrf value=%x><p>Generated %s request %d</p><p>Try the search, the sitemap or head back home to continue browsing our catalogue.</p>`,
			r.URL.Path, rand.Int63(), time.Now().Format(time.RFC3339Nano), rand.Int()))
	}))
	defer srv.Close()

	words := append([]string{"admin", "users", "Program Files", "2003", "@", ".git/logs/", "WS_FTP.LOG", "abcd1234", "DB"}, noise...)
	for i := 0; i < 300; i++ {
		words = append(words, fmt.Sprintf("w%dx", i))
	}
	results, _ := runScan(t, srv.URL, words, 2)
	if got := foundPaths(srv.URL, results); fmt.Sprint(got) != "[/admin /admin/users]" {
		t.Errorf("want exactly [/admin /admin/users], got %d findings: %v", len(got), got)
	}
}

// A stable 404 target must NOT be switched to vocabulary filtering.
func TestStableTargetKeepsShapeFiltering(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !realPages(w, r.URL.Path) {
			page(w, 404, "<h1>Not Found</h1>")
		}
	}))
	defer srv.Close()
	results, warnings := runScan(t, srv.URL, append([]string{"admin", "users"}, noise...), 2)
	if got := foundPaths(srv.URL, results); fmt.Sprint(got) != "[/admin /admin/users]" {
		t.Errorf("got %v", got)
	}
	if len(warnings) != 0 {
		t.Errorf("stable target produced warnings: %v", warnings)
	}
}

// -u http://host/app must recurse into /app/admin, not /app/app/admin.
func TestBasePathTargetRecursesCorrectly(t *testing.T) {
	var wrong atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/app/app") {
			wrong.Add(1)
		}
		if strings.HasPrefix(r.URL.Path, "/app") && realPages(w, strings.TrimPrefix(r.URL.Path, "/app")) {
			return
		}
		page(w, 404, "<h1>Not Found</h1>")
	}))
	defer srv.Close()

	for _, base := range []string{srv.URL + "/app", srv.URL + "/app/"} {
		results, _ := runScan(t, base, append([]string{"admin", "users"}, noise...), 2)
		if got := foundPaths(srv.URL, results); fmt.Sprint(got) != "[/app/admin /app/admin/users]" {
			t.Errorf("base %q: got %v", base, got)
		}
	}
	if wrong.Load() != 0 {
		t.Errorf("%d requests went to /app/app/... (base path applied twice)", wrong.Load())
	}
}

// A server that ignores letter case: Admin/ADMIN/admin are one page and one
// directory to recurse into.
func TestCaseInsensitiveTargetMergesVariants(t *testing.T) {
	var reqs atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reqs.Add(1)
		if !realPages(w, strings.ToLower(r.URL.Path)) {
			page(w, 404, "<h1>Not Found</h1>")
		}
	}))
	defer srv.Close()

	words := append([]string{"ADMIN", "Admin", "admin", "Users", "users"}, noise...)
	results, warnings := runScan(t, srv.URL, words, 2)
	if got := foundPaths(srv.URL, results); fmt.Sprint(got) != "[/admin /admin/users]" {
		t.Errorf("want the lowercase spelling once each, got %v", got)
	}
	if len(warnings) != 1 || !strings.Contains(warnings[0], "case-insensitively") {
		t.Errorf("want one case-insensitivity note, got %v", warnings)
	}
	// 3 directories (/, /admin, /admin/users) rather than one per variant.
	if perDir := int64(len(words) + 6); reqs.Load() > 3*perDir+10 {
		t.Errorf("sent %d requests; case variants were scanned as separate directories", reqs.Load())
	}
}

// A case-SENSITIVE server must keep distinct pages that differ only by case.
func TestCaseSensitiveTargetKeepsVariants(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/admin":
			page(w, 200, "<h1>Admin console</h1><p>restricted staff area with many controls</p>")
		case "/Admin":
			page(w, 200, "<h1>Legacy portal</h1><ul><li>archive of older reports and exports</li></ul>")
		default:
			page(w, 404, "<h1>Not Found</h1>")
		}
	}))
	defer srv.Close()
	results, warnings := runScan(t, srv.URL, append([]string{"admin", "Admin"}, noise...), 0)
	if got := foundPaths(srv.URL, results); fmt.Sprint(got) != "[/Admin /admin]" {
		t.Errorf("got %v", got)
	}
	if len(warnings) != 0 {
		t.Errorf("unexpected warnings: %v", warnings)
	}
}

// 429 must never be reported as a finding, and unchecked paths are reported.
func TestRateLimitedResponsesAreNotFindings(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/s") {
			w.Header().Set("Retry-After", "0")
			page(w, 429, "<h1>Too Many Requests</h1>")
			return
		}
		if !realPages(w, r.URL.Path) {
			page(w, 404, "<h1>Not Found</h1>")
		}
	}))
	defer srv.Close()
	results, warnings := runScan(t, srv.URL, append([]string{"admin"}, noise...), 0)
	for _, r := range results {
		if r.Status == 429 {
			t.Errorf("429 reported as a finding: %s", r.URL)
		}
	}
	if len(warnings) != 1 || !strings.Contains(warnings[0], "rate-limited") {
		t.Errorf("want one rate-limit warning, got %v", warnings)
	}
}

// A wordlist entry ending in "/" must not produce "//" in recursed paths.
func TestRecursionNeverProducesDoubleSlash(t *testing.T) {
	var bad atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "//") {
			bad.Add(1)
		}
		switch r.URL.Path {
		case "/logs/", "/logs":
			page(w, 200, "<h1>Log viewer</h1><p>pick a file from the rotation archive to inspect</p>")
		default:
			page(w, 404, "<h1>Not Found</h1>")
		}
	}))
	defer srv.Close()
	runScan(t, srv.URL, append([]string{"logs/"}, noise...), 1)
	if bad.Load() != 0 {
		t.Errorf("%d requests contained //", bad.Load())
	}
}

// Sensitive files below the root are found when discovery found the
// directory.
func TestScanSensitiveAllCoversDiscoveredDirectories(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/public/.env" {
			w.Write([]byte("DB_PASSWORD=x\n"))
			return
		}
		page(w, 404, "<h1>Not Found</h1>")
	}))
	defer srv.Close()
	results := []Result{{URL: srv.URL + "/public", Status: 200, ContentType: "text/html"}}
	findings, skipped := ScanSensitiveAll(context.Background(), testEngine(), srv.URL, results)
	if len(findings) != 1 || findings[0].URL != srv.URL+"/public/.env" || skipped != 0 {
		t.Errorf("got %+v skipped=%d", findings, skipped)
	}
}

func TestScanSensitiveAllCapsDirectories(t *testing.T) {
	var reqs atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reqs.Add(1)
		w.WriteHeader(404)
	}))
	defer srv.Close()
	var results []Result
	for i := 0; i < 40; i++ {
		results = append(results, Result{URL: fmt.Sprintf("%s/d%d", srv.URL, i), Status: 200, ContentType: "text/html"})
	}
	_, skipped := ScanSensitiveAll(context.Background(), testEngine(), srv.URL, results)
	if skipped != 30 {
		t.Errorf("skipped = %d, want 30", skipped)
	}
	if max := int64(11 * (len(sensitiveTargets) + len(wildcardShapes))); reqs.Load() > max {
		t.Errorf("sent %d requests, cap is %d", reqs.Load(), max)
	}
}

var _ = engine.Request{}

func TestEncodePath(t *testing.T) {
	cases := map[string]string{
		"/admin":            "/admin",
		"/a b c":            "/a%20b%20c",
		"/admin#frag":       "/admin%23frag",
		"/index.php?id=1&x": "/index.php?id=1&x",
		"/%2e%2e/x":         "/%2e%2e/x",
		"/%zz":              "/%25zz",
		"/100%":             "/100%25",
		"/ünï":              "/%C3%BCn%C3%AF",
		"/a\xff\x00b":       "/a%FF%00b",
		"/<script>":         "/%3Cscript%3E",
		"/back\\slash":      "/back%5Cslash",
		"/tab\there":        "/tab%09here",
	}
	for in, want := range cases {
		if got := encodePath(in); got != want {
			t.Errorf("encodePath(%q) = %q, want %q", in, got, want)
		}
	}
}

// A wordlist full of entries a URL cannot carry literally must neither
// crash nor invent findings, and a '#' entry must not alias the real page.
func TestHostileWordlistProducesOnlyRealFindings(t *testing.T) {
	var malformed atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.ContainsAny(r.RequestURI, " #\x00") {
			malformed.Add(1)
		}
		if !realPages(w, r.URL.Path) {
			page(w, 404, "<h1>Not Found</h1>")
		}
	}))
	defer srv.Close()

	words := []string{"admin", "users", "admin#frag", "a b c", "\ttab", "ünïcödé", "日本語", "\xff\xfe\x80bad",
		"//double", "/leading", "trailing/", ".", "..", "\\back\\slash", "<script>alert(1)</script>", "{{7*7}}",
		"$(id)", "`id`", "http://evil.example/", ":colon", "@at", "with%00null", "%zz", "%", strings.Repeat("A", 9000), ""}
	results, _ := runScan(t, srv.URL, words, 2)
	if got := foundPaths(srv.URL, results); fmt.Sprint(got) != "[/admin /admin/users]" {
		t.Errorf("got %v", got)
	}
	if malformed.Load() != 0 {
		t.Errorf("%d requests reached the server with a raw space, '#' or NUL in the request line", malformed.Load())
	}
}

// With the minimum of two calibration probes the instability of a changing
// not-found page can go unnoticed up front; the re-verification pass must
// still keep the result clean.
func TestTwoProbeCalibrationStillClean(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if realPages(w, r.URL.Path) {
			return
		}
		page(w, 200, fmt.Sprintf(`<h1>Oops</h1><p>The page %s could not be found on this server.</p><input type=hidden name=csrf value=%x><p>Generated %s request %d</p><p>Try the search, the sitemap or head back home to continue browsing our catalogue.</p>`,
			r.URL.Path, rand.Int63(), time.Now().Format(time.RFC3339Nano), rand.Int()))
	}))
	defer srv.Close()

	words := append([]string{"admin", "users"}, noise...)
	for round := 0; round < 8; round++ {
		var warnings []string
		d := New(testEngine(), Options{BaseURL: srv.URL, Wordlist: words, CalibrationN: 2, MaxDepth: 2,
			OnWarning: func(string, error) { warnings = append(warnings, "") }})
		results, _ := d.Run(context.Background(), "/")
		if got := foundPaths(srv.URL, results); fmt.Sprint(got) != "[/admin /admin/users]" {
			t.Fatalf("round %d: got %d findings: %v", round, len(got), got)
		}
	}
}

func TestCrawlSkipsDeadLinksLogoutSessionVariantsAndJunk(t *testing.T) {
	var logout, long atomic.Int64
	fetched := map[string]*atomic.Int64{"/a": {}}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/":
			page(w, 200, `<a href="/a?sid=1">1</a> <a href="/a?sid=2">2</a> <a href="/a?sid=3">3</a> <a href="/dead">d</a>
<a href="/logout">out</a> <a href="/account/sign-out?next=/">out2</a> <a href="/`+strings.Repeat("A", 5000)+`">long</a> <a href="/a?sid=4&page=2">other params</a>`)
		case r.URL.Path == "/a":
			fetched["/a"].Add(1)
			page(w, 200, `<a href="/a?sid=99">again</a>`)
		case strings.Contains(r.URL.Path, "out"):
			logout.Add(1)
			page(w, 200, "bye")
		case len(r.URL.Path) > 3000:
			long.Add(1)
			page(w, 404, "nf")
		default:
			page(w, 404, "nf")
		}
	}))
	defer srv.Close()

	results := Crawl(context.Background(), testEngine(), srv.URL, 5, 100)
	for _, r := range results {
		if r.Status == 404 {
			t.Errorf("dead link reported: %s", r.URL)
		}
	}
	if logout.Load() != 0 {
		t.Errorf("crawler followed %d logout link(s)", logout.Load())
	}
	if long.Load() != 0 {
		t.Error("crawler requested a 5000-character link")
	}
	// /a?sid=N is one page; /a?sid=N&page=M is a second parameter set.
	if n := fetched["/a"].Load(); n != 2 {
		t.Errorf("/a fetched %d times, want 2 (once per distinct parameter set)", n)
	}
	for _, w := range WordsFromCrawl([]CrawlResult{{URL: srv.URL + "/" + strings.Repeat("B", 200) + "/ok"}}) {
		if len(w) > 64 {
			t.Errorf("over-long crawl segment became a fuzz word (%d chars)", len(w))
		}
	}
}
