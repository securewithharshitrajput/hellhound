package discover

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/securewithharshitrajput/hellhound/internal/engine"
)

const blockBody = "<html><body><h1>Access denied</h1><p>Your request was blocked by the security service.</p></body></html>"

func blockPage(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "text/html")
	w.WriteHeader(403)
	fmt.Fprint(w, blockBody)
}

func homeSnapshot(t *testing.T, base string) *HomeSnapshot {
	t.Helper()
	r := testEngine().Do(context.Background(), engine.Request{Method: "GET", URL: base + "/"})
	return SnapshotHome(r)
}

func noBlockPause(t *testing.T) {
	old := blockPause
	blockPause = 0
	t.Cleanup(func() { blockPause = old })
}

type warnings struct {
	mu   sync.Mutex
	list []string
}

func (w *warnings) add(_ string, err error) {
	w.mu.Lock()
	w.list = append(w.list, err.Error())
	w.mu.Unlock()
}

func (w *warnings) joined() string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return strings.Join(w.list, "\n")
}

// A firewall that starts blocking partway through the scan (the Hostinger
// case: every path, the homepage included, suddenly gets one 403 page) must
// not turn its block page into findings.
func TestFirewallBlockMidScanIsNotReported(t *testing.T) {
	noBlockPause(t)
	var tripped atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := r.URL.Path
		if p == "/admin" {
			page(w, 200, "<h1>Admin console</h1><p>staff only area with many controls</p>")
			return
		}
		if strings.HasPrefix(p, "/w") {
			tripped.Store(true) // these words trip the firewall
		}
		if tripped.Load() {
			blockPage(w)
			return
		}
		if p == "/" {
			page(w, 200, "<h1>Welcome</h1><p>the real homepage of the site</p>")
			return
		}
		page(w, 404, "<h1>Not found</h1>")
	}))
	defer srv.Close()

	words := []string{"admin"}
	for i := 0; i < 8; i++ {
		words = append(words, fmt.Sprintf("w%d", i))
	}
	var warn warnings
	d := New(testEngine(), Options{BaseURL: srv.URL, Wordlist: words, CalibrationN: 4, Home: homeSnapshot(t, srv.URL), OnWarning: warn.add})
	results, err := d.Run(context.Background(), "/")
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range results {
		if r.Status == 403 {
			t.Errorf("block page reported as a finding: %s", r.URL)
		}
	}
	if len(results) != 1 || !strings.HasSuffix(results[0].URL, "/admin") {
		t.Errorf("want only /admin, got %d result(s)", len(results))
	}
	if !d.Blocked() || !strings.Contains(warn.joined(), "firewall") {
		t.Errorf("block not reported; blocked=%v warnings=%q", d.Blocked(), warn.joined())
	}
}

// Blocked from the very first request after the start: the directory is
// skipped with an explanation instead of reporting junk.
func TestFirewallBlockAtCalibrationSkipsDirectory(t *testing.T) {
	noBlockPause(t)
	var tripped atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if tripped.Load() {
			blockPage(w)
			return
		}
		page(w, 200, "<h1>Welcome</h1><p>the real homepage of the site</p>")
	}))
	defer srv.Close()
	home := homeSnapshot(t, srv.URL)
	tripped.Store(true)

	var warn warnings
	d := New(testEngine(), Options{BaseURL: srv.URL, Wordlist: []string{"a", "b", "c", "d"}, CalibrationN: 4, Home: home, OnWarning: warn.add, MatchCodes: map[int]bool{403: true}})
	results, _ := d.Run(context.Background(), "/")
	if len(results) != 0 {
		t.Errorf("got %d result(s) from a blocked scan, want 0", len(results))
	}
	if !strings.Contains(warn.joined(), "skipped: the target's firewall") {
		t.Errorf("missing skip explanation: %q", warn.joined())
	}
}

// A site that answers 403 everywhere, its homepage included, has always
// looked like that: it is not a block, and its real pages are still found.
func TestAll403SiteIsNotMistakenForBlock(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(forbidAll))
	defer srv.Close()
	got := scanWith(t, srv.URL, []string{"admin", "users", "teapot", "alpha", "beta", "gamma"}, func(o *Options) {
		o.Home = homeSnapshot(t, srv.URL)
		o.MatchCodes = map[int]bool{403: true}
	})
	if fmt.Sprint(got) != "[200/admin 200/users 403/alpha 403/beta 403/gamma 418/teapot]" {
		t.Errorf("got %v", got)
	}
}

func TestDotfileForbiddenEverywhereIsDropped(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/.") {
			page(w, 403, "Forbidden")
			return
		}
		page(w, 404, "<h1>Not found</h1>")
	}))
	defer srv.Close()
	if got := scanWith(t, srv.URL, []string{".env", ".git/config", "nothing"}, nil); len(got) != 0 {
		t.Errorf("dotfile 403s on a deny-all-dotfiles server reported: %v", got)
	}
}

func TestDotfileForbiddenSpecificallyIsKept(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.env" {
			page(w, 403, "Forbidden")
			return
		}
		page(w, 404, "<h1>Not found</h1>")
	}))
	defer srv.Close()
	d := New(testEngine(), Options{BaseURL: srv.URL, Wordlist: []string{".env"}, CalibrationN: 4})
	results, _ := d.Run(context.Background(), "/")
	if len(results) != 1 || !strings.Contains(results[0].Verdict.Reason, "very likely exists") {
		t.Fatalf("want /.env kept as likely existing, got %+v", results)
	}
}

func TestDescribeHit(t *testing.T) {
	cases := []struct {
		path, ct, loc string
		status, size  int
		want          string
	}{
		{"/test", "", "https://x.tld/test/", 301, 10, "directory (redirects to /test/)"},
		{"/admin", "", "/login?from=%2Fadmin", 307, 0, "needs login"},
		{"/secret", "text/html", "", 403, 10, "forbidden (403)"},
		{"/api/users", "application/json", "", 200, 2048, "JSON endpoint, 2 KB"},
		{"/about", "text/html; charset=utf-8", "", 200, 41175, "page, 40 KB"},
		{"/logo.webp", "", "", 200, 900, "image, 900 bytes"},
	}
	for _, c := range cases {
		if got := describeHit(c.path, c.status, c.ct, c.size, c.loc); !strings.HasPrefix(got, c.want) {
			t.Errorf("describeHit(%s %d) = %q, want prefix %q", c.path, c.status, got, c.want)
		}
	}
}

func TestCrawlTreatsTrailingSlashAsSamePage(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			page(w, 200, `<a href="/courses/">a</a><a href="/courses">b</a>`)
		case "/courses", "/courses/":
			page(w, 200, `<a href="/courses">self</a>`)
		default:
			page(w, 404, "nf")
		}
	}))
	defer srv.Close()
	res := Crawl(context.Background(), testEngine(), srv.URL, 3, 50)
	if len(res) != 1 {
		t.Errorf("want /courses listed once, got %d: %+v", len(res), res)
	}
}

func TestScanExposedCopies(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		long := strings.Repeat("<p>Courses, labs and training for everyone.</p>", 10)
		switch r.URL.Path {
		case "/", "/test/":
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprint(w, "<html><head><title>Acme Institute</title></head><body>"+long+"</body></html>")
		case "/staging/":
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprint(w, "<html><head><title>New design</title></head><body>"+long+"</body></html>")
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	results := []Result{
		{URL: srv.URL + "/test", Status: 301, RedirectTo: srv.URL + "/test/"},
		{URL: srv.URL + "/staging/", Status: 200},
		{URL: srv.URL + "/old", Status: 301, RedirectTo: srv.URL + "/old/"},
		{URL: srv.URL + "/about", Status: 200},
	}
	got := map[string]string{}
	for _, f := range ScanExposedCopies(context.Background(), testEngine(), srv.URL, results) {
		got[strings.TrimPrefix(f.URL, srv.URL)] = f.Severity
	}
	want := map[string]string{"/test/": "medium", "/staging/": "low"}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestMiningReportsBlockedHomepage(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		blockPage(w)
	}))
	defer srv.Close()
	_, st := BuildWordlistStats(context.Background(), testEngine(), srv.URL, nil)
	if !strings.Contains(strings.Join(st.Failed, ","), "homepage (403)") {
		t.Errorf("Failed = %v, want homepage (403) listed", st.Failed)
	}
}
