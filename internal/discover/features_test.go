package discover

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/securewithharshitrajput/hellhound/internal/engine"
)

// forbidAll answers 403 identically for everything except a few real pages.
func forbidAll(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/admin":
		page(w, 200, "<h1>Admin console</h1><p>restricted staff area with many controls</p>")
	case "/users":
		page(w, 200, "<h1>User list</h1><table><tr><td>alice</td><td>bob</td></tr></table>")
	case "/teapot":
		page(w, 418, "<h1>teapot</h1>")
	default:
		page(w, 403, "<h1>Forbidden</h1>")
	}
}

func scanWith(t *testing.T, base string, words []string, mutate func(*Options)) []string {
	t.Helper()
	o := Options{BaseURL: base, Wordlist: words, CalibrationN: 6, MaxDepth: 0}
	if mutate != nil {
		mutate(&o)
	}
	results, err := New(testEngine(), o).Run(context.Background(), "/")
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, r := range results {
		out = append(out, fmt.Sprintf("%d%s", r.Status, strings.TrimPrefix(r.URL, base)))
	}
	sort.Strings(out)
	return out
}

func TestManualFilters(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(forbidAll))
	defer srv.Close()
	words := []string{"admin", "users", "teapot", "alpha", "beta", "gamma"}
	set := func(v ...int) map[int]bool {
		m := map[int]bool{}
		for _, x := range v {
			m[x] = true
		}
		return m
	}
	usersSize := len("<html><head><title>t</title></head><body><h1>User list</h1><table><tr><td>alice</td><td>bob</td></tr></table></body></html>")

	cases := []struct {
		name   string
		mutate func(*Options)
		want   string
	}{
		{"calibration only", nil, "[200/admin 200/users 418/teapot]"},
		{"-mc 403 shows the baseline status too", func(o *Options) { o.MatchCodes = set(403) }, "[200/admin 200/users 403/alpha 403/beta 403/gamma 418/teapot]"},
		{"-fc 418", func(o *Options) { o.FilterCodes = set(418) }, "[200/admin 200/users]"},
		{"-fc 200", func(o *Options) { o.FilterCodes = set(200) }, "[418/teapot]"},
		{"filter wins over match", func(o *Options) { o.MatchCodes, o.FilterCodes = set(403), set(403) }, "[200/admin 200/users 418/teapot]"},
		{"-fs", func(o *Options) { o.FilterSizes = set(usersSize) }, "[200/admin 418/teapot]"},
	}
	for _, c := range cases {
		if got := fmt.Sprint(scanWith(t, srv.URL, words, c.mutate)); got != c.want {
			t.Errorf("%s: got %s, want %s", c.name, got, c.want)
		}
	}
}

// -mc on a large wordlist reports every matching path: the hit-rate safety
// nets must leave operator-forced results alone.
func TestMatchCodeResultsSurviveHitRateChecks(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(forbidAll))
	defer srv.Close()
	words := []string{"admin"}
	for i := 0; i < 300; i++ {
		words = append(words, fmt.Sprintf("w%dq", i))
	}
	got := scanWith(t, srv.URL, words, func(o *Options) { o.MatchCodes = map[int]bool{403: true} })
	if len(got) != 301 {
		t.Errorf("got %d results, want 301 (300 forced 403s + /admin)", len(got))
	}
}

// A scan interrupted between directories and resumed from its checkpoint
// must end with exactly the results of an uninterrupted scan, without
// re-scanning completed directories.
func TestResumeFromCheckpointEqualsFullScan(t *testing.T) {
	var perDir sync.Map
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seg := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
		dir := "/"
		if len(seg) > 1 {
			dir = "/" + seg[0]
		}
		n, _ := perDir.LoadOrStore(dir, new(atomic.Int64))
		n.(*atomic.Int64).Add(1)
		switch {
		case len(seg) == 1 && strings.HasPrefix(seg[0], "d") && len(seg[0]) == 2:
			page(w, 200, "<h1>Directory "+seg[0]+"</h1><ul><li>listing "+seg[0]+" "+seg[0]+" items</li></ul>")
		case len(seg) == 2 && seg[1] == "leaf":
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprintf(w, `{"leaf":"%s","owner":"team-%s","data":[1,2,3]}`, seg[0], seg[0])
		default:
			page(w, 404, "<h1>Not Found</h1>")
		}
	}))
	defer srv.Close()
	words := append([]string{"d1", "d2", "d3", "d4", "leaf"}, noise...)
	base := Options{BaseURL: srv.URL, Wordlist: words, CalibrationN: 6, MaxDepth: 1}

	full, _ := New(testEngine(), base).Run(context.Background(), "/")
	want := foundPaths(srv.URL, full)
	if len(want) != 8 {
		t.Fatalf("reference scan found %d, want 8: %v", len(want), want)
	}

	// First run: cancel as soon as two directories are complete.
	ctx, cancel := context.WithCancel(context.Background())
	var saved []byte
	first := base
	first.OnCheckpoint = func(cp Checkpoint) {
		if cp.DirsDone == 2 {
			saved, _ = json.Marshal(cp) // through JSON, as the CLI stores it
			cancel()
		}
	}
	New(testEngine(), first).Run(ctx, "/")
	if saved == nil {
		t.Fatal("no checkpoint after two directories")
	}
	var cp Checkpoint
	if err := json.Unmarshal(saved, &cp); err != nil {
		t.Fatal(err)
	}
	if cp.DirsDone != 2 || len(cp.Pending) != 3 {
		t.Fatalf("checkpoint: %d done, %d pending; want 2 and 3", cp.DirsDone, len(cp.Pending))
	}

	perDir.Range(func(k, v any) bool { v.(*atomic.Int64).Store(0); return true })
	second := base
	second.Resume = &cp
	lastDone := 0
	second.OnCheckpoint = func(c Checkpoint) { lastDone = c.DirsDone }
	resumed, _ := New(testEngine(), second).Run(context.Background(), "/")
	if got := foundPaths(srv.URL, resumed); fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("resumed scan: %v\nfull scan:    %v", got, want)
	}
	if lastDone != 5 {
		t.Errorf("resumed scan ended at %d directories done, want 5", lastDone)
	}
	if n, ok := perDir.Load("/"); ok && n.(*atomic.Int64).Load() != 0 {
		t.Errorf("the root directory was scanned again on resume (%d requests)", n.(*atomic.Int64).Load())
	}
}

func TestProgressCallbackReachesTotal(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(forbidAll))
	defer srv.Close()
	var last [3]int
	calls := 0
	scanWith(t, srv.URL, []string{"admin", "users", "alpha", "beta"}, func(o *Options) {
		o.Extensions = []string{"", ".bak"}
		o.OnProgress = func(dir string, done, total, hits int) {
			calls++
			if done < last[0] {
				t.Errorf("progress went backwards: %d after %d", done, last[0])
			}
			last = [3]int{done, total, hits}
		}
	})
	if calls != 8 || last != [3]int{8, 8, 2} {
		t.Errorf("calls=%d last(done,total,hits)=%v; want 8 calls ending at 8/8 with 2 hits", calls, last)
	}
}

func TestSitemapMining(t *testing.T) {
	var foreign atomic.Int64
	var srvURL string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/robots.txt":
			fmt.Fprintf(w, "User-agent: *\nSitemap: %s/sm-index.xml\nSitemap: http://other.invalid/sitemap.xml\n", srvURL)
		case "/sitemap.xml":
			fmt.Fprintf(w, `<?xml version="1.0"?><urlset>
<url><loc>%[1]s/products/widget-9x7</loc></url>
<url><loc> %[1]s/reports/q3-internal </loc></url>
<url><loc><![CDATA[%[1]s/cdata-page]]></loc></url>
<url><loc>%[1]s/search?q=a&amp;page=2</loc></url>
<url><loc>https://evil.invalid/other-host-only</loc></url></urlset>`, srvURL)
		case "/sm-index.xml":
			fmt.Fprintf(w, `<sitemapindex><sitemap><loc>%s/child.xml.gz</loc></sitemap><sitemap><loc>http://evil.invalid/x.xml</loc></sitemap></sitemapindex>`, srvURL)
		case "/child.xml.gz":
			var b bytes.Buffer
			gz := gzip.NewWriter(&b)
			fmt.Fprintf(gz, `<urlset><url><loc>%s/from-gz/archive</loc></url></urlset>`, srvURL)
			gz.Close()
			w.Header().Set("Content-Type", "application/gzip")
			w.Write(b.Bytes())
		case "/":
			page(w, 200, "home")
		default:
			w.WriteHeader(404)
		}
	}))
	defer srv.Close()
	srvURL = srv.URL

	cfg := engine.DefaultConfig()
	cfg.Allow = func(u string) bool {
		if !strings.HasPrefix(u, srv.URL) {
			foreign.Add(1)
			return false
		}
		return true
	}
	words := BuildWordlist(context.Background(), engine.New(cfg), srv.URL, nil)
	have := map[string]bool{}
	for _, w := range words {
		have[w] = true
	}
	for _, want := range []string{"products/widget-9x7", "widget-9x7", "reports/q3-internal", "q3-internal", "cdata-page", "from-gz/archive", "archive", "search"} {
		if !have[want] {
			t.Errorf("sitemap word %q missing", want)
		}
	}
	for _, bad := range []string{"other-host-only", "x.xml"} {
		if have[bad] {
			t.Errorf("word %q came from another host's sitemap entry", bad)
		}
	}
	if foreign.Load() != 0 {
		t.Errorf("%d request(s) were attempted to another host", foreign.Load())
	}
}

func TestSitemapIsBounded(t *testing.T) {
	var fetched atomic.Int64
	var srvURL string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/sm") || r.URL.Path == "/sitemap.xml" {
			fetched.Add(1)
			// every sitemap is an index pointing at 50 more
			fmt.Fprint(w, "<sitemapindex>")
			for i := 0; i < 50; i++ {
				fmt.Fprintf(w, "<sitemap><loc>%s/sm%s-%d.xml</loc></sitemap>", srvURL, strings.Trim(r.URL.Path, "/"), i)
			}
			fmt.Fprint(w, "</sitemapindex>")
			return
		}
		w.WriteHeader(404)
	}))
	defer srv.Close()
	srvURL = srv.URL
	BuildWordlist(context.Background(), testEngine(), srv.URL, nil)
	if n := fetched.Load(); n > maxSitemapFiles {
		t.Errorf("fetched %d sitemap files, cap is %d", n, maxSitemapFiles)
	}
}

func TestCrawlWithRendererFollowsRenderedLinks(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			page(w, 200, `<a href="/static">s</a><div id="root"></div>`)
		case "/static", "/built-by-js", "/second-hop":
			page(w, 200, "content of "+r.URL.Path)
		case "/data.json":
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte("{}"))
		default:
			w.WriteHeader(404)
		}
	}))
	defer srv.Close()

	var rendered sync.Map
	fake := func(ctx context.Context, u string) ([]byte, error) {
		rendered.Store(strings.TrimPrefix(u, srv.URL), true)
		switch strings.TrimPrefix(u, srv.URL) {
		case "", "/":
			return []byte(`<a href="/built-by-js">x</a> <a href="/data.json">d</a> <a href="http://elsewhere.invalid/x">off-site</a>`), nil
		case "/built-by-js":
			return []byte(`<a href="/second-hop">y</a>`), nil
		case "/static":
			return nil, fmt.Errorf("browser crashed")
		}
		return []byte("<html></html>"), nil
	}
	var renderErrs atomic.Int64
	results := CrawlWith(context.Background(), testEngine(), srv.URL, 3, 50, fake, func(string, error) { renderErrs.Add(1) })
	got := map[string]bool{}
	for _, r := range results {
		got[strings.TrimPrefix(r.URL, srv.URL)] = true
	}
	for _, want := range []string{"/static", "/built-by-js", "/second-hop", "/data.json"} {
		if !got[want] {
			t.Errorf("%s not crawled; got %v", want, got)
		}
	}
	if len(got) != 4 {
		t.Errorf("crawled %v, want exactly 4 same-host pages", got)
	}
	if _, ok := rendered.Load("/data.json"); ok {
		t.Error("a JSON response was sent to the renderer")
	}
	if renderErrs.Load() != 1 {
		t.Errorf("render errors reported = %d, want 1 (and the crawl must continue)", renderErrs.Load())
	}
	// Without a renderer only the static link is found.
	if plain := Crawl(context.Background(), testEngine(), srv.URL, 3, 50); len(plain) != 1 {
		t.Errorf("static crawl found %d pages, want 1", len(plain))
	}
}
