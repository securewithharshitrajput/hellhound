package discover

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/securewithharshitrajput/hellhound/internal/engine"
)

func TestJSEndpoints(t *testing.T) {
	src := []byte("fetch('/api/Users'); x=\"./local/data\"; y=`/rest/user/login?next=1`; z='//cdn.example.com/lib.js'; " +
		"w='/api/Users/:id'; a='/img/logo.png'; b='/static/app.js.map'; c='application/json'; d='/'; e=\"/o\"; f='https://x.example.org/v1/items'")
	got := jsEndpoints(src)
	sort.Strings(got)
	want := []string{"./local/data", "/api/Users", "/rest/user/login?next=1", "https://x.example.org/v1/items"}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("jsEndpoints = %v, want %v", got, want)
	}
}

func TestExtraLinkSources(t *testing.T) {
	body := []byte(`<html><head><base href="/app/"><meta http-equiv="refresh" content="3; url=/moved/here">
<img srcset="/a.png 1x, /b.png 2x"><button formaction="/do/it">x</button><div hx-get="/htmx/part"></div></head></html>`)
	if got := baseHref(body); got != "/app/" {
		t.Errorf("baseHref = %q", got)
	}
	if got := metaRefreshLinks(body); len(got) != 1 || got[0] != "/moved/here" {
		t.Errorf("metaRefreshLinks = %v", got)
	}
	if got := srcsetLinks(body); fmt.Sprint(got) != "[/a.png /b.png]" {
		t.Errorf("srcsetLinks = %v", got)
	}
	links := strings.Join(extractLinks(body), " ")
	for _, want := range []string{"/do/it", "/htmx/part"} {
		if !strings.Contains(links, want) {
			t.Errorf("extractLinks missed %s: %s", want, links)
		}
	}
	h := http.Header{}
	h.Add("Link", `</preload/font>; rel=preload, </next?page=2>; rel=next`)
	h.Set("Refresh", "0; url=/r/target")
	h.Set("Content-Location", "/canonical")
	if got := headerLinks(h); fmt.Sprint(got) != "[/preload/font /next?page=2 /r/target /canonical]" {
		t.Errorf("headerLinks = %v", got)
	}
}

func TestExtractFormsAndClassify(t *testing.T) {
	page, _ := url.Parse("http://site.example/account/")
	body := []byte(`<form action="/login" method="post"><input name="user"><input type="password" name="pass">
<input type="hidden" name="csrf_token" value="x"><input type="submit" value="go"></form>
<form action="up" method="POST" enctype="multipart/form-data"><input type="file" name="doc"></form>
<form><input name="q"></form>`)
	forms := ExtractForms(body, page)
	if len(forms) != 3 {
		t.Fatalf("got %d forms, want 3: %+v", len(forms), forms)
	}
	login, upload, search := forms[0], forms[1], forms[2]
	if login.Method != "POST" || login.Action != "http://site.example/login" || !login.HasPassword || !login.HasToken || fmt.Sprint(login.Fields) != "[user pass csrf_token]" {
		t.Errorf("login form wrong: %+v", login)
	}
	if !upload.HasFile || upload.Action != "http://site.example/account/up" {
		t.Errorf("upload form wrong: %+v", upload)
	}
	if search.Method != "GET" || search.Action != "http://site.example/account/" {
		t.Errorf("search form wrong: %+v", search)
	}
	types := map[string]string{}
	for _, f := range ClassifyForms(forms) {
		types[f.Type] = f.Severity
	}
	// The login form posts to plain http, so it is the insecure variant.
	if types["insecure-form"] != "medium" || types["upload-form"] != "low" || len(types) != 2 {
		t.Errorf("ClassifyForms = %v", types)
	}
	secure := ClassifyForms([]Form{{Page: "https://s/", Action: "https://s/login", Method: "POST", Fields: []string{"p"}, HasPassword: true}})
	if len(secure) != 1 || secure[0].Type != "login-form" || secure[0].Severity != "info" {
		t.Errorf("https login form = %+v", secure)
	}
}

func TestURLPatternSlugAndDate(t *testing.T) {
	pat := func(s string) string { u, _ := url.Parse(s); return URLPattern(u) }
	cases := map[string]string{
		"http://x/courses/Complete-Data-Science-6aac2df9c0c67432264be265": "/courses/{slug}-{id}",
		"http://x/blog/my-first-post-12345":                               "/blog/{slug}-{id}",
		"http://x/archive/2026-11-18":                                     "/archive/{id}",
		"http://x/orders/1700000000000":                                   "/orders/{id}",
		"http://x/about-us":                                               "/about-us",
		"http://x/web-3d":                                                 "/web-3d",
		"http://x/decaffed-facade":                                        "/decaffed-facade", // hex-only words are not ids
	}
	for in, want := range cases {
		if got := pat(in); got != want {
			t.Errorf("URLPattern(%s) = %q, want %q", in, got, want)
		}
	}
}

// One mock site that hides pages behind every new link source.
func TestCrawlFollowsEveryLinkSource(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			w.Header().Set("Link", "</via-link-header>; rel=preload")
			page(w, 200, `<base href="/app/"><a href="rel-page">r</a><script src="/static/main.js"></script>
<script>fetch("/inline-api/ping")</script><meta http-equiv="refresh" content="9; url=/meta-target">
<img srcset="/set-img-a.html 1x"><form action="/submit-here" method="post"><input name="email"></form>`)
		case "/app/rel-page":
			page(w, 200, "relative to base")
		case "/static/main.js":
			w.Header().Set("Content-Type", "application/javascript")
			fmt.Fprint(w, `const a="/api/from-js/list"; const b="/img/x.png"; const c="/api/Users/:id";`)
		case "/api/from-js/list", "/inline-api/ping", "/meta-target", "/set-img-a.html", "/via-link-header", "/redirected-to":
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `{"ok":true}`)
		case "/old":
			http.Redirect(w, r, "/redirected-to", http.StatusFound)
		case "/submit-here":
			w.WriteHeader(405)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	// "/old" is only reachable through a redirect from a linked page.
	srvMux := http.NewServeMux()
	_ = srvMux

	res, stats := CrawlOpts(context.Background(), testEngine(), srv.URL, CrawlConfig{MaxDepth: 3, MaxPages: 100})
	got := map[string]bool{}
	for _, r := range res {
		got[strings.TrimPrefix(r.URL, srv.URL)] = true
	}
	for _, want := range []string{"/app/rel-page", "/api/from-js/list", "/inline-api/ping", "/meta-target", "/set-img-a.html", "/via-link-header", "/submit-here"} {
		if !got[want] {
			t.Errorf("crawl missed %s; found %v", want, got)
		}
	}
	for _, bad := range []string{"/api/Users/:id", "/img/x.png"} {
		if got[bad] {
			t.Errorf("crawl requested %s, which should have been skipped", bad)
		}
	}
	if len(stats.Forms) != 1 || stats.Forms[0].Method != "POST" || fmt.Sprint(stats.Forms[0].Fields) != "[email]" {
		t.Errorf("forms = %+v", stats.Forms)
	}
}

func TestCrawlFollowsRedirectTargets(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			page(w, 200, `<a href="/old">old</a>`)
		case "/old":
			http.Redirect(w, r, "/login-page", http.StatusFound)
		case "/login-page":
			page(w, 200, "login")
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	res := Crawl(context.Background(), testEngine(), srv.URL, 3, 50)
	found := false
	for _, r := range res {
		if strings.HasSuffix(r.URL, "/login-page") {
			found = true
		}
	}
	if !found {
		t.Errorf("redirect target /login-page not reached: %+v", res)
	}
}

func TestResponseFilters(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(forbidAll))
	defer srv.Close()
	words := []string{"admin", "users", "teapot", "alpha", "beta", "gamma"}
	probe := testEngine().Do(context.Background(), engine.Request{Method: "GET", URL: srv.URL + "/teapot"})
	if probe.Err != nil {
		t.Fatal(probe.Err)
	}
	cases := []struct {
		name   string
		mutate func(*Options)
		want   string
	}{
		{"-fw hides the teapot's word count", func(o *Options) { o.FilterWords = map[int]bool{probe.Words: true} }, "[200/admin 200/users]"},
		{"-fl hides pages with that line count (all mock pages have one line)", func(o *Options) { o.FilterLines = map[int]bool{probe.Lines: true} }, "[]"},
		{"-fl with another count hides nothing", func(o *Options) { o.FilterLines = map[int]bool{probe.Lines + 50: true} }, "[200/admin 200/users 418/teapot]"},
		{"-fr hides bodies with 'Admin console'", func(o *Options) { o.FilterRegex = regexp.MustCompile(`Admin console`) }, "[200/users 418/teapot]"},
		{"-mr shows forbidden bodies", func(o *Options) { o.MatchRegex = regexp.MustCompile(`Forbidden`) }, "[200/admin 200/users 403/alpha 403/beta 403/gamma 418/teapot]"},
		{"-fr wins over -mr", func(o *Options) {
			o.MatchRegex, o.FilterRegex = regexp.MustCompile(`Forbidden`), regexp.MustCompile(`Forbidden`)
		}, "[200/admin 200/users 418/teapot]"},
	}
	for _, c := range cases {
		if got := fmt.Sprint(scanWith(t, srv.URL, words, c.mutate)); got != c.want {
			t.Errorf("%s: got %s, want %s", c.name, got, c.want)
		}
	}
}

// Some dev servers serve the same static asset for ANY nested path ending in
// that filename (confirmed live against OWASP Juice Shop: /main.js,
// /x/main.js and /x/y/main.js all return byte-identical JS). Without a
// content-hash guard, each relative <script src="main.js"> on a deeper page
// manufactures a "new" duplicate page report and re-scrapes the same bundle.
func TestCrawlDedupesIdenticalAssetBodies(t *testing.T) {
	const bundle = `const a="/real/api/endpoint";`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/":
			page(w, 200, `<a href="/section/">s</a><script src="main.js"></script>`)
		case r.URL.Path == "/section/":
			page(w, 200, `<script src="main.js"></script>`) // relative: resolves to /section/main.js, same bytes as /main.js
		case strings.HasSuffix(r.URL.Path, "main.js"):
			w.Header().Set("Content-Type", "application/javascript")
			fmt.Fprint(w, bundle)
		case r.URL.Path == "/real/api/endpoint":
			page(w, 200, "ok")
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	res, _ := CrawlOpts(context.Background(), testEngine(), srv.URL, CrawlConfig{MaxDepth: 3, MaxPages: 100})
	jsCount := 0
	for _, r := range res {
		if strings.HasSuffix(r.URL, "main.js") {
			jsCount++
		}
	}
	if jsCount != 1 {
		t.Errorf("got %d main.js entries, want exactly 1 (duplicate bodies should collapse): %+v", jsCount, res)
	}
	found := false
	for _, r := range res {
		if strings.HasSuffix(r.URL, "/real/api/endpoint") {
			found = true
		}
	}
	if !found {
		t.Error("the real endpoint mined from the (first-seen) bundle was lost")
	}
}
