package discover

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// spaIndex is a realistic catch-all page: attributes, quotes, colons, the
// words "key"/"secret"/"token", inline JS — everything a loose substring
// marker would trip over.
const spaIndex = `<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<title>Acme Dashboard</title>
<link rel="stylesheet" href="/static/app.css">
<script>window.CONFIG = {apiKey: "public-key", csrfToken: "TOKEN_PLACEHOLDER", mode: "production"};
if (a == b) { go home(); }</script>
</head><body style="color: #333">
<div id="root">Loading... press any KEY to continue. Keep your PASSWORD SECRET.</div>
<p>FROM our team: RUN the installer, COPY the license. module federation, go fast.</p>
</body></html>`

// TestScanSensitiveNoFalsePositivesOnCatchAllSPA: a target answering 200
// with the same HTML page for every path must produce zero sensitive-file
// findings.
func TestScanSensitiveNoFalsePositivesOnCatchAllSPA(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write([]byte(spaIndex))
	}))
	defer srv.Close()

	findings := ScanSensitive(context.Background(), testEngine(), srv.URL)
	if len(findings) != 0 {
		t.Errorf("catch-all SPA produced %d false sensitive-file findings, first: %+v", len(findings), findings[0])
	}
}

// TestScanSensitiveNoFalsePositivesOnCatchAllText: same idea, but the
// catch-all body is plain text that echoes the path and happens to contain
// env-looking and key-looking tokens.
func TestScanSensitiveNoFalsePositivesOnCatchAllText(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprintf(w, "status=ok\npath=%s\nMODE=maintenance\nuser:guest\n\"note\": \"secret key rotation pending\"\n", r.URL.Path)
	}))
	defer srv.Close()

	findings := ScanSensitive(context.Background(), testEngine(), srv.URL)
	if len(findings) != 0 {
		t.Errorf("catch-all text target produced %d false findings, first: %+v", len(findings), findings[0])
	}
}

// TestScanSensitiveStillFindsRealFilesOnCatchAllSPA: the SPA guard must not
// hide a real exposed file served alongside the catch-all.
func TestScanSensitiveStillFindsRealFilesOnCatchAllSPA(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.env":
			w.Write([]byte("# prod\nAPP_ENV=production\nexport DB_PASSWORD=\"hunter2\"\nSTRIPE_KEY=sk_live_abc\n"))
		case "/.htpasswd":
			w.Write([]byte("admin:$apr1$x9Zk2f1a$Q0b3fVqk2n9n0u8mT1yK1/\nbob:{SHA}W6ph5Mm5Pz8GgiULbPgzG37mj9g=\n"))
		case "/id_rsa":
			w.Write([]byte("-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAA\n-----END OPENSSH PRIVATE KEY-----\n"))
		case "/package.json":
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"name":"acme","version":"1.0.0","dependencies":{"express":"4.17.1"}}`))
		default:
			w.Header().Set("Content-Type", "text/html")
			w.Write([]byte(spaIndex))
		}
	}))
	defer srv.Close()

	findings := ScanSensitive(context.Background(), testEngine(), srv.URL)
	got := map[string]bool{}
	for _, f := range findings {
		got[strings.TrimPrefix(f.URL, srv.URL)] = true
	}
	for _, want := range []string{"/.env", "/.htpasswd", "/id_rsa", "/package.json"} {
		if !got[want] {
			t.Errorf("real exposed file %s was missed", want)
		}
	}
	if len(findings) != 4 {
		t.Errorf("expected exactly 4 findings, got %d: %+v", len(findings), findings)
	}
}

// TestScanDangerousMethodsCollapsesServerWideAllow: a server that answers
// OPTIONS identically for every path (including nonexistent ones) must not
// produce one finding per URL.
func TestScanDangerousMethodsCollapsesServerWideAllow(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "OPTIONS" {
			w.Header().Set("Allow", "GET, POST, PUT, DELETE, OPTIONS")
			w.WriteHeader(204)
			return
		}
		w.Write([]byte("ok"))
	}))
	defer srv.Close()

	var urls []string
	for i := 0; i < 30; i++ {
		urls = append(urls, fmt.Sprintf("%s/page%d", srv.URL, i))
	}
	findings := ScanDangerousMethods(context.Background(), testEngine(), urls)
	if len(findings) != 1 {
		t.Fatalf("server-wide Allow header should collapse to 1 finding, got %d", len(findings))
	}
	if !strings.Contains(findings[0].Description, "every path") {
		t.Errorf("collapsed finding should say it is server-wide, got %q", findings[0].Description)
	}
}

// TestCaptureInfoDisclosureVolatileHeadersDoNotFlood: headers whose value
// changes on every response (timings, request ids, cache nodes) must yield
// at most one finding per header, not one per response.
func TestCaptureInfoDisclosureVolatileHeadersDoNotFlood(t *testing.T) {
	var results []Result
	for i := 0; i < 40; i++ {
		results = append(results, Result{
			URL:    fmt.Sprintf("http://t.example/p%d", i),
			Status: 200,
			Headers: map[string]string{
				"X-Runtime":   fmt.Sprintf("0.0%d", 10+i),
				"X-Varnish":   fmt.Sprintf("%d", 100000+i),
				"X-Served-By": fmt.Sprintf("cache-node-%d", i),
				"Via":         fmt.Sprintf("1.1 varnish-%d", i),
				"Server":      "nginx/1.21.3",
			},
		})
	}
	findings := CaptureInfoDisclosure(results)
	perHeader := map[string]int{}
	for _, f := range findings {
		perHeader[strings.SplitN(f.Evidence, ":", 2)[0]]++
	}
	for h, n := range perHeader {
		if n > 1 {
			t.Errorf("header %s produced %d findings, want 1", h, n)
		}
	}
	for _, f := range findings {
		if strings.HasPrefix(f.Evidence, "X-Runtime") && f.Severity != "info" {
			t.Errorf("X-Runtime is a timing value, not a version; severity = %q, want info", f.Severity)
		}
	}
}

// TestCaptureInfoDisclosureDeterministicOrder: same input, same output order.
func TestCaptureInfoDisclosureDeterministicOrder(t *testing.T) {
	results := []Result{{
		URL: "http://t.example/", Status: 200,
		Headers: map[string]string{"Server": "Apache/2.4.41", "X-Powered-By": "PHP/7.4.3", "X-Generator": "Drupal 9", "X-AspNet-Version": "4.0.30319"},
	}}
	first := fmt.Sprint(CaptureInfoDisclosure(results))
	for i := 0; i < 30; i++ {
		if got := fmt.Sprint(CaptureInfoDisclosure(results)); got != first {
			t.Fatalf("output order is not deterministic:\n%s\nvs\n%s", first, got)
		}
	}
}

func TestRedirectsExternallyStrictHost(t *testing.T) {
	cases := []struct {
		loc  string
		want bool
	}{
		{"https://example.org/hellhound-open-redirect-canary", true},
		{"//example.org/hellhound-open-redirect-canary", true},
		{"https://EXAMPLE.org/x", true},
		// canary only inside a query string of a same-site redirect: not open
		{"/login?next=https%3A%2F%2Fexample.org%2Fhellhound-open-redirect-canary", false},
		{"//target.tld/login?next=https://example.org/hellhound-open-redirect-canary", false},
		{"https://target.tld/login?next=https://example.org/x", false},
		// lookalike hosts are not the canary
		{"https://notexample.org/x", false},
		{"https://example.org.target.tld/x", false},
		{"/dashboard", false},
		{"", false},
	}
	for _, c := range cases {
		if got := redirectsExternally(c.loc); got != c.want {
			t.Errorf("redirectsExternally(%q) = %v, want %v", c.loc, got, c.want)
		}
	}
}

func TestDetectDirListingRejectsWeakLookalikes(t *testing.T) {
	misses := []string{
		`<html><body><h1>Docs</h1><p>Entries marked [DIR] are folders.</p></body></html>`,
		`<html><body><table><tr><th><a href="?sort=m">Last modified</a></th></tr></table><p>Our changelog</p></body></html>`,
		`<html><body><p>The index of /proc is documented elsewhere.</p></body></html>`,
	}
	for i, m := range misses {
		if ev, ok := DetectDirListing([]byte(m)); ok {
			t.Errorf("case %d: ordinary page classified as dir listing (evidence %q)", i, ev)
		}
	}
	hits := []string{
		`<html><head><title>Index of /backup</title></head><body><h1>Index of /backup</h1><a href="../">../</a></body></html>`,
		`<!DOCTYPE HTML><html><head><title>Directory listing for /logs/</title></head><body><ul><li><a href="a.log">a.log</a></li></ul></body></html>`,
		"<html>\r\n<head><title>Index of /files/</title></head>\r\n<body>\r\n<h1>Index of /files/</h1><hr><pre><a href=\"../\">../</a>\r\n</pre></body></html>",
	}
	for i, h := range hits {
		if _, ok := DetectDirListing([]byte(h)); !ok {
			t.Errorf("case %d: real dir listing missed", i)
		}
	}
}

func TestMatchFingerprintsNoFalseStackOnPlainPages(t *testing.T) {
	body := []byte(`<html><body><p>We moved our blog from WordPress to a static site. See spring.io for the Spring docs.
	Cookies: XSRF-TOKEN is set by our Angular app.</p></body></html>`)
	if got := matchFingerprints(body, map[string][]string{"Server": {"nginx"}}); len(got) != 0 {
		t.Errorf("prose mentioning products was fingerprinted as %v", got)
	}
}

// TestScanSensitiveEvidenceNeverContainsSecretValues: evidence ends up in
// terminals, tickets and CI uploads, so it must name what was found without
// repeating the secret.
func TestScanSensitiveEvidenceNeverContainsSecretValues(t *testing.T) {
	secrets := []string{"hunter2", "sk_live_abc", "b3BlbnNzaC1rZXktdjEAAAAA", "s3cr3t-db-pass", "ghp_tokenvalue123", "Q0b3fVqk2n9n0u8mT1yK1"}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.env":
			w.Write([]byte("DB_PASSWORD=hunter2\nSTRIPE_KEY=sk_live_abc\n"))
		case "/id_rsa":
			w.Write([]byte("-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAA\n-----END OPENSSH PRIVATE KEY-----\n"))
		case "/wp-config.php.bak":
			w.Write([]byte("<?php\ndefine('DB_PASSWORD', 's3cr3t-db-pass');\n"))
		case "/.git-credentials":
			w.Write([]byte("https://bob:ghp_tokenvalue123@github.com\n"))
		case "/.htpasswd":
			w.Write([]byte("admin:$apr1$x9Zk2f1a$Q0b3fVqk2n9n0u8mT1yK1/\n"))
		case "/credentials.json":
			w.Write([]byte(`{"client_secret": "hunter2"}`))
		default:
			w.WriteHeader(404)
		}
	}))
	defer srv.Close()

	findings := ScanSensitive(context.Background(), testEngine(), srv.URL)
	if len(findings) != 6 {
		t.Fatalf("expected 6 findings, got %d: %+v", len(findings), findings)
	}
	for _, f := range findings {
		if f.Evidence == "" {
			t.Errorf("%s: evidence is empty", f.URL)
		}
		for _, s := range secrets {
			if strings.Contains(f.Evidence, s) {
				t.Errorf("%s: evidence leaks secret value %q: %q", f.URL, s, f.Evidence)
			}
		}
	}
}

// TestCrawlDoesNotReportStartPage: a link back to "/" is the start page,
// whether or not the target URL was written with a trailing slash.
func TestCrawlDoesNotReportStartPage(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		if r.URL.Path == "/" {
			w.Write([]byte(`<html><body><a href="/a">a</a></body></html>`))
			return
		}
		w.Write([]byte(`<html><body><a href="/">home</a></body></html>`))
	}))
	defer srv.Close()

	for _, target := range []string{srv.URL, srv.URL + "/"} {
		for _, r := range Crawl(context.Background(), testEngine(), target, 3, 50) {
			if r.URL == srv.URL+"/" || r.URL == srv.URL {
				t.Errorf("target %q: start page reported as a crawl finding: %+v", target, r.URL)
			}
		}
	}
}
