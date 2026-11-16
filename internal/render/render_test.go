package render

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

func TestArgsConfineTheBrowser(t *testing.T) {
	c := &Chrome{Path: "chrome", Proxy: "http://127.0.0.1:8080", Insecure: true, UserAgent: "ua/1"}
	args, err := c.args("https://app.example.test:8443/a?b=c", "/tmp/p")
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(args, "\n")
	for _, want := range []string{
		"--headless=new", "--dump-dom", "--user-data-dir=/tmp/p", "--incognito",
		"--host-resolver-rules=MAP * ~NOTFOUND, EXCLUDE app.example.test",
		"--proxy-server=http://127.0.0.1:8080", "--ignore-certificate-errors", "--user-agent=ua/1",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("missing argument %q", want)
		}
	}
	if strings.Contains(joined, "--no-sandbox") {
		t.Error("the browser sandbox must never be disabled")
	}
	if args[len(args)-1] != "https://app.example.test:8443/a?b=c" {
		t.Errorf("URL must be the last argument, got %q", args[len(args)-1])
	}
	plain, _ := (&Chrome{Path: "chrome"}).args("http://x.test/", "/tmp/p")
	if s := strings.Join(plain, "\n"); strings.Contains(s, "--proxy-server") || strings.Contains(s, "--ignore-certificate-errors") {
		t.Error("proxy/insecure arguments present without being requested")
	}
}

// A URL must never be interpretable as a browser option.
func TestArgsRejectNonHTTPURLs(t *testing.T) {
	for _, bad := range []string{"--remote-debugging-port=9222", "file:///etc/passwd", "javascript:alert(1)", "chrome://settings", "", "http://"} {
		if _, err := (&Chrome{Path: "chrome"}).args(bad, "/tmp/p"); err == nil {
			t.Errorf("args(%q) accepted", bad)
		}
	}
}

func TestFindExplicitMissing(t *testing.T) {
	if _, err := Find("/definitely/not/a/browser"); err == nil {
		t.Error("missing explicit browser accepted")
	}
}

// End to end against a real local browser, when one is available.
func TestDOMContainsLinksBuiltByJavaScript(t *testing.T) {
	if testing.Short() {
		t.Skip("-short")
	}
	path, err := Find("")
	if err != nil || os.Geteuid() == 0 {
		t.Skip("no usable local browser")
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(`<html><body><div id="r"></div><script>
var a=document.createElement('a'); a.href='/'+['built','at','runtime'].join('-'); a.textContent='x'; document.getElementById('r').appendChild(a);
</script></body></html>`))
	}))
	defer srv.Close()
	c := &Chrome{Path: path, Timeout: 40 * time.Second}
	dom, err := c.DOM(context.Background(), srv.URL+"/")
	if err != nil {
		t.Skipf("browser could not run here: %v", err)
	}
	if !strings.Contains(string(dom), "/built-at-runtime") {
		t.Errorf("rendered DOM lacks the runtime-built link:\n%s", dom)
	}
}

func TestDOMHonoursTimeout(t *testing.T) {
	if testing.Short() {
		t.Skip("-short")
	}
	path, err := Find("")
	if err != nil || os.Geteuid() == 0 {
		t.Skip("no usable local browser")
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { <-r.Context().Done() }))
	defer srv.Close()
	c := &Chrome{Path: path, Timeout: 3 * time.Second}
	start := time.Now()
	if _, err := c.DOM(context.Background(), srv.URL+"/"); err == nil {
		t.Error("expected an error for a page that never loads")
	}
	if d := time.Since(start); d > 12*time.Second {
		t.Errorf("DOM returned after %v; the 3s limit was not enforced", d)
	}
}
