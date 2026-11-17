package discover

import (
	"context"
	"fmt"
	"html"
	"regexp"
	"strings"

	"github.com/securewithharshitrajput/hellhound/internal/engine"
)

// copyDirNames are directory names people use for test, staging, backup and
// old copies of a site. Left reachable on the live domain, such a copy
// usually runs older code than the real site (with whatever bugs were fixed
// since), may point at test databases or debug settings, and gets indexed
// by search engines as duplicate content.
var copyDirNames = map[string]bool{
	"test": true, "testing": true, "test-site": true, "testsite": true,
	"staging": true, "stage": true, "dev": true, "develop": true, "development": true,
	"old": true, "old-site": true, "oldsite": true, "site-old": true, "wp-old": true,
	"backup": true, "backups": true, "bak": true, "copy": true,
	"beta": true, "demo": true, "preview": true, "sandbox": true, "uat": true, "qa": true,
	"temp": true, "tmp": true, "new-site": true, "newsite": true,
}

var titleRe = regexp.MustCompile(`(?is)<title[^>]*>(.*?)</title>`)

// pageTitle returns the whitespace-collapsed <title> of an HTML body.
func pageTitle(body []byte) string {
	m := titleRe.FindSubmatch(body)
	if m == nil {
		return ""
	}
	return strings.Join(strings.Fields(html.UnescapeString(string(m[1]))), " ")
}

// ScanExposedCopies looks at discovered directories named like a test,
// staging or backup area (/test, /staging, /old, ...) and reports the ones
// that serve a public HTML site. When the page carries the same title as
// the live homepage it is a full copy of the site.
func ScanExposedCopies(ctx context.Context, eng *engine.Engine, baseURL string, results []Result) []SecurityFinding {
	seen := map[string]bool{}
	var urls []string
	for _, r := range results {
		if r.Status >= 400 || r.Status < 200 {
			continue
		}
		p := urlPath(r.URL)
		if strings.ContainsAny(p, "?#") || !copyDirNames[strings.ToLower(lastSeg(p))] {
			continue
		}
		if r.Status >= 300 && !strings.HasSuffix(pathOnly(r.RedirectTo), "/") {
			continue // redirects somewhere else (a login page, the homepage)
		}
		u := strings.TrimRight(r.URL, "/") + "/"
		if !seen[u] {
			seen[u] = true
			urls = append(urls, u)
		}
	}
	if len(urls) == 0 || ctx.Err() != nil {
		return nil
	}
	reqs := []engine.Request{{Method: "GET", URL: strings.TrimRight(baseURL, "/") + "/"}}
	for _, u := range urls {
		reqs = append(reqs, engine.Request{Method: "GET", URL: u})
	}
	resps := eng.DoAll(ctx, reqs)
	homeTitle := ""
	if resps[0].Err == nil && resps[0].Status == 200 {
		homeTitle = pageTitle(resps[0].Body)
	}
	var out []SecurityFinding
	for i, resp := range resps[1:] {
		if resp.Err != nil || resp.Status != 200 || len(resp.Body) < 256 ||
			!strings.Contains(strings.ToLower(resp.Header.Get("Content-Type")), "html") {
			continue
		}
		title := pageTitle(resp.Body)
		f := SecurityFinding{Type: "exposed-copy", URL: urls[i]}
		if title != "" && title == homeTitle {
			f.Severity = "medium"
			f.Description = "a copy of the live site is publicly reachable here — test/backup copies usually run older, unpatched code and get indexed by search engines; delete it or put it behind a password"
		} else {
			f.Severity = "low"
			f.Description = "a test/staging/backup area serves a public page here — confirm it is meant to be public, otherwise delete it or put it behind a password"
		}
		if title != "" {
			f.Evidence = fmt.Sprintf("<title>%s</title>", truncateRunes(title, 80))
		}
		out = append(out, f)
	}
	return out
}

func truncateRunes(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n]) + "…"
}
