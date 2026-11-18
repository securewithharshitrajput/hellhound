package discover

import (
	"html"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
)

// Link sources beyond <a href>. This follows the approach of katana's
// response parser, which reads far more than anchors: image sets, <base>,
// meta refresh, form actions, htmx attributes, response headers, and the
// endpoints written inside JavaScript. A page's links live in all of them.

var (
	// srcsetRe: "srcset" holds several comma-separated candidates.
	srcsetRe = regexp.MustCompile(`(?i)\bsrcset\s*=\s*["']([^"'<>]+)["']`)
	// metaRefreshRe: <meta http-equiv="refresh" content="0; url=/next">.
	metaRefreshRe = regexp.MustCompile(`(?i)content\s*=\s*["']\s*\d+\s*;\s*url\s*=\s*['"]?([^"'<>]+?)['"]?\s*["']`)
	// baseHrefRe: <base href="/app/"> changes what every relative link means.
	baseHrefRe = regexp.MustCompile(`(?is)<base\s[^>]*?href\s*=\s*["']([^"'<>]+)["']`)
	// scriptBlockRe: inline <script> bodies (no src), mined for endpoints.
	scriptBlockRe = regexp.MustCompile(`(?is)<script\b[^>]*>(.*?)</script>`)
	// linkHeaderRe: <url>; rel="preload" entries of a Link header.
	linkHeaderRe = regexp.MustCompile(`<([^>\s]+)>`)

	// jsEndpointRe finds quoted URL-like strings in JavaScript: absolute
	// paths ("/api/users"), relative ones ("./x", "../x") and full http(s)
	// URLs, with an optional query string. Strings containing template
	// placeholders (":id", "${x}", "{id}") fail to match on purpose: they
	// are not requestable as written.
	jsEndpointRe = regexp.MustCompile("[\"'`]((?:https?://[A-Za-z0-9_.\\-]+(?::\\d{1,5})?)?(?:\\.{1,2}/|/)[A-Za-z0-9_\\-][A-Za-z0-9_\\-/%.~]{1,150}(?:\\?[A-Za-z0-9_\\-=&%.,~+]{0,200})?)[\"'`]")
)

// maxJSEndpoints bounds how many endpoints one script can contribute, so a
// huge bundle cannot flood the crawl.
const maxJSEndpoints = 200

// jsEndpoints returns the distinct URL-like strings found in JavaScript
// source, without static assets (images, fonts, styles, media) that a
// script merely references.
func jsEndpoints(src []byte) []string {
	seen := map[string]bool{}
	var out []string
	for _, m := range jsEndpointRe.FindAllSubmatch(src, -1) {
		s := string(m[1])
		if seen[s] || strings.Contains(s, "//") && !strings.HasPrefix(s, "http") {
			continue
		}
		seen[s] = true
		p := s
		if i := strings.IndexAny(p, "?#"); i >= 0 {
			p = p[:i]
		}
		if IsStaticAsset(p) || strings.HasSuffix(strings.ToLower(p), ".map") {
			continue
		}
		out = append(out, s)
		if len(out) >= maxJSEndpoints {
			break
		}
	}
	return out
}

// inlineScriptEndpoints mines the <script> blocks of an HTML page.
func inlineScriptEndpoints(body []byte) []string {
	var out []string
	for _, m := range scriptBlockRe.FindAllSubmatch(body, -1) {
		if len(m[1]) > 0 {
			out = append(out, jsEndpoints(m[1])...)
		}
	}
	return out
}

// srcsetLinks returns the URLs of every srcset candidate in an HTML body.
func srcsetLinks(body []byte) []string {
	var out []string
	for _, m := range srcsetRe.FindAllSubmatch(body, -1) {
		for _, cand := range strings.Split(html.UnescapeString(string(m[1])), ",") {
			if f := strings.Fields(cand); len(f) > 0 {
				out = append(out, f[0])
			}
		}
	}
	return out
}

// metaRefreshLinks returns the targets of <meta http-equiv="refresh">.
func metaRefreshLinks(body []byte) []string {
	var out []string
	for _, m := range metaRefreshRe.FindAllSubmatch(body, -1) {
		out = append(out, strings.TrimSpace(html.UnescapeString(string(m[1]))))
	}
	return out
}

// baseHref returns the page's <base href> ("" when there is none).
func baseHref(body []byte) string {
	if m := baseHrefRe.FindSubmatch(body); m != nil {
		return strings.TrimSpace(html.UnescapeString(string(m[1])))
	}
	return ""
}

// headerLinks returns URLs a response advertises in its headers: Link
// (preload/next/prev), Refresh and Content-Location.
func headerLinks(h http.Header) []string {
	var out []string
	for _, v := range h.Values("Link") {
		for _, m := range linkHeaderRe.FindAllStringSubmatch(v, -1) {
			out = append(out, m[1])
		}
	}
	for _, v := range h.Values("Refresh") {
		if i := strings.Index(strings.ToLower(v), "url="); i >= 0 {
			out = append(out, strings.Trim(strings.TrimSpace(v[i+4:]), `"'`))
		}
	}
	if v := h.Get("Content-Location"); v != "" {
		out = append(out, v)
	}
	return out
}

// absoluteAgainst resolves raw against base and returns it as a string
// ("" if raw is unparseable). Used to apply a page's <base href> before the
// scope check, which resolves against the page itself.
func absoluteAgainst(base *url.URL, raw string) string {
	ref, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return ""
	}
	return base.ResolveReference(ref).String()
}

// Form is one HTML form seen while crawling.
type Form struct {
	Page        string   `json:"page"`   // page the form was found on
	Action      string   `json:"action"` // absolute URL it submits to
	Method      string   `json:"method"` // GET or POST
	Fields      []string `json:"fields"` // named inputs, in page order
	HasPassword bool     `json:"has_password"`
	HasFile     bool     `json:"has_file"`
	HasToken    bool     `json:"has_token"` // a hidden CSRF-style field is present
}

var (
	formRe     = regexp.MustCompile(`(?is)<form\b([^>]*)>(.*?)</form>`)
	inputRe    = regexp.MustCompile(`(?is)<(input|select|textarea|button)\b([^>]*)>`)
	attrRe     = regexp.MustCompile(`(?is)\b([a-z][a-z0-9_:\-]*)\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'>]+))`)
	csrfNameRe = regexp.MustCompile(`(?i)csrf|xsrf|_token\b|^token$|authenticity|nonce|__requestverificationtoken`)
)

func attrs(s string) map[string]string {
	out := map[string]string{}
	for _, m := range attrRe.FindAllStringSubmatch(s, -1) {
		v := m[2]
		if v == "" {
			v = m[3]
		}
		if v == "" {
			v = m[4]
		}
		out[strings.ToLower(m[1])] = html.UnescapeString(v)
	}
	return out
}

// ExtractForms returns the forms in an HTML body, with actions resolved
// against page. Forms are only described, never submitted.
func ExtractForms(body []byte, page *url.URL) []Form {
	var out []Form
	for _, m := range formRe.FindAllSubmatch(body, 100) {
		fa := attrs(string(m[1]))
		f := Form{Page: page.String(), Method: strings.ToUpper(fa["method"])}
		if f.Method != "POST" {
			f.Method = "GET"
		}
		action := page
		if a := strings.TrimSpace(fa["action"]); a != "" {
			ref, err := url.Parse(a)
			if err != nil {
				continue
			}
			action = page.ResolveReference(ref)
		}
		action.Fragment = ""
		f.Action = action.String()
		seen := map[string]bool{}
		for _, im := range inputRe.FindAllSubmatch(m[2], 200) {
			ia := attrs(string(im[2]))
			typ := strings.ToLower(ia["type"])
			name := ia["name"]
			switch typ {
			case "password":
				f.HasPassword = true
			case "file":
				f.HasFile = true
			case "submit", "button", "reset", "image":
				continue
			}
			if name == "" {
				continue
			}
			if typ == "hidden" && csrfNameRe.MatchString(name) {
				f.HasToken = true
			}
			if !seen[name] {
				seen[name] = true
				f.Fields = append(f.Fields, name)
			}
		}
		out = append(out, f)
	}
	return out
}

// formKey identifies a form for de-duplication across pages: the same
// login form linked from every page is one form.
func formKey(f Form) string {
	fields := append([]string(nil), f.Fields...)
	sort.Strings(fields)
	return f.Method + " " + f.Action + " " + strings.Join(fields, ",")
}

// ClassifyForms turns forms into security findings. Nothing is submitted:
// these describe what the form is, and what to test by hand.
func ClassifyForms(forms []Form) []SecurityFinding {
	var out []SecurityFinding
	for _, f := range forms {
		ev := f.Method + " " + f.Action + " fields: " + strings.Join(f.Fields, ", ")
		switch {
		case f.HasPassword && strings.HasPrefix(strings.ToLower(f.Action), "http://"):
			out = append(out, SecurityFinding{Type: "insecure-form", Severity: "medium", URL: f.Page,
				Description: "a form with a password field submits over unencrypted HTTP — the password can be read by anyone on the network path",
				Evidence:    ev})
		case f.HasPassword:
			out = append(out, SecurityFinding{Type: "login-form", Severity: "info", URL: f.Page,
				Description: "login form found (not submitted) — test it for lockout / rate limiting, default credentials and username enumeration",
				Evidence:    ev})
		}
		if f.HasFile {
			out = append(out, SecurityFinding{Type: "upload-form", Severity: "low", URL: f.Page,
				Description: "file upload form found (not submitted) — test what file types and sizes are accepted and where uploads are served from",
				Evidence:    ev})
		}
	}
	return out
}
