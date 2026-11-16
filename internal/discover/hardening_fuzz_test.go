package discover

import (
	"strings"
	"testing"
	"unicode/utf8"
)

// FuzzSensitiveMatchers feeds arbitrary bodies to every sensitive-file
// matcher and the HTML guard: none may panic, and evidence must stay short
// and printable whatever the target sends back.
func FuzzSensitiveMatchers(f *testing.F) {
	f.Add([]byte("DB_PASSWORD=x\n"))
	f.Add([]byte("<!DOCTYPE html><html><body>=:\"</body></html>"))
	f.Add([]byte("-----BEGIN RSA PRIVATE KEY-----\n\x00\xff\xfe"))
	f.Add([]byte(`{"client_secret":"x"}`))
	f.Add([]byte("admin:$apr1$abc\n"))
	f.Add([]byte{0xff, 0xfe, 0x00, 0x80})
	f.Fuzz(func(t *testing.T, body []byte) {
		looksLikeHTML(body)
		matchesWildcard(body, "/.env", []uint64{0, 1 << 63})
		for _, p := range sensitiveTargets {
			ev, ok := p.Match(body)
			if !ok {
				continue
			}
			if len(ev) > 200 {
				t.Fatalf("%s: evidence too long (%d bytes)", p.Path, len(ev))
			}
			if !utf8.ValidString(ev) {
				t.Fatalf("%s: evidence is not valid UTF-8: %q", p.Path, ev)
			}
			if strings.ContainsAny(ev, "\n\r\x00\x1b") {
				t.Fatalf("%s: evidence contains control characters: %q", p.Path, ev)
			}
		}
	})
}

// FuzzTierAParsers covers the remaining parsers that read target-controlled
// input: directory-listing detection, Location classification, the Allow
// header, tech fingerprints and header severity.
func FuzzTierAParsers(f *testing.F) {
	f.Add("<title>Index of /x</title>", "https://example.org/a", "GET, PUT")
	f.Add("", "//example.org", ",,,")
	f.Add("\xff<h1>Index of /", "/\\example.org", "trace")
	f.Add("x", "http://[::1", "\x00")
	f.Fuzz(func(t *testing.T, body, loc, allow string) {
		if ev, ok := DetectDirListing([]byte(body)); ok && len(ev) > 100 {
			t.Fatalf("dir-listing evidence too long: %d", len(ev))
		}
		redirectsExternally(loc)
		parseAllowHeader(allow)
		matchFingerprints([]byte(body), map[string][]string{"X-Powered-By": {allow}, "Set-Cookie": {loc}})
		classifyHeaderSeverity(allow, loc)
		describeHeader(allow, loc)
		schemeAndHostOf(loc)
		res := []Result{{URL: loc, Status: 200, BodyPreview: []byte(body), Headers: map[string]string{"Server": allow, "Via": body}}}
		ClassifyDirListings(res)
		for _, sf := range CaptureInfoDisclosure(res) {
			if len(sf.Evidence) > 200 {
				t.Fatalf("header evidence too long: %d", len(sf.Evidence))
			}
		}
	})
}
