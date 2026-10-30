package discover

import "testing"

// TestCaptureInfoDisclosureDedupesByHostAndValue verifies the critical
// property: hitting a site that returns "Server: nginx/1.21.3" on 100 URLs
// produces ONE finding, not 100 — otherwise the report drowns in header
// noise and the real stuff gets lost.
func TestCaptureInfoDisclosureDedupesByHostAndValue(t *testing.T) {
	results := make([]Result, 50)
	for i := range results {
		results[i] = Result{
			URL:     "http://target.example/path" + string(rune('a'+i%26)),
			Status:  200,
			Headers: map[string]string{"Server": "nginx/1.21.3", "X-Powered-By": "Express"},
		}
	}
	findings := CaptureInfoDisclosure(results)
	// 2 headers x 1 host = 2 findings max; definitely not 50.
	if len(findings) != 2 {
		t.Errorf("expected 2 deduped findings, got %d: %v", len(findings), findings)
	}
}

// TestCaptureInfoDisclosureSeverity confirms a header with an exact version
// is "low" (useful for CVE lookup) while a generic token like "cloudflare"
// is "info" (CDN awareness, not a weakness).
func TestCaptureInfoDisclosureSeverity(t *testing.T) {
	cases := []struct {
		name   string
		header string
		value  string
		want   string
	}{
		{"nginx with version", "Server", "nginx/1.21.3", "low"},
		{"cloudflare generic", "Server", "cloudflare", "info"},
		{"apache with full version", "Server", "Apache/2.4.41 (Ubuntu)", "low"},
		{"generic server token", "Server", "something-opaque", "info"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := classifyHeaderSeverity(c.header, c.value)
			if got != c.want {
				t.Errorf("classifyHeaderSeverity(%q, %q) = %q, want %q", c.header, c.value, got, c.want)
			}
		})
	}
}

func TestContainsVersion(t *testing.T) {
	for _, v := range []string{"nginx/1.21", "2.4.41", "10.0.19041"} {
		if !containsVersion(v) {
			t.Errorf("containsVersion(%q) = false, want true", v)
		}
	}
	for _, v := range []string{"cloudflare", "apache", "nothing"} {
		if containsVersion(v) {
			t.Errorf("containsVersion(%q) = true, want false", v)
		}
	}
}
