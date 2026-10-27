package wordlist

import "testing"

// FuzzFromJS and FuzzFromRobots feed arbitrary bytes to the route-mining
// regexes. Both process content returned directly BY the target (a JS
// bundle, robots.txt) — content the scanner has zero control over — so a
// malformed or adversarially-crafted file must never panic or hang.
func FuzzFromJS(f *testing.F) {
	seeds := []string{
		`fetch("/api/x")`,
		``,
		`"` + string(make([]byte, 500)) + `"`,
		"\x00\x01\xff\xfe",
		`"/a".repeat(100000)`, // not real JS, just a long-ish string literal shape
	}
	for _, s := range seeds {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, body []byte) {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("FromJS panicked on input %q: %v", body, r)
			}
		}()
		_ = FromJS(body)
	})
}

func FuzzFromRobots(f *testing.F) {
	seeds := []string{
		"User-agent: *\nDisallow: /admin\n",
		"",
		"\x00\xff",
		"Disallow:" + string(make([]byte, 1000)),
	}
	for _, s := range seeds {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, body []byte) {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("FromRobots panicked on input %q: %v", body, r)
			}
		}()
		_ = FromRobots(body)
	})
}
