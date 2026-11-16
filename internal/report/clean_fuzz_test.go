package report

import (
	"testing"
	"unicode/utf8"
)

func FuzzClean(f *testing.F) {
	for _, s := range []string{"plain", "\x1b[31m", "a\u009bb", "\xff\xfe", "‮", "=1", ""} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		out := Clean(s)
		if !utf8.ValidString(out) {
			t.Fatalf("Clean(%q) is not valid UTF-8", s)
		}
		if hasControl(out) {
			t.Fatalf("Clean(%q) = %q still has control characters", s, out)
		}
		if Clean(out) != out {
			t.Fatalf("Clean is not idempotent for %q", s)
		}
		if c := csvCell(s); c != "" && (c[0] == '=' || c[0] == '+' || c[0] == '-' || c[0] == '@') {
			t.Fatalf("csvCell(%q) = %q starts with a formula trigger", s, c)
		}
	})
}
