package main

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestHeaderFlagSet(t *testing.T) {
	cases := []struct {
		name    string
		input   string
		wantKey string
		wantVal string
		wantErr bool
	}{
		{"basic", "X-Foo: bar", "X-Foo", "bar", false},
		{"extra whitespace trimmed", "  X-Foo  :   bar  ", "X-Foo", "bar", false},
		{"value containing a colon (e.g. a URL)", "Referer: http://x.y/z:80", "Referer", "http://x.y/z:80", false},
		{"no colon is an error", "not-a-header", "", "", true},
		{"empty value is fine", "X-Empty:", "X-Empty", "", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			h := headerFlag{}
			err := h.Set(c.input)
			if c.wantErr {
				if err == nil {
					t.Fatalf("expected an error for input %q, got none", c.input)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error for input %q: %v", c.input, err)
			}
			if got := h[c.wantKey]; got != c.wantVal {
				t.Errorf("h[%q] = %q, want %q", c.wantKey, got, c.wantVal)
			}
		})
	}
}

func TestHeaderFlagSetIsRepeatable(t *testing.T) {
	h := headerFlag{}
	h.Set("X-One: a")
	h.Set("X-Two: b")
	if len(h) != 2 {
		t.Fatalf("expected 2 headers after two Set calls, got %d: %v", len(h), h)
	}
	if h["X-One"] != "a" || h["X-Two"] != "b" {
		t.Errorf("header values wrong: %v", h)
	}
}

func TestLoadWordlistFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "words.txt")
	content := "admin\n\n  backup  \n# a comment line\napi\r\n"
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("setup: %v", err)
	}

	got := loadWordlistFile(path)
	want := []string{"admin", "backup", "api"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v (blank lines, comments, and CRLF should all be handled)", got, want)
	}
}

func TestLoadWordlistFileEmptyPath(t *testing.T) {
	if got := loadWordlistFile(""); got != nil {
		t.Errorf("expected nil for an empty path, got %v", got)
	}
}

func TestLoadWordlistFileMissingFile(t *testing.T) {
	// Should warn to stderr and return nil, not panic or error out — a
	// missing -w file shouldn't crash the whole run, just mean "no extra
	// words from that source".
	got := loadWordlistFile("/nonexistent/path/that/does/not/exist.txt")
	if got != nil {
		t.Errorf("expected nil for a missing file, got %v", got)
	}
}
