package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestNormalizeTarget(t *testing.T) {
	ok := map[string]string{
		"http://example.test":           "http://example.test",
		"http://example.test/":          "http://example.test",
		"HTTP://Example.test:8080/app/": "http://Example.test:8080/app",
		"https://example.test/a/b":      "https://example.test/a/b",
		"http://[::1]:9102":             "http://[::1]:9102",
		"  http://example.test  ":       "http://example.test",
	}
	for in, want := range ok {
		got, err := normalizeTarget(in)
		if err != nil || got != want {
			t.Errorf("normalizeTarget(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	bad := map[string]string{
		"example.test":                "http://",
		"127.0.0.1:8080":              "http://",
		"ftp://example.test":          "http://",
		"http://":                     "no host",
		"http://example.test/?a=b":    "query string",
		"http://example.test/#frag":   "fragment",
		"http://user:pw@example.test": "credentials",
		"":                            "http://",
	}
	for in, wantMsg := range bad {
		_, err := normalizeTarget(in)
		if err == nil || !strings.Contains(err.Error(), wantMsg) {
			t.Errorf("normalizeTarget(%q) error = %v; want one mentioning %q", in, err, wantMsg)
		}
	}
}

func TestValidateFlags(t *testing.T) {
	good := func() error { return validateFlags(40, 2, 6, 0, 512, 3, 500, 10*time.Second) }
	if err := good(); err != nil {
		t.Fatalf("defaults rejected: %v", err)
	}
	cases := []struct {
		name string
		err  error
		flag string
	}{
		{"c=0", validateFlags(0, 2, 6, 0, 512, 3, 500, time.Second), "-c"},
		{"c<0", validateFlags(-5, 2, 6, 0, 512, 3, 500, time.Second), "-c"},
		{"c huge", validateFlags(100000, 2, 6, 0, 512, 3, 500, time.Second), "-c"},
		{"depth<0", validateFlags(40, -1, 6, 0, 512, 3, 500, time.Second), "-depth"},
		{"calibrate=0", validateFlags(40, 2, 0, 0, 512, 3, 500, time.Second), "-calibrate"},
		{"calibrate=1", validateFlags(40, 2, 1, 0, 512, 3, 500, time.Second), "-calibrate"},
		{"rate<0", validateFlags(40, 2, 6, -3, 512, 3, 500, time.Second), "-rate"},
		{"maxbody=0", validateFlags(40, 2, 6, 0, 0, 3, 500, time.Second), "-maxbody"},
		{"crawl-depth=0", validateFlags(40, 2, 6, 0, 512, 0, 500, time.Second), "-crawl-depth"},
		{"crawl-max=0", validateFlags(40, 2, 6, 0, 512, 3, 0, time.Second), "-crawl-max"},
		{"timeout=0", validateFlags(40, 2, 6, 0, 512, 3, 500, 0), "-timeout"},
		{"timeout tiny", validateFlags(40, 2, 6, 0, 512, 3, 500, time.Nanosecond), "-timeout"},
	}
	for _, c := range cases {
		if c.err == nil || !strings.Contains(c.err.Error(), c.flag) {
			t.Errorf("%s: error = %v; want one naming %s", c.name, c.err, c.flag)
		}
	}
	if err := validateFlags(1, 0, 2, 0, 1, 1, 1, 100*time.Millisecond); err != nil {
		t.Errorf("minimum legal values rejected: %v", err)
	}
}

func TestValidExt(t *testing.T) {
	for _, e := range []string{".bak", ".old", "~", ".tar.gz", ".php7", ".BAK", "_backup"[:0] + ".x-y_z"} {
		if !validExt(e) {
			t.Errorf("validExt(%q) = false", e)
		}
	}
	for _, e := range []string{"bak", "?q", "../x", ".a/b", ". b", ".a..b", "#x", ".x?y"} {
		if validExt(e) {
			t.Errorf("validExt(%q) = true", e)
		}
	}
}

func TestHeaderFlagRejectsInjectionAndBadNames(t *testing.T) {
	for _, v := range []string{"X-A: b\nInjected: yes", "X-A: b\r\nX: y", ": v", "Bad Name: v", "X-A: a\x00b", "Na(me: v"} {
		if err := (headerFlag{}).Set(v); err == nil {
			t.Errorf("Set(%q) accepted", v)
		}
	}
	h := headerFlag{}
	if err := h.Set("Authorization: Bearer a:b:c"); err != nil || h["Authorization"] != "Bearer a:b:c" {
		t.Errorf("valid header with colons in the value mishandled: %v %v", err, h)
	}
}

func TestReadListFile(t *testing.T) {
	dir := t.TempDir()
	if got, err := readListFile("-w", ""); got != nil || err != nil {
		t.Errorf("empty path: %v %v", got, err)
	}
	if _, err := readListFile("-w", filepath.Join(dir, "missing.txt")); err == nil {
		t.Error("missing file accepted")
	}
	if _, err := readListFile("-w", dir); err == nil || !strings.Contains(err.Error(), "directory") {
		t.Errorf("directory accepted: %v", err)
	}
	empty := filepath.Join(dir, "empty.txt")
	os.WriteFile(empty, []byte("\n  \n# only a comment\n"), 0o644)
	if _, err := readListFile("-w", empty); err == nil {
		t.Error("file with no entries accepted")
	}
	good := filepath.Join(dir, "good.txt")
	os.WriteFile(good, []byte("\xef\xbb\xbfadmin\r\nadmin\n  users  \n\n#c\napi\n"), 0o644)
	got, err := readListFile("-w", good)
	if err != nil || strings.Join(got, ",") != "admin,users,api" {
		t.Errorf("got %q, %v; want admin,users,api (BOM, CRLF, blanks, comments, duplicates handled)", got, err)
	}
}

func TestCheckWritable(t *testing.T) {
	dir := t.TempDir()
	fresh := filepath.Join(dir, "new.json")
	if err := checkWritable("", fresh); err != nil {
		t.Fatalf("writable path rejected: %v", err)
	}
	if _, err := os.Stat(fresh); !os.IsNotExist(err) {
		t.Error("the pre-flight check left an empty file behind")
	}
	existing := filepath.Join(dir, "old.json")
	os.WriteFile(existing, []byte("keep"), 0o644)
	if err := checkWritable(existing); err != nil {
		t.Fatalf("existing file rejected: %v", err)
	}
	if b, _ := os.ReadFile(existing); string(b) != "keep" {
		t.Error("the pre-flight check truncated an existing report")
	}
	if err := checkWritable(filepath.Join(dir, "no", "such", "dir", "o.json")); err == nil {
		t.Error("unwritable path accepted")
	}
}
