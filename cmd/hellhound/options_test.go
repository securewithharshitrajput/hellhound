package main

import (
	"flag"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/securewithharshitrajput/hellhound/internal/discover"
)

func testFlags() (*flag.FlagSet, *int, *int, *bool, headerFlag) {
	fs := flag.NewFlagSet("t", flag.ContinueOnError)
	c := fs.Int("c", 40, "")
	depth := fs.Int("depth", 2, "")
	crawl := fs.Bool("crawl", false, "")
	fs.Int("crawl-depth", 3, "")
	fs.Int("crawl-max", 500, "")
	fs.Int("calibrate", 6, "")
	fs.Int("rate", 0, "")
	fs.Duration("timeout", 10*time.Second, "")
	fs.String("config", "", "")
	fs.String("profile", "", "")
	h := headerFlag{}
	fs.Var(h, "H", "")
	return fs, c, depth, crawl, h
}

func TestPrecedenceProfileConfigCommandLine(t *testing.T) {
	dir := t.TempDir()
	conf := filepath.Join(dir, "hh.conf")
	os.WriteFile(conf, []byte("# c\nc = 7\n--depth=1\ncrawl\nH = X-A: from-config\nH = \"X-B: quoted\"\n"), 0o644)

	// profile deep says depth 4 + crawl; config says depth 1, c 7; CLI says c 3.
	fs, c, depth, crawl, h := testFlags()
	args, err := expandArgs(fs, []string{"-profile", "deep", "-config", conf, "-c", "3", "-H", "X-A: from-cli"})
	if err != nil {
		t.Fatal(err)
	}
	if err := fs.Parse(args); err != nil {
		t.Fatal(err)
	}
	if *c != 3 || *depth != 1 || !*crawl {
		t.Errorf("c=%d depth=%d crawl=%v; want 3 (CLI), 1 (config over profile), true", *c, *depth, *crawl)
	}
	if h["X-A"] != "from-cli" || h["X-B"] != "quoted" {
		t.Errorf("headers = %v; CLI must win for the same header, config headers kept otherwise", h)
	}
}

func TestExpandArgsErrors(t *testing.T) {
	dir := t.TempDir()
	write := func(body string) string {
		p := filepath.Join(dir, "c.conf")
		os.WriteFile(p, []byte(body), 0o644)
		return p
	}
	for name, args := range map[string][]string{
		"unknown profile":   {"-profile", "turbo"},
		"missing config":    {"-config", filepath.Join(dir, "nope.conf")},
		"unknown key":       {"-config", write("bogus = 1\n")},
		"nested config":     {"-config", write("config = other.conf\n")},
		"profile in config": {"-config", write("profile = deep\n")},
		"malformed line":    {"-config", write("two words = 1\n")},
	} {
		fs, _, _, _, _ := testFlags()
		if _, err := expandArgs(fs, args); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestScanFor(t *testing.T) {
	cases := []struct {
		args []string
		want string
	}{
		{[]string{"-profile", "deep"}, "deep"},
		{[]string{"--profile=gentle"}, "gentle"},
		{[]string{"-no-banner", "-u", "http://x", "-profile", "quick", "-c", "3"}, "quick"},
		{[]string{"-u", "http://x", "--", "-profile", "deep"}, ""},
		{[]string{"-profile"}, ""},
		{[]string{"-u", "http://x"}, ""},
	}
	for _, c := range cases {
		if got := scanFor(c.args, "profile"); got != c.want {
			t.Errorf("scanFor(%v) = %q, want %q", c.args, got, c.want)
		}
	}
}

func TestEveryProfileOnlyUsesRealFlagsWithValidValues(t *testing.T) {
	for name := range profiles {
		fs, _, _, _, _ := testFlags()
		args, err := expandArgs(fs, []string{"-profile", name})
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if err := fs.Parse(args); err != nil {
			t.Errorf("profile %s does not parse: %v", name, err)
		}
	}
}

func TestParseIntSet(t *testing.T) {
	got, err := parseIntSet("-mc", " 200, 301-303 ,403,", 100, 599)
	want := map[int]bool{200: true, 301: true, 302: true, 303: true, 403: true}
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, %v", got, err)
	}
	if got, err := parseIntSet("-mc", "", 100, 599); got != nil || err != nil {
		t.Errorf("empty: %v %v", got, err)
	}
	for _, bad := range []string{"99", "600", "abc", "300-200", "2x0", "200-", "-200"} {
		if _, err := parseIntSet("-mc", bad, 100, 599); err == nil || !strings.Contains(err.Error(), "-mc") {
			t.Errorf("parseIntSet(%q) = %v; want an error naming the flag", bad, err)
		}
	}
	if _, err := parseIntSet("-fs", "0-2000000000", 0, 1<<31-1); err == nil {
		t.Error("an enormous range must be rejected, not expanded")
	}
}

func TestFormatProgress(t *testing.T) {
	s := formatProgress("/admin", 250, 1000, 3, 2, 812.4, 5*time.Second, 110)
	for _, want := range []string{"[/admin]", "250/1000", "(25%)", "812 req/s", "ETA 15s", "3 hit(s)", "2 dir(s) done"} {
		if !strings.Contains(s, want) {
			t.Errorf("progress line %q lacks %q", s, want)
		}
	}
	if strings.ContainsAny(s, "\r\n\x1b") {
		t.Errorf("formatted line contains control characters: %q", s)
	}
	long := formatProgress("/"+strings.Repeat("deep/", 60), 1, 2, 0, 0, 1, time.Second, 80)
	if n := len([]rune(long)); n > 80 {
		t.Errorf("line is %d columns, limit 80", n)
	}
	if s := formatProgress("/", 0, 0, 0, 0, 0, 0, 110); !strings.Contains(s, "0/0") {
		t.Errorf("zero totals: %q", s)
	}
}

func TestProgressSilentWhenNotATerminal(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "out")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	p := newProgress(f, true, func() int64 { return 0 })
	p.Update("/", 1, 2, 0)
	p.Update("/", 2, 2, 1)
	p.Clear()
	p.Println("hellhound: a message %d", 1)
	data, _ := os.ReadFile(f.Name())
	if string(data) != "hellhound: a message 1\n" {
		t.Errorf("a file must receive plain lines only, got %q", data)
	}
}

func TestStateRoundTripAndValidation(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")
	if st, err := loadState(path, "http://t"); st != nil || err != nil {
		t.Fatalf("missing file should mean a fresh scan: %v %v", st, err)
	}
	in := &scanState{Target: "http://t", Words: []string{"a", "b"}, Extensions: []string{"", ".bak"}, MaxDepth: 2, CalibN: 6,
		Checkpoint: discover.Checkpoint{Pending: []string{"/x"}, Depths: map[string]int{"/": 0, "/x": 1}, DirsDone: 1,
			Results: []discover.Result{{URL: "http://t/x", Status: 200, BodyPreview: []byte("<b>"), Headers: map[string]string{"Server": "s"}}}}}
	if err := saveState(path, in); err != nil {
		t.Fatal(err)
	}
	out, err := loadState(path, "http://t")
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(out.Words, in.Words) || !reflect.DeepEqual(out.Checkpoint.Pending, in.Checkpoint.Pending) ||
		out.Checkpoint.Results[0].URL != "http://t/x" || string(out.Checkpoint.Results[0].BodyPreview) != "<b>" || out.Checkpoint.Depths["/x"] != 1 {
		t.Errorf("state did not survive a round trip: %+v", out)
	}
	if _, err := loadState(path, "http://other"); err == nil || !strings.Contains(err.Error(), "belongs to") {
		t.Errorf("state for another target accepted: %v", err)
	}
	os.WriteFile(path, []byte("{not json"), 0o644)
	if _, err := loadState(path, "http://t"); err == nil {
		t.Error("corrupt state accepted")
	}
	os.WriteFile(path, []byte(`{"tool":"other","version":1,"target":"http://t","words":["a"]}`), 0o644)
	if _, err := loadState(path, "http://t"); err == nil {
		t.Error("foreign state accepted")
	}
	// No temp files left next to the state.
	saveState(path, in)
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 {
		t.Errorf("%d files in the state directory, want only the state file", len(entries))
	}
}
