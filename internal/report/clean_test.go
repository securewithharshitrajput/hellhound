package report

import (
	"bytes"
	"encoding/csv"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/securewithharshitrajput/hellhound/internal/analyze"
	"github.com/securewithharshitrajput/hellhound/internal/discover"
)

func hasControl(s string) bool {
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		if unsafeRune(r, size) {
			return true
		}
		i += size
	}
	return false
}

func TestCleanNeutralisesTerminalControl(t *testing.T) {
	cases := []string{
		"\x1b[2J\x1b[31mPWNED\x1b[0m", // CSI: clear screen, colour
		"\x1b]0;evil title\x07",       // OSC: window title
		"a\u009b31mb",                 // 8-bit CSI
		"line1\nline2\r\x00\x7f",      // newline, CR, NUL, DEL
		"safe‮exe.txt",                // right-to-left override
		"bad\xff\xfeutf8",             // invalid UTF-8
		" split",                      // line separator
	}
	for _, in := range cases {
		out := Clean(in)
		if hasControl(out) {
			t.Errorf("Clean(%q) still has control characters: %q", in, out)
		}
		if !utf8.ValidString(out) {
			t.Errorf("Clean(%q) is not valid UTF-8", in)
		}
	}
	if got := Clean("\x1b[31m"); got != `\x1b[31m` {
		t.Errorf("want a visible escape, got %q", got)
	}
	for _, same := range []string{"", "plain", "/path?a=b&c=d", "ünïcödé 日本語 — ok", "tab-free"} {
		if got := Clean(same); got != same {
			t.Errorf("Clean(%q) changed ordinary text to %q", same, got)
		}
	}
}

func TestCsvCellBlocksFormulaInjection(t *testing.T) {
	for _, in := range []string{"=cmd|' /C calc'!A0", "+1+1", "-----BEGIN RSA PRIVATE KEY-----", "@SUM(A1)"} {
		if got := csvCell(in); !strings.HasPrefix(got, "'") {
			t.Errorf("csvCell(%q) = %q, want a leading apostrophe", in, got)
		}
	}
	// A leading tab or carriage return (which spreadsheets skip before
	// reading "=") is escaped to visible text, which also defuses it.
	for _, in := range []string{"\t=1", "\r=1", "\n=1"} {
		if got := csvCell(in); strings.ContainsRune("=+-@\t\r\n", rune(got[0])) {
			t.Errorf("csvCell(%q) = %q still starts with a formula trigger", in, got)
		}
	}
	for _, in := range []string{"http://t/x", "status 200", "", "[core]"} {
		if got := csvCell(in); got != in {
			t.Errorf("csvCell(%q) = %q, want unchanged", in, got)
		}
	}
}

// Every writer must be free of raw control characters and formula cells
// when the target supplies hostile text.
func TestAllOutputsAreSafeAgainstHostileText(t *testing.T) {
	evil := "\x1b[2J\x1b[31mPWNED\u009b0m‮"
	results := []discover.Result{{
		URL: "http://t/admin", Status: 301,
		Verdict: analyze.Verdict{Interesting: true, Reason: "redirect (301) -> /admin" + evil},
	}}
	rep := Build("http://t", results)
	rep.SecurityFindings = []discover.SecurityFinding{
		{Type: "dir-listing", Severity: "medium", URL: "http://t/up/", Description: "listing", Evidence: "<title>Index of /up" + evil + "</title>"},
		{Type: "sensitive-file", Severity: "high", URL: "http://t/id_rsa", Description: "key", Evidence: "-----BEGIN RSA PRIVATE KEY-----"},
		{Type: "info-disclosure", Severity: "low", URL: "http://t", Description: "=HYPERLINK(\"http://x\")", Evidence: "Server: x" + evil},
	}

	var sum, js, cs, sa bytes.Buffer
	WriteSummary(&sum, rep)
	if err := WriteJSON(&js, rep); err != nil {
		t.Fatal(err)
	}
	if err := WriteCSV(&cs, rep); err != nil {
		t.Fatal(err)
	}
	if err := WriteSARIF(&sa, rep); err != nil {
		t.Fatal(err)
	}
	for name, out := range map[string]string{"summary": sum.String(), "json": js.String(), "csv": cs.String(), "sarif": sa.String()} {
		for _, line := range strings.Split(out, "\n") {
			if hasControl(line) {
				t.Errorf("%s output contains a raw control character: %q", name, line)
			}
		}
	}
	rows, err := csv.NewReader(&cs).ReadAll()
	if err != nil {
		t.Fatalf("csv does not parse: %v", err)
	}
	for _, row := range rows {
		for _, cell := range row {
			if cell != "" && strings.ContainsRune("=+-@", rune(cell[0])) {
				t.Errorf("csv cell would be read as a formula: %q", cell)
			}
		}
	}
}

// Identical inputs in a different arrival order must give the same report,
// and the shortest URL represents a cluster.
func TestBuildIsDeterministicAndPrefersShortestURL(t *testing.T) {
	same := analyze.Verdict{Interesting: true, Reason: "r", ClusterKey: 42}
	a := []discover.Result{
		{URL: "http://t/admin?x=1", Status: 200, Length: 10, Verdict: same},
		{URL: "http://t/zeta", Status: 200, Length: 99, Verdict: analyze.Verdict{Interesting: true, ClusterKey: 1 << 40}},
		{URL: "http://t/admin", Status: 200, Length: 10, Verdict: same},
		{URL: "http://t/alpha", Status: 200, Length: 55, Verdict: analyze.Verdict{Interesting: true, ClusterKey: 0xffff0000ffff}},
	}
	b := []discover.Result{a[3], a[2], a[1], a[0]}
	var out1, out2 bytes.Buffer
	WriteSummary(&out1, Build("http://t", a))
	WriteSummary(&out2, Build("http://t", b))
	if out1.String() != out2.String() {
		t.Errorf("report depends on arrival order:\n%s\nvs\n%s", out1.String(), out2.String())
	}
	if strings.Contains(out1.String(), "admin?x=1 ") && !strings.Contains(out1.String(), "http://t/admin ") {
		t.Errorf("cluster is represented by the longer URL:\n%s", out1.String())
	}
}
