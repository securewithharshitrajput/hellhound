package style

import (
	"bytes"
	"strings"
	"testing"
)

// With colour off, every helper must return its input unchanged: files,
// pipes and reports depend on byte-identical plain output.
func TestPlainPaletteIsIdentity(t *testing.T) {
	p := Palette{}
	for _, s := range []string{p.Bold("x"), p.Red("x"), p.Green("x"), p.Orange("x"), p.Grey("x")} {
		if s != "x" {
			t.Errorf("plain palette changed text: %q", s)
		}
	}
	if got := p.Status(200); got != "[200]" {
		t.Errorf("Status = %q", got)
	}
	if got := p.Severity("high"); got != "[HIGH  ]" {
		t.Errorf("Severity = %q", got)
	}
	if got := p.Section("security"); got != "[security]" {
		t.Errorf("Section = %q", got)
	}
}

func TestStatusColoursByClass(t *testing.T) {
	p := Palette{On: true}
	cases := map[int]string{200: "\x1b[1;32m", 301: "\x1b[36m", 403: "\x1b[1;33m", 404: "\x1b[35m", 500: "\x1b[1;31m"}
	for code, want := range cases {
		if got := p.Status(code); !strings.HasPrefix(got, want) || !strings.HasSuffix(got, "\x1b[0m") {
			t.Errorf("Status(%d) = %q, want prefix %q", code, got, want)
		}
	}
}

// Severity badges keep the same visible width with and without colour.
func TestSeverityWidthStable(t *testing.T) {
	on, off := Palette{On: true}, Palette{}
	for _, sev := range []string{"high", "medium", "low", "info"} {
		visible := strings.NewReplacer("\x1b[1;97;41m", "", "\x1b[1;38;5;208m", "", "\x1b[33m", "", "\x1b[90m", "", "\x1b[0m", "").Replace(on.Severity(sev))
		if visible != off.Severity(sev) {
			t.Errorf("%s: coloured %q vs plain %q", sev, visible, off.Severity(sev))
		}
	}
}

func TestLogWriterClassifiesLines(t *testing.T) {
	var buf bytes.Buffer
	w := LogWriter{W: &buf, P: Palette{On: true}}
	w.Write([]byte("hellhound: warning: slow target\nhellhound: crawling x...\nhellhound: crawl done in 2s\nhellhound: error: boom\nhellhound: mined 3 words\n"))
	out := buf.String()
	for _, want := range []string{"! \x1b[0m\x1b[33mwarning: slow target", "▶ ", "✓ ", "x \x1b[0m\x1b[31merror: boom", "  mined 3 words"} {
		if !strings.Contains(out, want) {
			t.Errorf("log output missing %q:\n%q", want, out)
		}
	}
	if strings.Count(out, "\n") != 5 {
		t.Errorf("line count changed: %q", out)
	}
}

func TestLogWriterPassesProgressAndPlain(t *testing.T) {
	var buf bytes.Buffer
	LogWriter{W: &buf, P: Palette{On: true}}.Write([]byte("\r\x1b[K[/] 3/10 (30%)"))
	if buf.String() != "\r\x1b[K[/] 3/10 (30%)" {
		t.Errorf("progress line was altered: %q", buf.String())
	}
	buf.Reset()
	in := "hellhound: warning: x\n"
	LogWriter{W: &buf, P: Palette{}}.Write([]byte(in))
	if buf.String() != in {
		t.Errorf("plain log writer altered text: %q", buf.String())
	}
}
