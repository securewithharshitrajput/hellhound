// Package style colours hellhound's terminal output: status codes by class,
// severities by urgency, section headers, and log lines by what they mean
// (a phase starting, a phase done, a warning, an error).
//
// Colour is only ever written to a real terminal. Into a file, a pipe, or
// any machine-readable report (JSON, CSV, SARIF) the output stays plain, so
// `hellhound ... > out.txt` and `| grep` see exactly the same text as before.
// The NO_COLOR convention (https://no-color.org) and -no-color turn it off;
// FORCE_COLOR turns it on for a pipe that ends in a terminal (e.g. `| less -R`).
package style

import (
	"fmt"
	"io"
	"os"
	"strings"
)

// Palette applies colours when On, and returns text unchanged otherwise.
type Palette struct{ On bool }

// Out styles what goes to stdout (findings); Err styles stderr (the log).
// Both start off; main enables each for its own stream.
var Out, Err Palette

// Detect reports whether colour should be used on f.
func Detect(f *os.File, noColor bool) bool {
	if noColor || os.Getenv("NO_COLOR") != "" || os.Getenv("TERM") == "dumb" {
		return false
	}
	if v := os.Getenv("FORCE_COLOR"); v != "" && v != "0" && v != "false" {
		return true
	}
	info, err := f.Stat()
	return err == nil && info.Mode()&os.ModeCharDevice != 0
}

func (p Palette) wrap(code, s string) string {
	if !p.On || s == "" {
		return s
	}
	return "\x1b[" + code + "m" + s + "\x1b[0m"
}

func (p Palette) Bold(s string) string    { return p.wrap("1", s) }
func (p Palette) Dim(s string) string     { return p.wrap("2", s) }
func (p Palette) Red(s string) string     { return p.wrap("31", s) }
func (p Palette) Green(s string) string   { return p.wrap("32", s) }
func (p Palette) Yellow(s string) string  { return p.wrap("33", s) }
func (p Palette) Blue(s string) string    { return p.wrap("34", s) }
func (p Palette) Magenta(s string) string { return p.wrap("35", s) }
func (p Palette) Cyan(s string) string    { return p.wrap("36", s) }
func (p Palette) Grey(s string) string    { return p.wrap("90", s) }
func (p Palette) Orange(s string) string  { return p.wrap("38;5;208", s) }

// Status renders "[200]" coloured by class: 2xx green, 3xx cyan, 401/403
// yellow (exists but protected), other 4xx magenta, 5xx red.
func (p Palette) Status(code int) string {
	s := fmt.Sprintf("[%d]", code)
	switch {
	case code >= 200 && code < 300:
		return p.wrap("1;32", s)
	case code >= 300 && code < 400:
		return p.wrap("36", s)
	case code == 401 || code == 403:
		return p.wrap("1;33", s)
	case code >= 400 && code < 500:
		return p.wrap("35", s)
	case code >= 500:
		return p.wrap("1;31", s)
	}
	return s
}

// Severity renders a fixed-width severity badge: HIGH as white on red,
// MEDIUM orange, LOW yellow, INFO grey. Width is kept identical with and
// without colour, so columns line up either way.
func (p Palette) Severity(sev string) string {
	label := strings.ToUpper(sev)
	padded := fmt.Sprintf("%-6s", label)
	if !p.On {
		return "[" + padded + "]"
	}
	switch strings.ToLower(sev) {
	case "critical", "high":
		return p.wrap("1;97;41", "["+padded+"]")
	case "medium":
		return p.wrap("1;38;5;208", "["+padded+"]")
	case "low":
		return p.wrap("33", "["+padded+"]")
	case "info":
		return p.wrap("90", "["+padded+"]")
	}
	return "[" + padded + "]"
}

// Section renders a "[name]" block header in the colour of its kind.
func (p Palette) Section(name string) string {
	tag := "[" + name + "]"
	switch name {
	case "security":
		return p.wrap("1;31", tag)
	case "crawl":
		return p.wrap("1;36", tag)
	case "forms":
		return p.wrap("1;35", tag)
	case "openapi", "graphql":
		return p.wrap("1;32", tag)
	case "vhost":
		return p.wrap("1;34", tag)
	}
	return p.wrap("1", tag)
}

// LogWriter colours hellhound's stderr log line by line, by meaning, so the
// many existing log calls need no change:
//
//	"hellhound: warning: ..."           yellow, with a "!" marker
//	errors, "INCOMPLETE", "not reachable" red, with an "x" marker
//	a phase starting ("...")             bold blue, with a "▶" marker
//	a phase finishing (" done in ")      green, with a "✓" marker
//	anything else                        the "hellhound:" prefix dimmed
//
// The live progress line ("\r..." chunks) passes through untouched.
type LogWriter struct {
	W io.Writer
	P Palette
}

func (l LogWriter) Write(b []byte) (int, error) {
	if !l.P.On {
		return l.W.Write(b)
	}
	s := string(b)
	lines := strings.SplitAfter(s, "\n")
	var out strings.Builder
	for _, ln := range lines {
		if ln == "" {
			continue
		}
		body := strings.TrimSuffix(ln, "\n")
		nl := ln[len(body):]
		out.WriteString(l.line(body))
		out.WriteString(nl)
	}
	if _, err := io.WriteString(l.W, out.String()); err != nil {
		return 0, err
	}
	return len(b), nil
}

const prefix = "hellhound: "

func (l LogWriter) line(s string) string {
	p := l.P
	if s == "" || strings.HasPrefix(s, "\r") || strings.Contains(s, "\x1b[") {
		return s // progress line or already coloured
	}
	if !strings.HasPrefix(s, prefix) {
		return s
	}
	msg := s[len(prefix):]
	tag := p.Orange("hellhound") + p.Grey(":") + " "
	lower := strings.ToLower(msg)
	switch {
	case strings.HasPrefix(lower, "error") || strings.Contains(lower, "not reachable") ||
		strings.Contains(msg, "INCOMPLETE") || strings.HasPrefix(lower, "cannot ") || strings.HasPrefix(lower, "invalid "):
		return tag + p.wrap("1;31", "x ") + p.Red(msg)
	case strings.HasPrefix(lower, "warning:"):
		return tag + p.wrap("1;33", "! ") + p.Yellow(msg)
	case strings.HasPrefix(lower, "interrupted") || strings.HasPrefix(lower, "reached -max-time"):
		return tag + p.wrap("1;33", "■ ") + p.Yellow(msg)
	case strings.HasSuffix(msg, "...") || strings.HasSuffix(msg, "…") || strings.HasPrefix(lower, "calibrating + scanning"):
		return tag + p.wrap("1;34", "▶ ") + p.Bold(msg)
	case strings.Contains(msg, " done in ") || strings.HasPrefix(lower, "done in ") || strings.HasPrefix(lower, "wrote "):
		return tag + p.Green("✓ ") + p.Green(msg)
	}
	return tag + "  " + msg
}
