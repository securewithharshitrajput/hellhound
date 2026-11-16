package report

import (
	"fmt"
	"strings"
	"unicode/utf8"

	"github.com/securewithharshitrajput/hellhound/internal/discover"
)

// Clean makes text that came from the target safe to print and to store.
// Response headers, page titles, redirect locations and API schema names
// are attacker-controlled: left as-is, an ESC or CSI sequence in them can
// clear the operator's terminal, recolour or hide lines, rewrite the window
// title, or (with bidirectional overrides) make a report line read
// differently from what it contains. Every control character is replaced by
// a visible escape such as \x1b, and invalid UTF-8 by \xNN.
func Clean(s string) string {
	clean := true
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		if unsafeRune(r, size) {
			clean = false
			break
		}
		i += size
	}
	if clean {
		return s
	}
	var b strings.Builder
	b.Grow(len(s) + 16)
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		switch {
		case r == utf8.RuneError && size == 1:
			fmt.Fprintf(&b, `\x%02x`, s[i])
		case unsafeRune(r, size):
			if r < 0x100 {
				fmt.Fprintf(&b, `\x%02x`, r)
			} else {
				fmt.Fprintf(&b, `\u%04x`, r)
			}
		default:
			b.WriteRune(r)
		}
		i += size
	}
	return b.String()
}

func unsafeRune(r rune, size int) bool {
	switch {
	case r == utf8.RuneError && size == 1: // invalid UTF-8 byte
		return true
	case r < 0x20, r >= 0x7f && r <= 0x9f: // C0, DEL, C1 (0x9b is an 8-bit CSI)
		return true
	case r >= 0x202a && r <= 0x202e, r >= 0x2066 && r <= 0x2069, r == 0x200e, r == 0x200f: // bidi controls
		return true
	case r == 0x2028 || r == 0x2029: // line / paragraph separators
		return true
	}
	return false
}

// CleanFindings returns findings with every text field passed through Clean.
func CleanFindings(in []discover.SecurityFinding) []discover.SecurityFinding {
	out := make([]discover.SecurityFinding, len(in))
	for i, f := range in {
		f.URL = Clean(f.URL)
		f.Description = Clean(f.Description)
		f.Evidence = Clean(f.Evidence)
		out[i] = f
	}
	return out
}

// csvCell neutralises spreadsheet formula injection: a cell beginning with
// = + - @ (or a tab / carriage return) is executed as a formula by Excel
// and LibreOffice when the CSV is opened, and paths and evidence come from
// the target. A leading apostrophe makes the cell plain text.
func csvCell(s string) string {
	s = Clean(s)
	if s != "" && strings.ContainsRune("=+-@\t\r", rune(s[0])) {
		return "'" + s
	}
	return s
}
