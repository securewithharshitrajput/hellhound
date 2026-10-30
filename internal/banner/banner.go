// Package banner prints hellhound's startup banner: an ASCII logo plus a
// randomly rotating tip, the way Metasploit shows a random "tip of the
// day" and ProjectDiscovery tools (katana, nuclei, httpx) show a boxed
// ASCII banner on every run.
//
// Color and the logo are skipped automatically when stderr isn't a real
// terminal (redirected to a file, piped through something that doesn't
// pass a TTY through), so automation and log files never see raw ANSI
// escape codes or ASCII art mixed into otherwise-parseable output. The
// banner goes to stderr, not stdout — stdout stays reserved for findings
// output, so `hellhound ... > results.txt` still shows the banner on-screen
// while the findings land cleanly in the file.
package banner

import (
	"fmt"
	"math/rand"
	"os"
	"strings"
)

// Version is the tool's displayed version. Bump this on meaningful
// feature changes.
const Version = "0.6.0"

// Tagline appears under the logo and in the no-TTY fallback line.
const Tagline = "calibrated recon that classifies what it finds"

// Name is the word rendered as block-letter ASCII art. Change this (and
// add any new letters to glyphs below) to re-skin the banner for a
// different tool name — see renderLogo.
const Name = "HELLHOUND"

// tips rotate randomly on each run, Metasploit-tip-of-the-day style —
// surfacing one real capability the operator might not know about yet
// instead of the same static banner every single time.
var tips = []string{
	"tip: -vhosts <file> hunts internal vhosts DNS never told you about",
	"tip: raise -maxbody if a big OpenAPI/GraphQL spec looks truncated",
	"tip: -no-mine skips robots.txt/JS mining if you just want raw speed",
	"tip: calibration redacts the fuzzed word from bodies first — WAF deny pages won't false-positive",
	"tip: -H \"Name: value\" is repeatable — stack auth headers, custom UA, anything",
	"tip: findings are reported by cluster, not raw hit count — read the cluster count first",
	"tip: -k skips TLS verification for self-signed dev/staging certs — never use it on prod scope",
	"tip: recursion only follows hits that actually look like directories, not JSON leaf endpoints",
	"tip: -x http://127.0.0.1:8080 routes everything through Burp/ZAP (add -k for HTTPS)",
	"tip: -rate N caps requests/sec to stay under a target's WAF/bot thresholds",
	"tip: -crawl follows real links to find pages no wordlist could ever guess",
	"tip: Tier-A security checks are on by default — read the [security] block first, it's the dangerous stuff",
	"tip: tech detection auto-adds WP/Rails/Spring/Laravel/Django-specific wordlists on hits — no setup",
	"tip: -no-security skips sensitive-file / dir-listing / OPTIONS / open-redirect probing (pure discovery mode)",
}

// glyphs maps each supported letter to a 5-row block-letter cell. Rows
// within one letter are always written as literal same-length strings, so
// a letter's own internal alignment is correct by construction. Add a
// letter here (keeping all 5 of its rows the same rune-width) to support
// renaming the banner.
//
// This replaced a hand-typed figlet-style ASCII-art string constant: that
// version had rows of inconsistent total width (44 runes vs 41 on
// different lines) because getting a multi-letter box-drawing banner
// aligned by hand, from memory, is exactly the kind of thing that's easy
// to get subtly wrong and hard to eyeball-check afterward. Generating it
// from per-letter cells makes the invariant ("every letter contributes
// the same width on every row") checkable in code (see renderLogo) instead
// of relying on careful typing.
var glyphs = map[byte][5]string{
	'S': {"███████", "██     ", "███████", "     ██", "███████"},
	'C': {"███████", "██     ", "██     ", "██     ", "███████"},
	'O': {"███████", "██   ██", "██   ██", "██   ██", "███████"},
	'U': {"██   ██", "██   ██", "██   ██", "██   ██", "███████"},
	'T': {"███████", "   ██  ", "   ██  ", "   ██  ", "   ██  "},
	'H': {"██   ██", "██   ██", "███████", "██   ██", "██   ██"},
	'E': {"███████", "██     ", "█████  ", "██     ", "███████"},
	'L': {"██     ", "██     ", "██     ", "██     ", "███████"},
	'N': {"██   ██", "███  ██", "██ █ ██", "██  ███", "██   ██"},
	'D': {"██████ ", "██   ██", "██   ██", "██   ██", "██████ "},
}

// renderLogo builds the block-letter banner for word, two spaces between
// letters. It panics on an unsupported letter rather than silently
// rendering a gap, so a typo'd Name fails loudly at startup instead of
// producing a banner with a hole in it.
func renderLogo(word string) string {
	var rows [5]strings.Builder
	for i, ch := range []byte(word) {
		g, ok := glyphs[ch]
		if !ok {
			panic(fmt.Sprintf("banner: no glyph for letter %q in Name %q", ch, word))
		}
		for row := 0; row < 5; row++ {
			if i > 0 {
				rows[row].WriteString("  ")
			}
			rows[row].WriteString(g[row])
		}
	}
	var out strings.Builder
	out.WriteByte('\n')
	for _, r := range rows {
		out.WriteString(r.String())
		out.WriteByte('\n')
	}
	return out.String()
}

var logo = renderLogo(Name)

func isTerminal(f *os.File) bool {
	info, err := f.Stat()
	if err != nil {
		return false
	}
	return (info.Mode() & os.ModeCharDevice) != 0
}

// Print writes the banner to stderr. suppress forces the plain single-line
// form (or nothing) regardless of TTY detection — wired to a -no-banner /
// -silent style flag.
func Print(suppress bool) {
	if suppress {
		return
	}
	w := os.Stderr
	tip := tips[rand.Intn(len(tips))]

	if !isTerminal(w) {
		fmt.Fprintf(w, "hellhound v%s — %s\n%s\n\n", Version, Tagline, tip)
		return
	}

	const (
		bold   = "\x1b[1m"
		red    = "\x1b[31m"
		orange = "\x1b[38;5;208m"
		dim    = "\x1b[2m"
		reset  = "\x1b[0m"
	)

	fmt.Fprint(w, red+bold+logo+reset)
	fmt.Fprintf(w, "        %sv%s%s  %s%s%s\n", orange+bold, Version, reset, dim, Tagline, reset)
	fmt.Fprintf(w, "        %s%s%s\n\n", dim, tip, reset)
}
