package wordlist

import (
	"strings"
	"testing"
	"time"
)

// TestRegexesAreReDoSResistant feeds classic catastrophic-backtracking
// trigger shapes to every regex that runs on content a TARGET controls
// (robots.txt, JS bundles, the homepage) — FromJS, FromRobots, and
// (indirectly) the script-src extraction in the discover package. Go's
// regexp package is RE2-based, which guarantees linear-time matching by
// construction (no backtracking engine to exploit), so this should always
// pass — but that guarantee had never been exercised against adversarial
// input here, and a future regex added without that guarantee in mind
// (or a change to a non-stdlib regex library) could silently break it.
// A hostile or just broken target must never be able to hang the scanner
// by shaping its robots.txt or JS response.
func TestRegexesAreReDoSResistant(t *testing.T) {
	// Classic ReDoS bait: long runs of a repeated character immediately
	// followed by a character that almost-but-doesn't complete the
	// pattern, which is exactly what makes backtracking engines blow up.
	evilRun := strings.Repeat("a", 50000)

	cases := []struct {
		name string
		body []byte
		fn   func([]byte) []string
	}{
		{"FromJS quote-heavy", []byte(`"` + evilRun + `!`), FromJS},
		{"FromJS many near-miss routes", []byte(strings.Repeat(`"/`+evilRun+`X`, 200)), FromJS},
		{"FromRobots long disallow line", []byte("Disallow: /" + evilRun), FromRobots},
		{"FromRobots many lines", []byte(strings.Repeat("Disallow: /"+evilRun+"\n", 200)), FromRobots},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			done := make(chan struct{})
			go func() {
				c.fn(c.body)
				close(done)
			}()
			select {
			case <-done:
				// fine — completed
			case <-time.After(30 * time.Second):
				// 30s, not 5s: the race detector adds a well-documented
				// ~10-20x slowdown to allocation-heavy code (confirmed
				// directly — this exact test went from 0.4s to over 5s
				// under `-race` alone, a constant-factor instrumentation
				// cost, not quadratic/exponential regex blowup). Real
				// ReDoS would show up as minutes-to-hours, not single-
				// digit seconds, so 30s stays well clear of false
				// positives from race-detector overhead while still
				// catching genuine catastrophic backtracking.
				t.Fatalf("%s did not complete within 30s — possible ReDoS", c.name)
			}
		})
	}
}
