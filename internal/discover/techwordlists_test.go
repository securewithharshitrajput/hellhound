package discover

import (
	"testing"
)

// TestMatchFingerprintsIdentifiesWordPress proves tech detection catches
// WordPress from a body signal AND independently from a response header
// signal — real sites commonly expose only one.
func TestMatchFingerprintsIdentifiesWordPress(t *testing.T) {
	// Body-only signal
	body := []byte(`<html><link href="/wp-content/themes/x/style.css"></html>`)
	got := matchFingerprints(body, map[string][]string{})
	if !containsTech(got, TechWordPress) {
		t.Errorf("expected WordPress to be detected from body, got %v", got)
	}

	// Header-only signal
	got = matchFingerprints([]byte("<html></html>"), map[string][]string{"X-Powered-By": {"WordPress 6.3"}})
	if !containsTech(got, TechWordPress) {
		t.Errorf("expected WordPress to be detected from X-Powered-By header, got %v", got)
	}
}

func TestMatchFingerprintsMultipleStacks(t *testing.T) {
	// A real-world possibility: a Spring Boot API with Swagger that also
	// exposes an ASP.NET-hosted CMS edge.
	body := []byte(`<html>Whitelabel Error Page __VIEWSTATE</html>`)
	got := matchFingerprints(body, map[string][]string{})
	if !containsTech(got, TechSpring) {
		t.Errorf("expected Spring, got %v", got)
	}
	if !containsTech(got, TechAspNet) {
		t.Errorf("expected AspNet, got %v", got)
	}
}

// TestWordsForTechsDedupesAcrossStacks verifies the same path doesn't
// appear twice when two detected stacks both list it (e.g. two PHP stacks
// both listing wp-config.php).
func TestWordsForTechsDedupesAcrossStacks(t *testing.T) {
	// WordPress and PHP both list "config.php.bak"-adjacent paths; verify
	// the union has no duplicates.
	words := WordsForTechs([]Tech{TechWordPress, TechPHP})
	seen := map[string]int{}
	for _, w := range words {
		seen[w]++
	}
	for w, n := range seen {
		if n > 1 {
			t.Errorf("duplicate word %q appeared %d times in merged tech wordlists", w, n)
		}
	}
}

func TestWordsForTechsReturnsRailsSpecifics(t *testing.T) {
	words := WordsForTechs([]Tech{TechRails})
	found := false
	for _, w := range words {
		if w == "rails/info/routes" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected rails/info/routes in Rails-specific wordlist, got %v", words)
	}
}

func containsTech(list []Tech, want Tech) bool {
	for _, t := range list {
		if t == want {
			return true
		}
	}
	return false
}
