package banner

import (
	"strings"
	"testing"
	"unicode/utf8"
)

// TestGlyphsAreInternallyConsistent catches exactly the bug that shipped
// in an earlier hand-typed version of this banner: every row of a given
// letter's glyph must be the same rune-width, or the rendered banner comes
// out visibly crooked.
func TestGlyphsAreInternallyConsistent(t *testing.T) {
	for letter, rows := range glyphs {
		width := utf8.RuneCountInString(rows[0])
		for i, row := range rows {
			if w := utf8.RuneCountInString(row); w != width {
				t.Errorf("letter %q row %d has width %d, want %d (same as row 0) — banner will render crooked", letter, i, w, width)
			}
		}
	}
}

// TestRenderLogoProducesAlignedRows checks the actual rendered output for
// the real banner Name: every non-empty line must be the same total
// width, which only holds if every letter cell has consistent width (the
// above test) AND renderLogo concatenates them correctly.
func TestRenderLogoProducesAlignedRows(t *testing.T) {
	out := renderLogo(Name)
	lines := strings.Split(out, "\n")
	width := -1
	for i, l := range lines {
		if l == "" {
			continue
		}
		w := utf8.RuneCountInString(l)
		if width == -1 {
			width = w
		} else if w != width {
			t.Errorf("rendered logo line %d has width %d, want %d (line %q)", i, w, width, l)
		}
	}
	if width <= 0 {
		t.Error("rendered logo appears empty")
	}
}

// TestRenderLogoPanicsOnUnknownLetter guards the explicit fail-loud
// behavior: a Name containing a letter with no glyph must panic at
// startup, not silently render a gap.
func TestRenderLogoPanicsOnUnknownLetter(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Error("expected renderLogo to panic on an unsupported letter")
		}
	}()
	renderLogo("HELLHOUNDX") // 'X' has no glyph defined
}
