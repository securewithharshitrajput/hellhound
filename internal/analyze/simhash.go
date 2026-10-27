// SimHash gives a 64-bit fingerprint of a response body such that similar
// bodies produce fingerprints with small Hamming distance. This is what lets
// us say "this 'not found' page is the same shape every time, even though it
// embeds a random request-id and timestamp" without an exact-match hash.
package analyze

import (
	"hash/fnv"
	"math/bits"
	"regexp"
	"strings"
)

// volatileRe strips tokens that commonly vary per-request (timestamps, UUIDs,
// request ids, CSRF tokens, hex/decimal ids) so they don't fragment what is
// otherwise the same template into many different fingerprints.
var volatileRe = regexp.MustCompile(`(?i)[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}|\b\d{4}-\d{2}-\d{2}(?:[t ]\d{2}:\d{2}:\d{2})?\b|\b[0-9a-f]{6,}\b|\b\d{6,}\b`)

// Normalize removes volatile tokens prior to hashing/word-shingling. extra
// lets the caller redact known attacker-controlled input (the exact path
// segment that was requested) that a "not found" template may echo back
// verbatim — without this, a page that says "cannot find /<random-token>"
// would fingerprint as unique every single time, defeating calibration.
//
// Redaction is word-boundary-anchored (see boundedPattern) rather than a
// bare substring replace. A bare replace of a short word like "admin" would
// also match inside unrelated static text that happens to contain it as a
// substring — e.g. a WAF's static deny page saying "contact your
// administrator" — mangling it into "contact your ~istrator" only when the
// fuzzed word happens to be "admin", which desyncs that one response's
// hash from the baseline and makes a page that's byte-for-byte identical to
// every other soft-404 wrongly look unique.
//
// extra is redacted BEFORE volatileRe, not after. Found by testing at
// scale (50,000 random candidate words): whenever a fuzzed word itself
// happens to look like a generic volatile token — 6+ hex characters, a
// 6+ digit number, a UUID shape — volatileRe used to strike out the bare
// word FIRST, consuming it without its leading "/" and leaving that slash
// stranded in the output (".../looking for: /~" instead of ".../looking
// for: ~"). That stray character shifted the SimHash just enough to push
// an otherwise byte-for-byte-identical soft-404 page past the similarity
// threshold — a real, measured ~0.1% false-positive rate on a large
// wordlist, not a theoretical concern. Redacting the known echoed input
// first removes it (and its slash) as one unit; volatileRe then only ever
// sees whatever's left, which is exactly the unrelated server-generated
// noise it exists to catch.
func Normalize(body []byte, extra ...string) []byte {
	out := body
	for _, e := range extra {
		e = strings.TrimSpace(e)
		if e == "" {
			continue
		}
		// regexp.Compile (not MustCompile): e originates from operator
		// input — a wordlist line, a vhost candidate hostname — that can
		// contain invalid UTF-8 if the file wasn't clean text.
		// regexp.QuoteMeta escapes regex metacharacters but does not
		// repair invalid UTF-8, and Go's regexp engine rejects a pattern
		// containing it; MustCompile turns that rejection into a panic
		// that would crash the entire scan over a single malformed
		// wordlist byte. Skipping redaction for that one token (worst
		// case: slightly less precise calibration for that word) is a
		// strictly better failure mode than losing every result found so
		// far.
		re, err := regexp.Compile(`(?i)` + boundedPattern(e))
		if err != nil {
			continue
		}
		out = re.ReplaceAll(out, []byte("~"))
	}
	return volatileRe.ReplaceAll(out, []byte("~"))
}

// boundedPattern anchors a literal to word boundaries on whichever ends
// actually abut a word character, so "admin" won't match inside
// "administrator" but "/admin" (which starts with a non-word "/") still
// matches normally at that end — Go's RE2 engine supports only the simple
// \b boundary assertion (no lookaround), so this decides per-side whether
// \b is meaningful rather than applying it unconditionally.
func boundedPattern(tok string) string {
	pat := regexp.QuoteMeta(tok)
	if tok == "" {
		return pat
	}
	if isWordByte(tok[0]) {
		pat = `\b` + pat
	}
	if isWordByte(tok[len(tok)-1]) {
		pat = pat + `\b`
	}
	return pat
}

func isWordByte(c byte) bool {
	return c == '_' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
}

// SimHash computes a 64-bit fingerprint over whitespace-delimited shingles
// (word 3-grams) of the normalized body. Standard weighted-bit SimHash.
// extra: see Normalize.
func SimHash(body []byte, extra ...string) uint64 {
	norm := Normalize(body, extra...)
	shingles := shingle(norm, 3)
	if len(shingles) == 0 {
		// Fall back to whole-body hash for tiny/empty bodies.
		shingles = [][]byte{norm}
	}
	var v [64]int
	for _, sh := range shingles {
		h := fnvHash(sh)
		for i := 0; i < 64; i++ {
			if (h>>uint(i))&1 == 1 {
				v[i]++
			} else {
				v[i]--
			}
		}
	}
	var out uint64
	for i := 0; i < 64; i++ {
		if v[i] > 0 {
			out |= 1 << uint(i)
		}
	}
	return out
}

// Hamming returns the number of differing bits between two fingerprints.
// 0 = identical shape; <=3 is "near-identical" for our purposes (default
// threshold used by the Calibrator); >12 is unrelated content.
func Hamming(a, b uint64) int {
	return bits.OnesCount64(a ^ b)
}

func fnvHash(b []byte) uint64 {
	h := fnv.New64a()
	h.Write(b)
	return h.Sum64()
}

// shingle splits on ASCII whitespace and groups into overlapping n-grams of
// words. Operating on words rather than raw bytes makes the fingerprint
// robust to minor byte-level noise while still sensitive to real content
// changes.
func shingle(b []byte, n int) [][]byte {
	words := splitWords(b)
	if len(words) < n {
		if len(words) == 0 {
			return nil
		}
		return [][]byte{joinWords(words)}
	}
	out := make([][]byte, 0, len(words)-n+1)
	for i := 0; i+n <= len(words); i++ {
		out = append(out, joinWords(words[i:i+n]))
	}
	return out
}

func splitWords(b []byte) [][]byte {
	var words [][]byte
	start := -1
	isSpace := func(c byte) bool { return c == ' ' || c == '\t' || c == '\n' || c == '\r' }
	for i, c := range b {
		if isSpace(c) {
			if start >= 0 {
				words = append(words, b[start:i])
				start = -1
			}
		} else if start < 0 {
			start = i
		}
	}
	if start >= 0 {
		words = append(words, b[start:])
	}
	return words
}

func joinWords(ws [][]byte) []byte {
	n := len(ws) - 1
	for _, w := range ws {
		n += len(w)
	}
	out := make([]byte, 0, n)
	for i, w := range ws {
		if i > 0 {
			out = append(out, ' ')
		}
		out = append(out, w...)
	}
	return out
}
