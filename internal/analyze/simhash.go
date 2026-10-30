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
//
// The timestamp branch also consumes a trailing RFC3339 timezone offset
// (+05:30, -08:00, or Z) — found via a real-world false positive: a server
// whose "not found" page embeds a full RFC3339 timestamp (...T13:20:02+05:30)
// left the "+05:30" suffix unmatched (the date/time portion alone doesn't
// reach it), so it survived as consistent, un-redacted template text — right
// up until a fuzzed WORD happened to literally be "05", whose own
// word-boundary-anchored redaction (see Normalize) then struck the "05"
// inside "+05:30" too, producing "+~:30" instead of "+05:30" — a change
// invisible by inspection but enough to desync that one candidate's hash
// from the baseline. Consuming the whole timezone suffix here removes the
// target entirely, rather than trying to anticipate every word that might
// collide with it.
const volatilePattern = `[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}|\b\d{4}-\d{2}-\d{2}(?:[t ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:z|[+-]\d{2}:\d{2})?)?\b|\b[0-9a-f]{6,}\b|\b\d{6,}\b`

var volatileRe = regexp.MustCompile(`(?i)` + volatilePattern)

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
// extra and the fixed volatile patterns are redacted in ONE combined pass
// (one compiled regex, one ReplaceAll), not two sequential passes. Two
// sequential passes was tried first and broke in both possible orderings:
//
//   - extra-first, then volatile: whenever a fuzzed word happened to look
//     like a generic volatile token (6+ hex chars, a 6+ digit number),
//     redacting it against the ALREADY-volatile-stripped text was fine —
//     but a plain short word like "05" would strike its own occurrence
//     inside an unrelated timestamp's timezone offset ("+05:30" ->
//     "+~:30") before the volatile pass ever got a chance to consume that
//     timestamp as one intact unit, desyncing that one candidate's hash
//     from the baseline. Measured directly against a real target.
//   - volatile-first, then extra: a fuzzed word that itself looks hex-like
//     ("004cc4") gets stripped by the generic hex pattern BEFORE the
//     explicit path redaction runs, consuming the bare word without its
//     leading "/" and leaving that slash stranded — a real, measured
//     ~0.1% false-positive rate on a 50,000-word wordlist.
//
// Combining both pattern sets into one regex and replacing in a single
// pass resolves both: Go's regexp finds whichever match starts EARLIEST
// in the string, so the full date+time(+timezone) pattern — which starts
// matching at the date's first digit, well before "05" appears later
// inside the timezone offset — always wins that case automatically by
// position; and the full "/004cc4" pattern (which starts one character
// earlier, at the leading slash, than either the bare word alone or the
// generic hex pattern can) wins the leftover-slash case the same way.
// Neither fix requires reasoning about pattern ORDER once there's only
// one pass — position alone decides it.
func Normalize(body []byte, extra ...string) []byte {
	patterns := make([]string, 0, len(extra)+1)
	for _, e := range extra {
		e = strings.TrimSpace(e)
		if e == "" {
			continue
		}
		patterns = append(patterns, boundedPattern(e))
	}
	patterns = append(patterns, volatilePattern)

	// regexp.Compile (not MustCompile): extra originates from operator
	// input — a wordlist line, a vhost candidate hostname — that can
	// contain invalid UTF-8 if the file wasn't clean text. QuoteMeta (used
	// by boundedPattern) escapes regex metacharacters but does not repair
	// invalid UTF-8, and Go's regexp engine rejects a pattern containing
	// it; MustCompile would turn that rejection into a panic that crashes
	// the entire scan over a single malformed wordlist byte. Falling back
	// to just the fixed volatile pattern (which is always valid) is a
	// strictly better failure mode than losing every result found so far.
	re, err := regexp.Compile(`(?i)` + strings.Join(patterns, "|"))
	if err != nil {
		re = volatileRe
	}
	return replaceExceptBeforeTagClose(re, body)
}

// replaceExceptBeforeTagClose is ReplaceAll with one exception: a match
// immediately followed by '>' is left untouched. Found against a real
// wordlist: a fuzzed word that happens to BE a valid HTML tag name ("html",
// "body") collides with the page's own structural tags — "<html>" and
// "</html>" both contain the bare word "html" immediately followed by '>'
// (true of any opening OR closing tag, since "<tag>" and "</tag>" both end
// exactly that way), and redacting it there corrupts the document's own
// outermost structure rather than an echoed path, producing a hash that
// diverges from the baseline only for that one candidate word. A genuine
// "cannot find /X" echo is never itself immediately followed by '>' (that
// context is specific to being inside a tag), so this exclusion costs
// nothing for real echo redaction while closing off an entire class of
// collision. Go's regexp has no negative-lookahead to express this
// directly, so matches are found first and selectively applied instead of
// using ReplaceAll's single pass.
func replaceExceptBeforeTagClose(re *regexp.Regexp, body []byte) []byte {
	matches := re.FindAllIndex(body, -1)
	if matches == nil {
		return body
	}
	out := make([]byte, 0, len(body))
	last := 0
	for _, m := range matches {
		start, end := m[0], m[1]
		if end < len(body) && body[end] == '>' {
			continue // leave this one exactly as it is in the source
		}
		out = append(out, body[last:start]...)
		out = append(out, '~')
		last = end
	}
	out = append(out, body[last:]...)
	return out
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

// SimilarShape reports whether two SimHash fingerprints are within the
// Calibrator's own near-identical threshold. Exported so other phases
// (e.g. mid-scan drift re-filtering in the discover package) can judge
// "same template" using the exact same cutoff the calibrator does, rather
// than hardcoding a threshold that could drift out of sync.
func SimilarShape(a, b uint64) bool {
	return Hamming(a, b) <= simThreshold
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
