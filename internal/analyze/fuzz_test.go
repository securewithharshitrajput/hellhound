package analyze

import (
	"testing"

	"github.com/securewithharshitrajput/hellhound/internal/engine"
)

func fakeResp(status int, body []byte) engine.Response {
	return engine.Response{Status: status, Body: body, Length: len(body)}
}

// FuzzSimHash feeds arbitrary byte sequences (including invalid UTF-8,
// binary garbage, huge repeated runs) into SimHash + Normalize to catch
// panics that curated test cases wouldn't think to try — a real target can
// return anything, including deliberately malformed bytes from a probe
// that's hostile to the scanner itself.
func FuzzSimHash(f *testing.F) {
	seeds := [][]byte{
		{},
		[]byte("hello world"),
		[]byte("\x00\x01\x02\xff\xfe"),
		[]byte(string([]byte{0xc0, 0xaf})), // invalid UTF-8 continuation
		[]byte("<html>日本語 テスト</html>"),
		[]byte("admin administrator administration"),
		[]byte("a"),
		{0xff},
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, body []byte) {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("SimHash panicked on input %q: %v", body, r)
			}
		}()
		h := SimHash(body)
		_ = h
		// Determinism: same input must always produce the same hash.
		h2 := SimHash(body)
		if h != h2 {
			t.Errorf("SimHash is non-deterministic for input %q: %d != %d", body, h, h2)
		}
	})
}

// FuzzNormalizeWithRedaction specifically fuzzes the redaction path (extra
// tokens to strip) since that's where the boundedPattern regex construction
// happens per-call from caller-supplied strings — a candidate wordlist
// word, fully attacker/operator controlled, becomes a regex pattern
// fragment. A hostile or just weird word (regex metacharacters, extremely
// long strings, empty string, unicode) must never panic or hang.
func FuzzNormalizeWithRedaction(f *testing.F) {
	type seed struct {
		body  string
		extra string
	}
	seeds := []seed{
		{"hello world", "admin"},
		{"test", ""},
		{"test", "."},
		{"test", "(.*)"},
		{"test", "[a-z"},       // unterminated char class
		{"test", "\\"},         // trailing backslash
		{"test", "a{1000000}"}, // regex quantifier bomb attempt
		{"", ""},
	}
	for _, s := range seeds {
		f.Add(s.body, s.extra)
	}
	f.Fuzz(func(t *testing.T, body, extra string) {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("Normalize panicked on body=%q extra=%q: %v", body, extra, r)
			}
		}()
		_ = Normalize([]byte(body), extra)
	})
}

// FuzzClassify exercises Calibrate->Learn->Classify end to end with
// arbitrary status codes and bodies, checking only that it never panics.
func FuzzClassify(f *testing.F) {
	f.Add(200, []byte("hello"), 200, []byte("world"))
	f.Add(404, []byte(""), 500, []byte("\x00\xff"))
	f.Add(0, []byte("x"), -1, []byte("y"))

	f.Fuzz(func(t *testing.T, calibStatus int, calibBody []byte, realStatus int, realBody []byte) {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("calibrate/classify panicked: calibStatus=%d calibBody=%q realStatus=%d realBody=%q: %v",
					calibStatus, calibBody, realStatus, realBody, r)
			}
		}()
		c := NewCalibrator()
		probes := []Probe{
			{Token: "aaa", Resp: fakeResp(calibStatus, calibBody)},
			{Token: "bbb", Resp: fakeResp(calibStatus, calibBody)},
		}
		c.Learn("/", probes)
		_ = c.Classify("/", "/candidate", fakeResp(realStatus, realBody))
	})
}
