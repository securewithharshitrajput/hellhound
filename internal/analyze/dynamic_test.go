package analyze

import (
	"fmt"
	"math/rand"
	"strings"
	"testing"

	"github.com/securewithharshitrajput/hellhound/internal/engine"
)

func probe(tok string, status int, body string) Probe {
	return Probe{Token: tok, Resp: engine.Response{Status: status, Body: []byte(body), Length: len(body)}}
}

func TestStableProbesBuildNoDynamicModel(t *testing.T) {
	c := NewCalibrator()
	var ps []Probe
	for i := 0; i < 6; i++ {
		tok := fmt.Sprintf("tok%dzz", i)
		ps = append(ps, probe(tok, 404, "<html><body><h1>Not Found</h1><p>The requested URL /"+tok+" was not found on this server.</p></body></html>"))
	}
	if b := c.Learn("/", ps); b.Unstable() {
		t.Error("identical not-found pages were classed as unstable")
	}
}

func TestDynamicModelSeparatesNoiseFromRealPages(t *testing.T) {
	vocab := strings.Fields("alpha beta gamma delta epsilon zeta eta theta iota kappa lambda mu nu xi omicron pi rho sigma tau upsilon")
	noisy := func() string {
		var b strings.Builder
		for i, n := 0, 20+rand.Intn(300); i < n; i++ {
			b.WriteString(vocab[rand.Intn(len(vocab))] + " ")
		}
		return "<html><body><h1>Recommended for you</h1><p>" + b.String() + "</p></body></html>"
	}
	c := NewCalibrator()
	var ps []Probe
	for i := 0; i < 12; i++ {
		ps = append(ps, probe(fmt.Sprintf("tok%dzz", i), 200, noisy()))
	}
	b := c.Learn("/", ps)
	if !b.Unstable() {
		t.Fatal("random-content pages were not recognised as unstable")
	}
	for i := 0; i < 200; i++ {
		v := c.Classify("/", fmt.Sprintf("/word%d", i), engine.Response{Status: 200, Body: []byte(noisy())})
		if v.Interesting {
			t.Fatalf("another random not-found page was reported as a finding: %s", v.Reason)
		}
	}
	real := "<html><body><h1>Admin console</h1><p>restricted staff area with many controls and settings</p></body></html>"
	if v := c.Classify("/", "/admin", engine.Response{Status: 200, Body: []byte(real)}); !v.Interesting {
		t.Errorf("a real page was suppressed: %s", v.Reason)
	}
	// A different status is never covered by the 200 model.
	if v := c.Classify("/", "/secret", engine.Response{Status: 403, Body: []byte(noisy())}); !v.Interesting {
		t.Errorf("a 403 was suppressed by the 200 vocabulary model: %s", v.Reason)
	}
}

func TestTwoDisagreeingProbesAskForMore(t *testing.T) {
	c := NewCalibrator()
	b := c.Learn("/", []Probe{
		probe("aaa111", 200, "<html><body><p>one two three four five six seven eight nine ten</p></body></html>"),
		probe("bbb222", 200, "<html><body><table><tr><td>completely</td><td>different</td><td>structure</td><td>here</td></tr></table></body></html>"),
	})
	if !b.Unstable() {
		t.Error("two disagreeing probes must report Unstable so the caller sends more")
	}
}

func TestRateLimitIsNeverInteresting(t *testing.T) {
	c := NewCalibrator()
	c.Learn("/", []Probe{probe("aaa111", 404, "nf"), probe("bbb222", 404, "nf")})
	if v := c.Classify("/", "/x", engine.Response{Status: 429, Body: []byte("slow down")}); v.Interesting {
		t.Error("429 classified as interesting")
	}
}

func TestTokenSetDropsVolatileTokens(t *testing.T) {
	toks := tokenSet([]byte("Request 8841 at 2026-01-02T03:04:05Z id=ab12cd34 Hello WORLD x"), "/zzz")
	for _, bad := range []string{"8841", "ab12cd34", "x"} {
		if _, ok := toks[bad]; ok {
			t.Errorf("volatile or too-short token %q kept", bad)
		}
	}
	for _, good := range []string{"request", "hello", "world"} {
		if _, ok := toks[good]; !ok {
			t.Errorf("token %q missing from %v", good, toks)
		}
	}
}

func FuzzDynamicClassify(f *testing.F) {
	f.Add([]byte("<html>a b c</html>"), []byte("x y z"), "/p")
	f.Add([]byte{0xff, 0x00}, []byte(""), "")
	f.Fuzz(func(t *testing.T, a, b []byte, path string) {
		tokenSet(a, path)
		c := NewCalibrator()
		c.Learn("/", []Probe{
			{Token: "t1", Resp: engine.Response{Status: 200, Body: a}},
			{Token: "t2", Resp: engine.Response{Status: 200, Body: b}},
			{Token: "t3", Resp: engine.Response{Status: 200, Body: append(append([]byte{}, a...), b...)}},
		})
		c.Classify("/", path, engine.Response{Status: 200, Body: b})
	})
}
