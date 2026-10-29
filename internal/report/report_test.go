package report

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/securewithharshitrajput/hellhound/internal/analyze"
	"github.com/securewithharshitrajput/hellhound/internal/discover"
)

func mkResult(url string, status int, body string) discover.Result {
	h := analyze.SimHash([]byte(body))
	return discover.Result{
		URL: url, Status: status, Length: len(body),
		Verdict: analyze.Verdict{Interesting: true, Reason: "test finding", ClusterKey: h},
	}
}

func TestBuildEmptyResults(t *testing.T) {
	rep := Build("http://target", nil)
	if rep.Total != 0 {
		t.Errorf("Total = %d, want 0", rep.Total)
	}
	if len(rep.Clusters) != 0 {
		t.Errorf("len(Clusters) = %d, want 0", len(rep.Clusters))
	}
}

func TestBuildGroupsAndCountsClusters(t *testing.T) {
	results := []discover.Result{
		mkResult("http://t/a", 200, "shared template body with some content here that is long enough"),
		mkResult("http://t/b", 200, "shared template body with some content here that is long enough"),
		mkResult("http://t/c", 200, "a completely different and unrelated page about something else"),
	}
	rep := Build("http://target", results)
	if rep.Total != 3 {
		t.Errorf("Total = %d, want 3", rep.Total)
	}
	if len(rep.Clusters) != 2 {
		t.Fatalf("expected 2 clusters (2 similar + 1 distinct), got %d", len(rep.Clusters))
	}
	// Largest cluster first (sorted by MemberCount descending).
	if rep.Clusters[0].MemberCount != 2 {
		t.Errorf("largest cluster MemberCount = %d, want 2", rep.Clusters[0].MemberCount)
	}
	if len(rep.Clusters[0].Members) != 2 {
		t.Errorf("largest cluster should list its Members since MemberCount > 1, got %d", len(rep.Clusters[0].Members))
	}
	// A singleton cluster shouldn't populate Members (omitempty, keeps
	// small reports small) — only MemberCount matters for a lone finding.
	if len(rep.Clusters[1].Members) != 0 {
		t.Errorf("singleton cluster should have empty Members, got %d", len(rep.Clusters[1].Members))
	}
}

// TestBuildDuplicateURLsDoNotCrash: Build keys its URL->Result side map by
// URL string. If the same URL ever appeared twice in results (not possible
// through today's discover.Run, but Build has no way to enforce that on
// its own input), it must not panic or produce a corrupted report —
// worth locking in explicitly since this map-by-URL pattern is exactly
// the kind of thing that breaks silently if an upstream caller's
// invariant ever changes.
func TestBuildDuplicateURLsDoNotCrash(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("Build panicked on duplicate URLs: %v", r)
		}
	}()
	results := []discover.Result{
		mkResult("http://t/dup", 200, "first version of the body"),
		mkResult("http://t/dup", 200, "first version of the body"),
	}
	rep := Build("http://target", results)
	if rep.Total != 2 {
		t.Errorf("Total = %d, want 2 (Build should still count both input results)", rep.Total)
	}
}

func TestWriteJSONRoundTrips(t *testing.T) {
	results := []discover.Result{
		mkResult("http://t/admin", 200, "admin panel content goes here for the test"),
	}
	rep := Build("http://target", results)

	var buf bytes.Buffer
	if err := WriteJSON(&buf, rep); err != nil {
		t.Fatalf("WriteJSON: %v", err)
	}

	var decoded JSONReport
	if err := json.Unmarshal(buf.Bytes(), &decoded); err != nil {
		t.Fatalf("output is not valid JSON matching JSONReport: %v\noutput:\n%s", err, buf.String())
	}
	if decoded.Target != "http://target" {
		t.Errorf("decoded Target = %q, want %q", decoded.Target, "http://target")
	}
	if decoded.Total != 1 {
		t.Errorf("decoded Total = %d, want 1", decoded.Total)
	}
	if len(decoded.Clusters) != 1 || decoded.Clusters[0].Representative.URL != "http://t/admin" {
		t.Errorf("decoded clusters don't match: %+v", decoded.Clusters)
	}
}

func TestWriteSummaryFormat(t *testing.T) {
	results := []discover.Result{
		mkResult("http://t/a", 200, "shared template aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
		mkResult("http://t/b", 200, "shared template aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
	}
	rep := Build("http://target", results)

	var buf bytes.Buffer
	WriteSummary(&buf, rep)
	out := buf.String()

	if !strings.Contains(out, "2 findings in 1 cluster(s)") {
		t.Errorf("summary missing expected header line, got:\n%s", out)
	}
	if !strings.Contains(out, "+1 similar") {
		t.Errorf("summary missing the '+N similar' tag for a 2-member cluster, got:\n%s", out)
	}
}
