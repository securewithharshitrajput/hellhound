package report

import (
	"bytes"
	"encoding/csv"
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

func TestWriteCSV(t *testing.T) {
	results := []discover.Result{
		mkResult("http://t/a", 200, "shared aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
		mkResult("http://t/b", 200, "shared aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
		mkResult("http://t/admin", 403, "totally different content for the admin forbidden page here"),
	}
	rep := Build("http://target", results)

	var buf bytes.Buffer
	if err := WriteCSV(&buf, rep); err != nil {
		t.Fatalf("WriteCSV: %v", err)
	}
	rows, err := csv.NewReader(&buf).ReadAll()
	if err != nil {
		t.Fatalf("output is not valid CSV: %v", err)
	}
	// Header + one row per finding (all 3 flattened, not 2 clusters).
	if len(rows) != 1+3 {
		t.Fatalf("expected header + 3 finding rows, got %d rows: %v", len(rows), rows)
	}
	if rows[0][0] != "url" || rows[0][1] != "status" {
		t.Errorf("unexpected header: %v", rows[0])
	}
	// Every data row's URL must be one of the inputs.
	seen := map[string]bool{}
	for _, row := range rows[1:] {
		seen[row[0]] = true
	}
	for _, want := range []string{"http://t/a", "http://t/b", "http://t/admin"} {
		if !seen[want] {
			t.Errorf("CSV missing finding %s", want)
		}
	}
}

func TestWriteSARIFIsValidAndComplete(t *testing.T) {
	results := []discover.Result{
		mkResult("http://t/admin", 200, "admin panel content for the test here and there"),
		mkResult("http://t/backup.zip", 200, "PK zip bytes totally distinct from the admin page content"),
	}
	rep := Build("http://target", results)

	var buf bytes.Buffer
	if err := WriteSARIF(&buf, rep); err != nil {
		t.Fatalf("WriteSARIF: %v", err)
	}

	// Must be valid JSON with the SARIF skeleton intact.
	var doc map[string]any
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("SARIF output is not valid JSON: %v", err)
	}
	if doc["version"] != "2.1.0" {
		t.Errorf("SARIF version = %v, want 2.1.0", doc["version"])
	}
	runs, ok := doc["runs"].([]any)
	if !ok || len(runs) != 1 {
		t.Fatalf("expected exactly 1 run, got %v", doc["runs"])
	}
	run := runs[0].(map[string]any)
	sarifResults, ok := run["results"].([]any)
	if !ok || len(sarifResults) != 2 {
		t.Fatalf("expected 2 SARIF results (one per finding), got %v", run["results"])
	}
	// Each result must carry a location URI matching a finding.
	first := sarifResults[0].(map[string]any)
	locs := first["locations"].([]any)
	if len(locs) == 0 {
		t.Fatal("SARIF result has no location")
	}
}
