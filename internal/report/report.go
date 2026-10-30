// Package report renders discovery results as JSON and as a clustered
// human-readable summary (the de-duplicated view: one line per distinct
// template/shape, with a member count, instead of one line per hit).
package report

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"

	"github.com/securewithharshitrajput/hellhound/internal/analyze"
	"github.com/securewithharshitrajput/hellhound/internal/discover"
)

// JSONFinding is the wire format for one discovery result.
type JSONFinding struct {
	URL    string `json:"url"`
	Status int    `json:"status"`
	Length int    `json:"length"`
	Words  int    `json:"words"`
	Lines  int    `json:"lines"`
	Depth  int    `json:"depth"`
	Reason string `json:"reason"`
}

// JSONCluster groups near-duplicate findings under one representative.
type JSONCluster struct {
	Representative JSONFinding   `json:"representative"`
	MemberCount    int           `json:"member_count"`
	Members        []JSONFinding `json:"members,omitempty"`
}

// JSONReport is the full output document.
type JSONReport struct {
	Target           string                     `json:"target"`
	Total            int                        `json:"total_findings"`
	Clusters         []JSONCluster              `json:"clusters"`
	SecurityFindings []discover.SecurityFinding `json:"security_findings,omitempty"`
}

func toJSONFinding(r discover.Result) JSONFinding {
	return JSONFinding{
		URL: r.URL, Status: r.Status, Length: r.Length,
		Words: r.Words, Lines: r.Lines, Depth: r.Depth,
		Reason: r.Verdict.Reason,
	}
}

// Build converts raw discovery results into a clustered report, grouping
// near-duplicate bodies via analyze.ClusterFindings so a templated section
// rendered hundreds of times collapses to one entry with a count — this is
// the "advance over ffuf" payoff: the operator reads N clusters, not N
// thousand near-identical lines.
func Build(target string, results []discover.Result) JSONReport {
	findings := make([]analyze.Finding, len(results))
	resultByURL := make(map[string]discover.Result, len(results))
	for i, r := range results {
		findings[i] = analyze.Finding{
			URL: r.URL, Status: r.Status, Length: r.Length,
			Words: r.Words, Lines: r.Lines, Verdict: r.Verdict,
		}
		resultByURL[r.URL] = r
	}
	// analyze.ClusterFindings groups by body shape; we keep a URL->Result
	// side map because discover.Result carries Depth, which analyze.Finding
	// deliberately doesn't need to know about.
	clusters := analyze.ClusterFindings(findings)

	out := JSONReport{Target: target, Total: len(results)}
	for _, c := range clusters {
		rep := resultByURL[c.Representative.URL]
		jc := JSONCluster{
			Representative: toJSONFinding(rep),
			MemberCount:    len(c.Members),
		}
		if len(c.Members) > 1 {
			for _, m := range c.Members {
				jc.Members = append(jc.Members, toJSONFinding(resultByURL[m.URL]))
			}
		}
		out.Clusters = append(out.Clusters, jc)
	}
	sort.SliceStable(out.Clusters, func(i, j int) bool {
		return out.Clusters[i].MemberCount > out.Clusters[j].MemberCount
	})
	return out
}

// WriteJSON writes the report as indented JSON.
func WriteJSON(w io.Writer, r JSONReport) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(r)
}

// WriteSummary writes a compact, human-readable cluster summary — the
// "read this in ten seconds" view.
func WriteSummary(w io.Writer, r JSONReport) {
	fmt.Fprintf(w, "hellhound: %d findings in %d cluster(s) for %s\n\n", r.Total, len(r.Clusters), r.Target)
	for _, c := range r.Clusters {
		tag := ""
		if c.MemberCount > 1 {
			tag = fmt.Sprintf(" (+%d similar)", c.MemberCount-1)
		}
		fmt.Fprintf(w, "  [%d] %-60s len=%-6d %s%s\n", c.Representative.Status, c.Representative.URL, c.Representative.Length, c.Representative.Reason, tag)
	}
	WriteSecuritySummary(w, r.SecurityFindings)
}

// WriteSecuritySummary prints the Tier-A findings grouped by type, sorted
// so high-severity shows up at the top. The eye-catching marker makes these
// trivially distinguishable from the plain discovery hits above.
func WriteSecuritySummary(w io.Writer, findings []discover.SecurityFinding) {
	if len(findings) == 0 {
		return
	}
	// highest severity first, then group by type for readability
	sorted := make([]discover.SecurityFinding, len(findings))
	copy(sorted, findings)
	sort.SliceStable(sorted, func(i, j int) bool {
		ri := discover.SeverityRank(sorted[i].Severity)
		rj := discover.SeverityRank(sorted[j].Severity)
		if ri != rj {
			return ri > rj
		}
		if sorted[i].Type != sorted[j].Type {
			return sorted[i].Type < sorted[j].Type
		}
		return sorted[i].URL < sorted[j].URL
	})

	fmt.Fprintf(w, "\n[security] %d finding(s):\n", len(sorted))
	for _, f := range sorted {
		fmt.Fprintf(w, "  [%s] %s  %s\n", severityLabel(f.Severity), f.Type, f.URL)
		fmt.Fprintf(w, "        %s\n", f.Description)
		if f.Evidence != "" {
			ev := f.Evidence
			if len(ev) > 100 {
				ev = ev[:97] + "..."
			}
			fmt.Fprintf(w, "        evidence: %s\n", ev)
		}
	}
}

// severityLabel returns an uppercased, fixed-width severity label for
// consistent terminal alignment ("HIGH  " vs "LOW   " etc).
func severityLabel(s string) string {
	switch s {
	case "high":
		return "HIGH  "
	case "medium":
		return "MEDIUM"
	case "low":
		return "LOW   "
	case "info":
		return "INFO  "
	}
	return s
}
