package report

import (
	"encoding/csv"
	"encoding/json"
	"io"
	"strconv"
)

// WriteCSV writes one row per FINDING (flattening clusters — every member,
// not just representatives), so the output feeds cleanly into spreadsheets,
// grep/awk pipelines, or a database import. Header row first.
func WriteCSV(w io.Writer, r JSONReport) error {
	cw := csv.NewWriter(w)
	defer cw.Flush()
	if err := cw.Write([]string{"url", "status", "length", "words", "lines", "depth", "reason"}); err != nil {
		return err
	}
	writeRow := func(f JSONFinding) error {
		return cw.Write([]string{
			f.URL,
			strconv.Itoa(f.Status),
			strconv.Itoa(f.Length),
			strconv.Itoa(f.Words),
			strconv.Itoa(f.Lines),
			strconv.Itoa(f.Depth),
			f.Reason,
		})
	}
	for _, c := range r.Clusters {
		if len(c.Members) > 0 {
			for _, m := range c.Members {
				if err := writeRow(m); err != nil {
					return err
				}
			}
		} else {
			if err := writeRow(c.Representative); err != nil {
				return err
			}
		}
	}
	return cw.Error()
}

// --- SARIF 2.1.0 ---
//
// SARIF (Static Analysis Results Interchange Format) is what CI systems —
// GitHub code scanning in particular — ingest to display findings in a PR /
// security dashboard. Emitting it lets a hellhound run in CI surface
// discovered endpoints as annotations instead of buried log lines. Only the
// minimal subset needed for a valid, displayable document is produced.

type sarifReport struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	InformationURI string      `json:"informationUri"`
	Rules          []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID               string    `json:"id"`
	Name             string    `json:"name"`
	ShortDescription sarifText `json:"shortDescription"`
}

type sarifText struct {
	Text string `json:"text"`
}

type sarifResult struct {
	RuleID    string          `json:"ruleId"`
	Level     string          `json:"level"`
	Message   sarifText       `json:"message"`
	Locations []sarifLocation `json:"locations"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysicalLocation `json:"physicalLocation"`
}

type sarifPhysicalLocation struct {
	ArtifactLocation sarifArtifactLocation `json:"artifactLocation"`
}

type sarifArtifactLocation struct {
	URI string `json:"uri"`
}

const sarifRuleID = "hellhound/discovered-endpoint"

// WriteSARIF writes the findings as a SARIF 2.1.0 document. Every finding
// (all cluster members) becomes one result located at its URL, under a
// single "discovered-endpoint" rule, at "note" level — these are
// discoveries for a human to triage, not asserted vulnerabilities.
func WriteSARIF(w io.Writer, r JSONReport) error {
	doc := sarifReport{
		Schema:  "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
		Version: "2.1.0",
		Runs: []sarifRun{{
			Tool: sarifTool{Driver: sarifDriver{
				Name:           "hellhound",
				InformationURI: "https://github.com/securewithharshitrajput/hellhound",
				Rules: []sarifRule{{
					ID:               sarifRuleID,
					Name:             "DiscoveredEndpoint",
					ShortDescription: sarifText{Text: "An endpoint discovered by calibrated content discovery or crawling"},
				}},
			}},
			Results: []sarifResult{},
		}},
	}
	add := func(f JSONFinding) {
		doc.Runs[0].Results = append(doc.Runs[0].Results, sarifResult{
			RuleID:  sarifRuleID,
			Level:   "note",
			Message: sarifText{Text: "[" + strconv.Itoa(f.Status) + "] " + f.URL + " — " + f.Reason},
			Locations: []sarifLocation{{
				PhysicalLocation: sarifPhysicalLocation{
					ArtifactLocation: sarifArtifactLocation{URI: f.URL},
				},
			}},
		})
	}
	for _, c := range r.Clusters {
		if len(c.Members) > 0 {
			for _, m := range c.Members {
				add(m)
			}
		} else {
			add(c.Representative)
		}
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(doc)
}
