package report

import (
	"encoding/csv"
	"encoding/json"
	"io"
	"strconv"
	"strings"
)

// WriteCSV writes one row per FINDING (flattening clusters — every member,
// not just representatives), so the output feeds cleanly into spreadsheets,
// grep/awk pipelines, or a database import. Header row first. Security
// findings are written as additional rows with kind="security" and the
// severity in the reason column.
func WriteCSV(w io.Writer, r JSONReport) error {
	cw := csv.NewWriter(w)
	defer cw.Flush()
	if err := cw.Write([]string{"kind", "type", "severity", "url", "status", "length", "words", "lines", "depth", "reason", "evidence"}); err != nil {
		return err
	}
	writeRow := func(f JSONFinding) error {
		return cw.Write([]string{
			"endpoint", "", "",
			f.URL,
			strconv.Itoa(f.Status),
			strconv.Itoa(f.Length),
			strconv.Itoa(f.Words),
			strconv.Itoa(f.Lines),
			strconv.Itoa(f.Depth),
			f.Reason, "",
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
	for _, s := range r.SecurityFindings {
		if err := cw.Write([]string{
			"security", s.Type, s.Severity,
			s.URL, "", "", "", "", "",
			s.Description, s.Evidence,
		}); err != nil {
			return err
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

const (
	sarifRuleEndpoint        = "hellhound/discovered-endpoint"
	sarifRuleSensitiveFile   = "hellhound/sensitive-file"
	sarifRuleDirListing      = "hellhound/dir-listing"
	sarifRuleDangerousMethod = "hellhound/dangerous-methods"
	sarifRuleOpenRedirect    = "hellhound/open-redirect"
	sarifRuleInfoDisclosure  = "hellhound/info-disclosure"
)

// sarifLevelFor maps hellhound severities to SARIF levels. SARIF only has
// four levels (none/note/warning/error), so high collapses to "error" and
// medium/low both map to "warning" (preserving them separately would need a
// non-standard property GitHub ignores anyway).
func sarifLevelFor(severity string) string {
	switch severity {
	case "high":
		return "error"
	case "medium":
		return "warning"
	case "low":
		return "warning"
	case "info":
		return "note"
	}
	return "note"
}

func sarifRuleForType(t string) string {
	switch t {
	case "sensitive-file":
		return sarifRuleSensitiveFile
	case "dir-listing":
		return sarifRuleDirListing
	case "dangerous-methods":
		return sarifRuleDangerousMethod
	case "open-redirect":
		return sarifRuleOpenRedirect
	case "info-disclosure":
		return sarifRuleInfoDisclosure
	}
	return sarifRuleEndpoint
}

// WriteSARIF writes the findings as a SARIF 2.1.0 document. Discovery
// endpoints map to the "discovered-endpoint" rule at "note" level; each
// Tier-A security finding maps to its own rule at the appropriate severity
// so a CI dashboard shows the real problems in red and the discovery noise
// in gray.
func WriteSARIF(w io.Writer, r JSONReport) error {
	doc := sarifReport{
		Schema:  "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
		Version: "2.1.0",
		Runs: []sarifRun{{
			Tool: sarifTool{Driver: sarifDriver{
				Name:           "hellhound",
				InformationURI: "https://github.com/securewithharshitrajput/hellhound",
				Rules: []sarifRule{
					{ID: sarifRuleEndpoint, Name: "DiscoveredEndpoint", ShortDescription: sarifText{Text: "An endpoint discovered by calibrated content discovery or crawling"}},
					{ID: sarifRuleSensitiveFile, Name: "SensitiveFileExposed", ShortDescription: sarifText{Text: "A sensitive file (secrets, source control, backup) is publicly reachable"}},
					{ID: sarifRuleDirListing, Name: "DirectoryListingEnabled", ShortDescription: sarifText{Text: "Directory listing is enabled, every file in the directory is enumerable"}},
					{ID: sarifRuleDangerousMethod, Name: "DangerousHTTPMethod", ShortDescription: sarifText{Text: "Server advertises PUT/DELETE/PATCH/TRACE on an endpoint"}},
					{ID: sarifRuleOpenRedirect, Name: "OpenRedirect", ShortDescription: sarifText{Text: "URL parameter is reflected into Location header without validation"}},
					{ID: sarifRuleInfoDisclosure, Name: "InformationDisclosureHeader", ShortDescription: sarifText{Text: "Response header exposes framework/runtime version information"}},
				},
			}},
			Results: []sarifResult{},
		}},
	}
	add := func(f JSONFinding) {
		doc.Runs[0].Results = append(doc.Runs[0].Results, sarifResult{
			RuleID:  sarifRuleEndpoint,
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
	for _, s := range r.SecurityFindings {
		msg := "[" + strings.ToUpper(s.Severity) + "] " + s.URL + " — " + s.Description
		if s.Evidence != "" {
			msg += " (evidence: " + s.Evidence + ")"
		}
		doc.Runs[0].Results = append(doc.Runs[0].Results, sarifResult{
			RuleID:  sarifRuleForType(s.Type),
			Level:   sarifLevelFor(s.Severity),
			Message: sarifText{Text: msg},
			Locations: []sarifLocation{{
				PhysicalLocation: sarifPhysicalLocation{
					ArtifactLocation: sarifArtifactLocation{URI: s.URL},
				},
			}},
		})
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(doc)
}
