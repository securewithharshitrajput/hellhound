// Tier-A findings: the "this looks dangerous" layer that lifts hellhound
// from a pure endpoint discoverer into a tool that classifies what it finds.
// Every detector in this package (sensitive-file, dir-listing, dangerous-
// method, open-redirect, info-disclosure) returns results in this shared
// shape so the reporter can render them under one unified "security
// findings" section.
package discover

// SecurityFinding is one classified security-relevant observation. Unlike
// discover.Result, which just says "this endpoint exists and does not match
// the calibrated baseline," a SecurityFinding says "this endpoint exists
// AND it is dangerous for reason X" — the operator can skip triage.
//
// Severity levels are deliberately small and operator-oriented:
//
//	high   — unauthenticated credential/data exposure (e.g. .env, .git/config)
//	medium — misconfiguration with real exploit potential (dir listing, dangerous HTTP methods, open-redirect)
//	low    — information useful for pivoting, not directly exploitable (tech-version headers)
//	info   — context the operator should see but is not a flaw by itself
type SecurityFinding struct {
	Type        string `json:"type"`               // e.g. "sensitive-file", "dir-listing", "dangerous-methods", "open-redirect", "info-disclosure"
	Severity    string `json:"severity"`           // "high" | "medium" | "low" | "info"
	URL         string `json:"url"`                // where it was observed
	Description string `json:"description"`        // human-readable one-liner
	Evidence    string `json:"evidence,omitempty"` // optional short excerpt (header value, body marker, method list)
}

// Severity ranks for sort stability (highest first).
var severityRank = map[string]int{
	"high":   4,
	"medium": 3,
	"low":    2,
	"info":   1,
}

// SeverityRank returns a numeric rank so callers can sort findings
// consistently without hard-coding the string ordering.
func SeverityRank(s string) int { return severityRank[s] }
