// Directory-listing detection: when a server returns the raw contents of a
// directory (Apache mod_autoindex, nginx autoindex, Python SimpleHTTPServer,
// etc.) in response to a request for a directory URL, that's an immediate
// disclosure — every filename, often including intended-private backups, is
// visible. Classifying these distinctly from "a 200 that returned HTML" lets
// the operator triage them straight to the top.
package discover

import "regexp"

// dirListingRe matches the heading a server-generated index page carries:
// Apache/nginx/lighttpd "Index of /path", Python http.server "Directory
// listing for /path", and IIS's "[To Parent Directory]" link. The match is
// anchored to the <title>/<h1> element (or the IIS link text) because looser
// markers such as "[DIR]" or a "Last modified" column also appear on
// ordinary documentation and changelog pages.
var dirListingRe = regexp.MustCompile(`(?i)<(?:title|h1)>\s*(?:Index of|Directory listing for)\s+/[^<]*</(?:title|h1)>|\[To Parent Directory\]</a>`)

// ClassifyDirListings scans the Results' BodyPreview fields and promotes
// those matching a directory-listing fingerprint into a dedicated
// SecurityFinding. Requires status 200 — a 403 that says "listing disabled"
// is the opposite of a vulnerability.
func ClassifyDirListings(results []Result) []SecurityFinding {
	var out []SecurityFinding
	seen := map[string]bool{}
	for _, r := range results {
		if r.Status != 200 || len(r.BodyPreview) == 0 || seen[r.URL] {
			continue
		}
		marker, ok := DetectDirListing(r.BodyPreview)
		if !ok {
			continue
		}
		seen[r.URL] = true
		out = append(out, SecurityFinding{
			Type:        "dir-listing",
			Severity:    "medium",
			URL:         r.URL,
			Description: "directory listing enabled — every filename in this directory is enumerable, including non-linked backups",
			Evidence:    marker,
		})
	}
	return out
}

// DetectDirListing returns the matching heading and true if body looks like
// a server-generated directory index.
func DetectDirListing(body []byte) (string, bool) {
	m := dirListingRe.Find(body)
	if m == nil {
		return "", false
	}
	if len(m) > 100 {
		m = m[:100]
	}
	return string(m), true
}
