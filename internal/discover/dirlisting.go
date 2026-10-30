// Directory-listing detection: when a server returns the raw contents of a
// directory (Apache mod_autoindex, nginx autoindex, Python SimpleHTTPServer,
// etc.) in response to a request for a directory URL, that's an immediate
// disclosure — every filename, often including intended-private backups, is
// visible. Classifying these distinctly from "a 200 that returned HTML" lets
// the operator triage them straight to the top.
package discover

import "bytes"

// dirListingMarkers are strings whose presence in a response body strongly
// suggests the body is a directory listing rather than a real content page.
// Different servers produce different stock listings; the set below covers
// the common three (Apache / nginx / python -m http.server) and a few less
// common ones.
var dirListingMarkers = [][]byte{
	[]byte("<title>Index of /"),
	[]byte("<h1>Index of /"),
	[]byte("[DIR]"),
	[]byte("Parent Directory</a>"),
	[]byte("Directory listing for "), // python's http.server
	[]byte("Last modified</a>"),
	[]byte("<pre><a href=\"../\">"),
}

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

// DetectDirListing returns the first matching marker preview and true if
// body looks like a dir listing. Exported so other callers (crawler, etc.)
// can reuse the same classifier.
func DetectDirListing(body []byte) (string, bool) {
	for _, m := range dirListingMarkers {
		if idx := bytes.Index(body, m); idx >= 0 {
			end := idx + len(m) + 40
			if end > len(body) {
				end = len(body)
			}
			return string(body[idx:end]), true
		}
	}
	return "", false
}
