// Sensitive-file detection: a dedicated phase that probes conventional
// locations for files that leak credentials, source control metadata, or
// developer artifacts never meant to be public. These are the "I actually
// found something" discoveries that justify a pentest report by themselves —
// a readable .env or .git/config is often full compromise, not a weakness
// to triage.
//
// This phase deliberately runs OUTSIDE calibrated path discovery: calibration
// is designed to suppress noise against unknown targets, but the baseline it
// learns can occasionally mask a genuine sensitive-file hit when the target
// serves a 200-dressed-up-as-404 for everything. A direct probe for a
// known-dangerous path, with explicit content checks, catches cases
// calibration might filter out.
package discover

import (
	"bytes"
	"context"
	"strings"

	"github.com/securewithharshitrajput/hellhound/internal/engine"
)

// sensitiveProbe is one well-known dangerous path, with content fingerprints
// that must appear in the response body to count as a hit (rejects a soft-404
// that returns 200 with HTML).
type sensitiveProbe struct {
	Path     string
	Markers  []string // ANY of these substrings in the body confirms the file
	Severity string
	Why      string
}

// sensitiveTargets is the curated list. New additions must include at least
// one body marker — status 200 alone is not enough, because many WAFs and
// SPAs return 200 for everything.
var sensitiveTargets = []sensitiveProbe{
	// Secrets / credentials
	{"/.env", []string{"=", "APP_", "DB_", "SECRET", "KEY", "PASSWORD", "TOKEN"}, "high", "environment file commonly contains database and API credentials"},
	{"/config.env", []string{"=", "APP_", "DB_", "SECRET"}, "high", "environment file commonly contains credentials"},
	{"/.env.local", []string{"=", "APP_", "DB_", "SECRET"}, "high", "local environment file commonly contains credentials"},
	{"/.env.production", []string{"=", "APP_", "DB_", "SECRET"}, "high", "production environment file commonly contains credentials"},
	{"/credentials.json", []string{"\"client_id\"", "\"client_secret\"", "\"api_key\"", "\"token\""}, "high", "credential file"},
	{"/aws.json", []string{"aws_access_key", "aws_secret"}, "high", "AWS credentials"},
	{"/secrets.json", []string{"\"", "secret", "key"}, "high", "secrets file"},

	// Source control
	{"/.git/config", []string{"[core]", "[remote", "repositoryformatversion"}, "high", ".git directory exposed — attacker can reconstruct full source tree"},
	{"/.git/HEAD", []string{"ref:"}, "high", ".git directory exposed — attacker can reconstruct full source tree"},
	{"/.svn/entries", []string{"svn", "dir"}, "high", ".svn directory exposed"},
	{"/.hg/hgrc", []string{"[", "paths"}, "high", ".hg (Mercurial) directory exposed"},
	{"/.bzr/branch/branch.conf", []string{"parent_location"}, "medium", ".bzr (Bazaar) directory exposed"},

	// Package manifests (not fatal on their own but reveal exact dependency versions → CVE lookup)
	{"/package.json", []string{"\"name\"", "\"dependencies\"", "\"scripts\""}, "low", "node package manifest exposes dependency versions"},
	{"/composer.json", []string{"\"require\"", "\"autoload\""}, "low", "composer manifest exposes PHP dependency versions"},
	{"/Gemfile.lock", []string{"GEM", "specs:"}, "low", "Ruby Gemfile.lock exposes exact dependency versions"},
	{"/requirements.txt", []string{"=="}, "low", "Python requirements.txt exposes exact dependency versions"},
	{"/go.mod", []string{"module ", "go "}, "low", "Go module file exposes dependency versions"},
	{"/pom.xml", []string{"<project", "<groupId", "<artifactId"}, "low", "Maven pom.xml exposes dependency versions"},
	{"/build.gradle", []string{"dependencies", "implementation", "compile"}, "low", "Gradle build file exposes dependency versions"},

	// Backups
	{"/backup.sql", []string{"CREATE TABLE", "INSERT INTO", "DROP TABLE", "-- MySQL", "-- PostgreSQL"}, "high", "SQL dump exposed"},
	{"/dump.sql", []string{"CREATE TABLE", "INSERT INTO", "-- MySQL"}, "high", "SQL dump exposed"},
	{"/database.sql", []string{"CREATE TABLE", "INSERT INTO"}, "high", "SQL dump exposed"},
	{"/db.sqlite", []string{"SQLite format"}, "high", "SQLite database exposed"},
	{"/db.sqlite3", []string{"SQLite format"}, "high", "SQLite database exposed"},

	// OS / editor crumbs
	{"/.DS_Store", []string{"Bud1"}, "low", "macOS .DS_Store leaks directory listing"},
	{"/Thumbs.db", []string{"\xff\xfe"}, "low", "Windows Thumbs.db leaks directory listing"},

	// IaC
	{"/.terraform.tfstate", []string{"\"version\"", "\"terraform_version\"", "\"resources\""}, "high", "Terraform state file commonly contains cloud credentials and resource identifiers"},
	{"/terraform.tfstate", []string{"\"version\"", "\"terraform_version\"", "\"resources\""}, "high", "Terraform state file commonly contains cloud credentials and resource identifiers"},
	{"/docker-compose.yml", []string{"version:", "services:"}, "low", "docker-compose exposes service topology and sometimes env vars"},
	{"/Dockerfile", []string{"FROM ", "RUN ", "COPY "}, "low", "Dockerfile exposes build steps"},

	// Server config
	{"/web.config", []string{"<configuration", "<system.web"}, "medium", "IIS web.config exposed"},
	{"/.htaccess", []string{"RewriteEngine", "AuthType", "Options "}, "medium", ".htaccess exposed"},
	{"/.htpasswd", []string{":"}, "high", ".htpasswd exposes hashed credentials"},

	// Framework specific
	{"/wp-config.php.bak", []string{"DB_PASSWORD", "DB_USER", "define("}, "high", "WordPress config backup exposes DB credentials"},
	{"/wp-config.php~", []string{"DB_PASSWORD", "define("}, "high", "WordPress config backup exposes DB credentials"},
	{"/wp-config.php.old", []string{"DB_PASSWORD", "define("}, "high", "WordPress config backup exposes DB credentials"},
	{"/config.php.bak", []string{"password", "DB_"}, "high", "PHP config backup"},
	{"/application.yml", []string{"spring:", "datasource:", "password:"}, "medium", "Spring application.yml may contain credentials"},
	{"/application.properties", []string{"spring.", "datasource.", "password="}, "medium", "Spring application.properties may contain credentials"},

	// Private keys
	{"/id_rsa", []string{"-----BEGIN", "PRIVATE KEY"}, "high", "SSH private key exposed"},
	{"/server.key", []string{"-----BEGIN", "PRIVATE KEY"}, "high", "private key exposed"},
	{"/private.key", []string{"-----BEGIN", "PRIVATE KEY"}, "high", "private key exposed"},
	{"/privkey.pem", []string{"-----BEGIN", "PRIVATE KEY"}, "high", "private key exposed"},
}

// ScanSensitive probes the curated list of known-dangerous paths in ONE
// concurrent batch and returns only confirmed hits (status 200/206 AND at
// least one content marker present). Non-200 responses and 200s that look
// like generic HTML pages (missing all markers) are rejected to avoid soft-
// 404 false positives.
func ScanSensitive(ctx context.Context, eng *engine.Engine, baseURL string) []SecurityFinding {
	reqs := make([]engine.Request, len(sensitiveTargets))
	for i, p := range sensitiveTargets {
		reqs[i] = engine.Request{Method: "GET", URL: baseURL + p.Path}
	}
	resps := eng.DoAll(ctx, reqs)

	var out []SecurityFinding
	for i, resp := range resps {
		if resp.Err != nil {
			continue
		}
		// Accept 200 and 206 (partial). 403 can also leak existence but we
		// won't flag without content confirmation.
		if resp.Status != 200 && resp.Status != 206 {
			continue
		}
		probe := sensitiveTargets[i]
		if !bodyContainsAny(resp.Body, probe.Markers) {
			continue
		}
		out = append(out, SecurityFinding{
			Type:        "sensitive-file",
			Severity:    probe.Severity,
			URL:         baseURL + probe.Path,
			Description: probe.Why,
			Evidence:    firstMatchingMarker(resp.Body, probe.Markers),
		})
	}
	return out
}

// bodyContainsAny does a case-sensitive substring check. Markers were chosen
// to be case-stable (file headers, syntax tokens) so no normalization is
// needed and the check stays cheap.
func bodyContainsAny(body []byte, markers []string) bool {
	for _, m := range markers {
		if bytes.Contains(body, []byte(m)) {
			return true
		}
	}
	return false
}

// firstMatchingMarker returns the first marker found in the body — exposed
// as "evidence" so the operator sees WHY the detector fired without having
// to re-fetch the file. Capped so a 2MB SQL dump doesn't make the output
// unreadable.
func firstMatchingMarker(body []byte, markers []string) string {
	for _, m := range markers {
		if idx := bytes.Index(body, []byte(m)); idx >= 0 {
			end := idx + len(m) + 40
			if end > len(body) {
				end = len(body)
			}
			s := string(body[idx:end])
			// strip control chars so terminal output stays clean
			s = strings.Map(func(r rune) rune {
				if r == '\n' || r == '\r' || r == '\t' {
					return ' '
				}
				if r < 32 {
					return -1
				}
				return r
			}, s)
			return s
		}
	}
	return ""
}
