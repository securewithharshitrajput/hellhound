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
	"regexp"
	"strings"

	"github.com/securewithharshitrajput/hellhound/internal/analyze"
	"github.com/securewithharshitrajput/hellhound/internal/engine"
)

// matcher decides whether a response body really is the file a probe asked
// for, returning a short evidence excerpt when it is. Matchers are strict on
// purpose: a loose substring like "=" or ":" is present in almost every HTML
// page, so a catch-all target would be reported as leaking every file.
type matcher func(body []byte) (string, bool)

// sensitiveProbe is one well-known dangerous path plus the content check
// that confirms it.
type sensitiveProbe struct {
	Path     string
	Match    matcher
	Severity string
	Why      string
}

// anyLit matches when any literal is present.
func anyLit(lits ...string) matcher {
	return func(body []byte) (string, bool) {
		for _, l := range lits {
			if i := bytes.Index(body, []byte(l)); i >= 0 {
				return excerpt(body, i, len(l)), true
			}
		}
		return "", false
	}
}

// allLit matches when every literal is present; evidence is the first one.
func allLit(lits ...string) matcher {
	return func(body []byte) (string, bool) {
		for _, l := range lits {
			if !bytes.Contains(body, []byte(l)) {
				return "", false
			}
		}
		i := bytes.Index(body, []byte(lits[0]))
		return excerpt(body, i, len(lits[0])), true
	}
}

// prefix matches a file magic at offset 0.
func prefix(magic string) matcher {
	return func(body []byte) (string, bool) {
		if bytes.HasPrefix(body, []byte(magic)) {
			return excerpt(body, 0, len(magic)), true
		}
		return "", false
	}
}

// re matches a regular expression (RE2, linear time).
func re(pattern string) matcher {
	rx := regexp.MustCompile(pattern)
	return func(body []byte) (string, bool) {
		loc := rx.FindIndex(body)
		if loc == nil {
			return "", false
		}
		return excerpt(body, loc[0], loc[1]-loc[0]), true
	}
}

// jsonWith matches a JSON document (object or array) that also satisfies m.
func jsonWith(m matcher) matcher {
	return func(body []byte) (string, bool) {
		t := bytes.TrimLeft(body, " \t\r\n\xef\xbb\xbf")
		if len(t) == 0 || (t[0] != '{' && t[0] != '[') {
			return "", false
		}
		return m(body)
	}
}

var (
	envFile    = envMatcher
	secretJSON = jsonWith(re(`(?i)"[^"\n]*(?:secret|token|passw|api_?key|client_id|private_key|access_key)[^"\n]*"\s*:`))
	sqlDump    = anyLit("CREATE TABLE", "INSERT INTO", "DROP TABLE IF EXISTS")
	sqliteDB   = prefix("SQLite format 3")
	privateKey = re(`-----BEGIN [A-Z ]*PRIVATE KEY-----`)
	tfState    = jsonWith(anyLit(`"terraform_version"`))
	wpConfig   = anyLit("DB_PASSWORD")
)

// sensitiveTargets is the curated list. Every entry needs a matcher that a
// generic HTML/text page cannot satisfy.
var sensitiveTargets = []sensitiveProbe{
	// Secrets / credentials
	{"/.env", envFile, "high", "environment file commonly contains database and API credentials"},
	{"/config.env", envFile, "high", "environment file commonly contains credentials"},
	{"/.env.local", envFile, "high", "local environment file commonly contains credentials"},
	{"/.env.production", envFile, "high", "production environment file commonly contains credentials"},
	{"/.env.backup", envFile, "high", "environment file backup commonly contains credentials"},
	{"/.env.bak", envFile, "high", "environment file backup commonly contains credentials"},
	{"/credentials.json", secretJSON, "high", "credential file"},
	{"/aws.json", secretJSON, "high", "AWS credentials"},
	{"/secrets.json", secretJSON, "high", "secrets file"},
	{"/.aws/credentials", re(`(?m)^aws_(?:access_key_id|secret_access_key)\s*=`), "high", "AWS credentials file"},
	{"/.npmrc", re(`(?m)_authToken\s*=|^_auth\s*=`), "high", ".npmrc exposes a registry auth token"},
	{"/.git-credentials", redacted(re(`(?m)^https?://[^\s:/@]+:[^\s@]+@`), "credential URL with embedded password (redacted)"), "high", "stored git credentials exposed"},

	// Source control
	{"/.git/config", anyLit("[core]", `[remote "`), "high", ".git directory exposed — attacker can reconstruct full source tree"},
	{"/.git/HEAD", re(`\Aref: refs/\S+\s*\z|\A[0-9a-f]{40}\s*\z`), "high", ".git directory exposed — attacker can reconstruct full source tree"},
	{"/.svn/wc.db", sqliteDB, "high", ".svn directory exposed"},
	{"/.svn/entries", re(`\A\d+\s*\n\s*dir\b`), "high", ".svn directory exposed"},
	{"/.hg/hgrc", anyLit("[paths]", "[ui]"), "high", ".hg (Mercurial) directory exposed"},
	{"/.bzr/branch/branch.conf", anyLit("parent_location"), "medium", ".bzr (Bazaar) directory exposed"},

	// Package manifests (reveal exact dependency versions → CVE lookup)
	{"/package.json", jsonWith(re(`"(?:dependencies|devDependencies|scripts)"\s*:`)), "low", "node package manifest exposes dependency versions"},
	{"/composer.json", jsonWith(re(`"require(?:-dev)?"\s*:`)), "low", "composer manifest exposes PHP dependency versions"},
	{"/Gemfile.lock", allLit("specs:", "GEM"), "low", "Ruby Gemfile.lock exposes exact dependency versions"},
	{"/requirements.txt", re(`(?m)^[A-Za-z0-9_.\-]+(?:\[[A-Za-z0-9_,\-]+\])?[ \t]*(?:==|>=|~=)[ \t]*\d`), "low", "Python requirements.txt exposes exact dependency versions"},
	{"/go.mod", re(`(?m)^module \S+`), "low", "Go module file exposes dependency versions"},
	{"/pom.xml", allLit("<artifactId>", "<project"), "low", "Maven pom.xml exposes dependency versions"},
	{"/build.gradle", re(`dependencies\s*\{`), "low", "Gradle build file exposes dependency versions"},

	// Backups
	{"/backup.sql", sqlDump, "high", "SQL dump exposed"},
	{"/dump.sql", sqlDump, "high", "SQL dump exposed"},
	{"/database.sql", sqlDump, "high", "SQL dump exposed"},
	{"/db.sql", sqlDump, "high", "SQL dump exposed"},
	{"/db.sqlite", sqliteDB, "high", "SQLite database exposed"},
	{"/db.sqlite3", sqliteDB, "high", "SQLite database exposed"},
	{"/database.sqlite", sqliteDB, "high", "SQLite database exposed"},

	// OS / editor crumbs
	{"/.DS_Store", prefix("\x00\x00\x00\x01Bud1"), "low", "macOS .DS_Store leaks directory listing"},
	{"/Thumbs.db", prefix("\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"), "low", "Windows Thumbs.db leaks directory listing"},

	// IaC
	{"/.terraform.tfstate", tfState, "high", "Terraform state file commonly contains cloud credentials and resource identifiers"},
	{"/terraform.tfstate", tfState, "high", "Terraform state file commonly contains cloud credentials and resource identifiers"},
	{"/docker-compose.yml", re(`(?m)^services:`), "low", "docker-compose exposes service topology and sometimes env vars"},
	{"/Dockerfile", re(`(?m)^FROM \S+`), "low", "Dockerfile exposes build steps"},

	// Server config
	{"/web.config", anyLit("<configuration"), "medium", "IIS web.config exposed"},
	{"/.htaccess", re(`(?mi)^[ \t]*(?:RewriteEngine|RewriteRule|RewriteCond|AuthType|AuthUserFile|Options|ErrorDocument|DirectoryIndex|<IfModule|<Files|Deny from|Require all)\b`), "medium", ".htaccess exposed"},
	{"/.htpasswd", re(`(?m)^[A-Za-z0-9_.@\-]+:(?:\$apr1\$|\$2[aby]\$|\$[156]\$|\{SHA\}|\{SSHA\}|[A-Za-z0-9./]{13}\s*$)`), "high", ".htpasswd exposes hashed credentials"},

	// Framework specific
	{"/wp-config.php.bak", wpConfig, "high", "WordPress config backup exposes DB credentials"},
	{"/wp-config.php~", wpConfig, "high", "WordPress config backup exposes DB credentials"},
	{"/wp-config.php.old", wpConfig, "high", "WordPress config backup exposes DB credentials"},
	{"/wp-config.php.save", wpConfig, "high", "WordPress config backup exposes DB credentials"},
	{"/config.php.bak", allLit("<?php", "pass"), "high", "PHP config backup"},
	{"/application.yml", re(`(?m)^spring:|^\s+datasource:`), "medium", "Spring application.yml may contain credentials"},
	{"/application.properties", re(`(?m)^spring\.[A-Za-z0-9_.\-]+\s*=`), "medium", "Spring application.properties may contain credentials"},

	// Monitoring and debug endpoints left open to the internet
	{"/metrics", allLit("# HELP ", "# TYPE "), "medium", "Prometheus metrics are publicly readable — they reveal internal routes, request volumes, versions and process details"},
	{"/actuator/env", jsonWith(anyLit(`"propertySources"`, `"activeProfiles"`)), "high", "Spring Boot actuator /env exposes configuration and may expose secrets"},
	{"/actuator/heapdump", prefix("JAVA PROFILE"), "high", "Spring Boot heap dump exposed — it can contain credentials and session tokens in memory"},
	{"/server-status", allLit("Apache Server Status"), "medium", "Apache mod_status is public — it shows live requests, client addresses and URLs"},
	{"/server-info", allLit("Apache Server Information"), "medium", "Apache mod_info is public — it shows server configuration"},
	{"/phpinfo.php", anyLit("<title>phpinfo()", "PHP Version "), "medium", "phpinfo() page exposes PHP configuration, paths and environment variables"},

	// Private keys
	{"/id_rsa", privateKey, "high", "SSH private key exposed"},
	{"/.ssh/id_rsa", privateKey, "high", "SSH private key exposed"},
	{"/server.key", privateKey, "high", "private key exposed"},
	{"/private.key", privateKey, "high", "private key exposed"},
	{"/privkey.pem", privateKey, "high", "private key exposed"},
}

// wildcardShapes are the path shapes used to learn how the target answers
// for files that cannot exist. One per family of probe (dotfile, nested
// dot-directory, plain file with extension) because servers and WAFs often
// route those differently.
var wildcardShapes = []string{"/.%s", "/.%s/config", "/%s.json", "/%s.sql", "/%s.php.bak"}

// ScanSensitive probes the curated list in one concurrent batch and returns
// only confirmed hits. A hit must (1) return 200/206, (2) not be an HTML
// page, (3) not have the same shape as what the target returns for random
// nonexistent files, and (4) satisfy the probe's own content matcher.
func ScanSensitive(ctx context.Context, eng *engine.Engine, baseURL string) []SecurityFinding {
	baseURL = strings.TrimRight(baseURL, "/")
	n := len(sensitiveTargets)
	reqs := make([]engine.Request, 0, n+len(wildcardShapes))
	for _, p := range sensitiveTargets {
		reqs = append(reqs, engine.Request{Method: "GET", URL: baseURL + p.Path})
	}
	wildPaths := make([]string, len(wildcardShapes))
	wildToks := make([]string, len(wildcardShapes))
	for i, shape := range wildcardShapes {
		wildToks[i] = analyze.RandomToken()
		wildPaths[i] = strings.Replace(shape, "%s", wildToks[i], 1)
		reqs = append(reqs, engine.Request{Method: "GET", URL: baseURL + wildPaths[i]})
	}
	resps := eng.DoAll(ctx, reqs)
	if len(resps) != len(reqs) {
		return nil
	}

	// Shapes the target serves with a success status for files that do not
	// exist. Empty for a well-behaved target that answers 404.
	var wildHashes []uint64
	for i, r := range resps[n:] {
		if r.Err != nil || (r.Status != 200 && r.Status != 206) {
			continue
		}
		if len(bytes.TrimSpace(r.Body)) == 0 {
			continue
		}
		wildHashes = append(wildHashes, analyze.SimHash(r.Body, wildPaths[i], wildToks[i]))
	}

	var out []SecurityFinding
	for i, resp := range resps[:n] {
		if resp.Err != nil || (resp.Status != 200 && resp.Status != 206) {
			continue
		}
		probe := sensitiveTargets[i]
		if len(bytes.TrimSpace(resp.Body)) == 0 {
			continue
		}
		if looksLikeHTML(resp.Body) {
			continue
		}
		if matchesWildcard(resp.Body, probe.Path, wildHashes) {
			continue
		}
		evidence, ok := probe.Match(resp.Body)
		if !ok {
			continue
		}
		out = append(out, SecurityFinding{
			Type:        "sensitive-file",
			Severity:    probe.Severity,
			URL:         baseURL + probe.Path,
			Description: probe.Why,
			Evidence:    evidence,
		})
	}
	return out
}

// matchesWildcard reports whether body has the same shape as one of the
// target's answers for random nonexistent files (path echoes redacted).
func matchesWildcard(body []byte, path string, wildHashes []uint64) bool {
	if len(wildHashes) == 0 {
		return false
	}
	h := analyze.SimHash(body, path, strings.TrimLeft(lastSeg(path), "."))
	for _, wh := range wildHashes {
		if analyze.SimilarShape(h, wh) {
			return true
		}
	}
	return false
}

// looksLikeHTML reports whether body is an HTML document. None of the files
// this phase looks for are HTML, while soft-404s, SPA shells, WAF block
// pages and login redirects all are.
func looksLikeHTML(body []byte) bool {
	head := body
	if len(head) > 1024 {
		head = head[:1024]
	}
	l := bytes.ToLower(bytes.TrimLeft(head, " \t\r\n\xef\xbb\xbf"))
	if bytes.HasPrefix(l, []byte("<!doctype html")) || bytes.HasPrefix(l, []byte("<html")) {
		return true
	}
	return bytes.Contains(l, []byte("<html")) || bytes.Contains(l, []byte("<head>")) || bytes.Contains(l, []byte("<body"))
}

var envKeyRe = regexp.MustCompile(`(?m)^[ \t]*(?:export[ \t]+)?([A-Z_][A-Z0-9_]+)[ \t]*=[ \t]*\S`)

// envMatcher matches KEY=value assignment lines. Evidence lists the variable
// NAMES only — never the values, which are the secrets.
func envMatcher(body []byte) (string, bool) {
	ms := envKeyRe.FindAllSubmatch(body, 6)
	if len(ms) == 0 {
		return "", false
	}
	names := make([]string, 0, 5)
	for i, m := range ms {
		if i == 5 {
			names = append(names, "...")
			break
		}
		names = append(names, string(m[1]))
	}
	return "variables: " + strings.Join(names, ", ") + " (values redacted)", true
}

// redacted wraps m, replacing its evidence with a fixed description for
// matches whose text is itself the secret.
func redacted(m matcher, note string) matcher {
	return func(body []byte) (string, bool) {
		if _, ok := m(body); !ok {
			return "", false
		}
		return note, true
	}
}

// excerpt returns the matched span as short, printable evidence. It never
// extends past the match: for most of these files whatever follows the
// marker is the secret, and reports get pasted into tickets and uploaded
// to CI.
func excerpt(body []byte, start, matchLen int) string {
	const maxEvidence = 80
	if matchLen > maxEvidence {
		matchLen = maxEvidence
	}
	end := start + matchLen
	if end > len(body) {
		end = len(body)
	}
	s := strings.Map(func(r rune) rune {
		switch {
		case r == '\n' || r == '\r' || r == '\t':
			return ' '
		case r < 32 || r == 0x7f || r == '\uFFFD':
			return -1
		}
		return r
	}, string(body[start:end]))
	return strings.TrimSpace(s)
}

// maxSensitiveDirs bounds how many directories besides the target root get
// the full sensitive-file probe set, so a scan that found hundreds of
// directories does not multiply into tens of thousands of extra requests.
const maxSensitiveDirs = 10

// ScanSensitiveAll runs ScanSensitive at the target root and in the
// directories discovery found (an exposed .env or .git is as likely under
// /app/ or /public/ as at the root). It returns the findings and how many
// directories were skipped because of the maxSensitiveDirs cap.
func ScanSensitiveAll(ctx context.Context, eng *engine.Engine, baseURL string, results []Result) ([]SecurityFinding, int) {
	return ScanSensitiveIn(ctx, eng, baseURL, results, true)
}

// ScanSensitiveIn is ScanSensitiveAll with the root optional, for callers
// that already probed the root earlier in the run.
func ScanSensitiveIn(ctx context.Context, eng *engine.Engine, baseURL string, results []Result, includeRoot bool) ([]SecurityFinding, int) {
	baseURL = strings.TrimRight(baseURL, "/")
	bases := []string{baseURL}
	seen := map[string]bool{baseURL: true}
	skipped := 0
	add := func(dir string) {
		dir = strings.TrimRight(dir, "/")
		if dir == "" || seen[dir] || !strings.HasPrefix(dir, baseURL+"/") {
			return
		}
		seen[dir] = true
		if len(bases) > maxSensitiveDirs {
			skipped++
			return
		}
		bases = append(bases, dir)
	}
	for _, r := range results {
		if r.Status < 200 || r.Status >= 400 {
			continue
		}
		u := r.URL
		if i := strings.IndexAny(u, "?#"); i >= 0 {
			u = u[:i]
		}
		if looksLikeDirectory(r) {
			add(u)
		}
	}

	if !includeRoot {
		bases = bases[1:]
	}
	var out []SecurityFinding
	dup := map[string]bool{}
	for _, b := range bases {
		if ctx.Err() != nil {
			break
		}
		for _, f := range ScanSensitive(ctx, eng, b) {
			if !dup[f.URL] {
				dup[f.URL] = true
				out = append(out, f)
			}
		}
	}
	return out, skipped
}
