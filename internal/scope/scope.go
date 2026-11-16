// Package scope decides which URLs a scan is allowed to touch. It is
// enforced inside the HTTP engine — the single place every request passes
// through — so no phase (fuzzing, crawling, security probes, API probing)
// can step outside what the operator was authorized to test.
//
// A scope file has one rule per line; blank lines and #-comments are
// ignored. A leading "!" makes a rule an exclusion. Rule forms:
//
//	example.com                 a host, any port, any path
//	*.example.com               any subdomain of example.com
//	example.com:8443            a host on one port
//	https://example.com/app/    scheme, host and a path prefix
//	/admin                      a path prefix on any allowed host
//	/api/*/delete               a path glob ("*" matches any run of characters)
//
// A URL is in scope when no exclusion matches it and, if the file contains
// any non-exclusion rule, at least one of them does. Exclusions always win.
package scope

import (
	"bufio"
	"fmt"
	"io"
	"net/url"
	"strings"
)

type rule struct {
	scheme string // "" = any
	host   string // "" = any; "*.x" = any subdomain of x
	port   string // "" = any
	path   string // "" = any; prefix, or glob when it contains "*"
	raw    string
}

// Scope is a parsed set of rules.
type Scope struct {
	allow []rule
	deny  []rule
}

// Parse reads a scope file.
func Parse(r io.Reader) (*Scope, error) {
	s := &Scope{}
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	for n := 1; sc.Scan(); n++ {
		line := strings.TrimSpace(strings.TrimPrefix(sc.Text(), "\xef\xbb\xbf"))
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		deny := strings.HasPrefix(line, "!")
		if deny {
			line = strings.TrimSpace(line[1:])
		}
		ru, err := parseRule(line)
		if err != nil {
			return nil, fmt.Errorf("line %d: %v", n, err)
		}
		if deny {
			s.deny = append(s.deny, ru)
		} else {
			s.allow = append(s.allow, ru)
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if len(s.allow) == 0 && len(s.deny) == 0 {
		return nil, fmt.Errorf("no rules")
	}
	return s, nil
}

func parseRule(line string) (rule, error) {
	ru := rule{raw: line}
	if line == "" {
		return ru, fmt.Errorf("empty rule")
	}
	if strings.ContainsAny(line, " \t") {
		return ru, fmt.Errorf("rule %q contains whitespace", line)
	}
	if strings.HasPrefix(line, "/") || strings.HasPrefix(line, "*/") {
		ru.path = line
		return ru, nil
	}
	rest := line
	if i := strings.Index(rest, "://"); i >= 0 {
		ru.scheme = strings.ToLower(rest[:i])
		if ru.scheme != "http" && ru.scheme != "https" {
			return ru, fmt.Errorf("rule %q: scheme must be http or https", line)
		}
		rest = rest[i+3:]
	}
	if i := strings.Index(rest, "/"); i >= 0 {
		ru.path = rest[i:]
		rest = rest[:i]
	}
	hostport := rest
	// Split a trailing :port, leaving IPv6 literals ("[::1]:8080") intact.
	if i := strings.LastIndex(hostport, ":"); i >= 0 && !strings.HasSuffix(hostport, "]") {
		port := hostport[i+1:]
		if port == "" || strings.Trim(port, "0123456789") != "" {
			return ru, fmt.Errorf("rule %q: bad port", line)
		}
		ru.port = port
		hostport = hostport[:i]
	}
	ru.host = strings.ToLower(strings.Trim(hostport, "[]"))
	if ru.host == "" {
		return ru, fmt.Errorf("rule %q has no host", line)
	}
	if strings.Contains(strings.TrimPrefix(ru.host, "*."), "*") {
		return ru, fmt.Errorf("rule %q: a host wildcard is only allowed as a leading \"*.\"", line)
	}
	if ru.path == "/" {
		ru.path = ""
	}
	return ru, nil
}

// Allows reports whether rawURL is in scope. A URL that cannot be parsed is
// never in scope.
func (s *Scope) Allows(rawURL string) bool {
	if s == nil {
		return true
	}
	u, err := url.Parse(rawURL)
	if err != nil || u.Hostname() == "" {
		return false
	}
	for _, ru := range s.deny {
		if ru.matches(u) {
			return false
		}
	}
	if len(s.allow) == 0 {
		return true
	}
	for _, ru := range s.allow {
		if ru.matches(u) {
			return true
		}
	}
	return false
}

// Blocker returns the first exclusion rule matching rawURL, or "" — used to
// explain why a request was refused.
func (s *Scope) Blocker(rawURL string) string {
	if s == nil {
		return ""
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		return "unparseable URL"
	}
	for _, ru := range s.deny {
		if ru.matches(u) {
			return "!" + ru.raw
		}
	}
	return ""
}

func (ru rule) matches(u *url.URL) bool {
	if ru.scheme != "" && !strings.EqualFold(u.Scheme, ru.scheme) {
		return false
	}
	if ru.host != "" {
		h := strings.ToLower(u.Hostname())
		if strings.HasPrefix(ru.host, "*.") {
			if !strings.HasSuffix(h, ru.host[1:]) {
				return false
			}
		} else if h != ru.host {
			return false
		}
	}
	if ru.port != "" {
		p := u.Port()
		if p == "" {
			if strings.EqualFold(u.Scheme, "https") {
				p = "443"
			} else {
				p = "80"
			}
		}
		if p != ru.port {
			return false
		}
	}
	if ru.path == "" {
		return true
	}
	// Match against the decoded path so "%2e%2e" or "%61dmin" cannot be
	// used to slip past a path rule.
	path := u.Path
	if path == "" {
		path = "/"
	}
	if strings.Contains(ru.path, "*") {
		return glob(ru.path, path)
	}
	prefix := strings.TrimRight(ru.path, "/")
	return path == prefix || strings.HasPrefix(path, prefix+"/")
}

// glob reports whether s matches pattern, where "*" matches any run of
// characters (including "/"). Iterative, linear in practice, no regexp.
func glob(pattern, s string) bool {
	pi, si, star, mark := 0, 0, -1, 0
	for si < len(s) {
		switch {
		case pi < len(pattern) && pattern[pi] == '*':
			star, mark = pi, si
			pi++
		case pi < len(pattern) && pattern[pi] == s[si]:
			pi++
			si++
		case star >= 0:
			pi = star + 1
			mark++
			si = mark
		default:
			return false
		}
	}
	for pi < len(pattern) && pattern[pi] == '*' {
		pi++
	}
	return pi == len(pattern)
}
