package scope

import (
	"strings"
	"testing"
)

func mustParse(t *testing.T, text string) *Scope {
	t.Helper()
	s, err := Parse(strings.NewReader(text))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	return s
}

func TestAllows(t *testing.T) {
	s := mustParse(t, `
# engagement scope
app.example.com
*.dev.example.com
api.example.com:8443
https://shop.example.com/store/
[::1]:9000
!/admin
!*/delete*
!app.example.com/internal
`)
	cases := map[string]bool{
		"http://app.example.com/":                  true,
		"https://APP.example.com/a/b?x=1":          true,
		"http://x.dev.example.com/":                true,
		"http://dev.example.com/":                  false, // "*.": subdomains only
		"http://evildev.example.com/":              false,
		"https://api.example.com:8443/v1":          true,
		"https://api.example.com/v1":               false, // wrong port
		"https://shop.example.com/store/item":      true,
		"https://shop.example.com/store":           true,
		"https://shop.example.com/storefront":      false, // prefix is segment-bounded
		"http://shop.example.com/store/item":       false, // wrong scheme
		"http://[::1]:9000/x":                      true,
		"http://other.example.org/":                false,
		"http://app.example.com/admin":             false,
		"http://app.example.com/admin/users":       false,
		"http://app.example.com/administrator":     true,  // not the /admin prefix
		"http://app.example.com/%61dmin/users":     false, // decoded before matching
		"http://app.example.com/api/v1/delete-all": false,
		"http://app.example.com/internal/x":        false,
		"http://x.dev.example.com/internal/x":      true, // exclusion is host-specific
		"http://app.example.com/a/../admin":        true, // literal path; the server decides what it means
		"::not a url::":                            false,
		"":                                         false,
	}
	for u, want := range cases {
		if got := s.Allows(u); got != want {
			t.Errorf("Allows(%q) = %v, want %v", u, got, want)
		}
	}
}

func TestDenyOnlyFileAllowsEverythingElse(t *testing.T) {
	s := mustParse(t, "!/logout\n!*/*.png\n")
	if !s.Allows("http://any.host/page") || s.Allows("http://any.host/logout") || s.Allows("http://any.host/img/a.png") {
		t.Error("deny-only scope misbehaves")
	}
	if got := s.Blocker("http://any.host/logout"); got != "!/logout" {
		t.Errorf("Blocker = %q", got)
	}
}

func TestNilScopeAllowsAll(t *testing.T) {
	var s *Scope
	if !s.Allows("http://x/") || s.Blocker("http://x/") != "" {
		t.Error("nil scope must allow everything")
	}
}

func TestParseErrors(t *testing.T) {
	for _, bad := range []string{"", "# only comments\n", "ftp://x/", "host with space", "a*b.example.com", "example.com:port", "!", "://nohost"} {
		if _, err := Parse(strings.NewReader(bad)); err == nil {
			t.Errorf("Parse(%q) accepted", bad)
		}
	}
	if _, err := Parse(strings.NewReader("ok.example\nftp://bad/\n")); err == nil || !strings.Contains(err.Error(), "line 2") {
		t.Errorf("error should name the line: %v", err)
	}
}

func TestGlob(t *testing.T) {
	cases := []struct {
		p, s string
		want bool
	}{
		{"*", "", true}, {"*", "/a/b", true}, {"/a/*", "/a/", true}, {"/a/*", "/a", false},
		{"*/delete*", "/x/delete", true}, {"*/delete*", "/delete", true}, {"*/delete*", "/x/remove", false},
		{"/a*c", "/abc", true}, {"/a*c", "/ac", true}, {"/a*c", "/abd", false},
		{"/a**b", "/axxb", true}, {"*.png", "/i/a.png", true}, {"*.png", "/i/a.png.bak", false},
	}
	for _, c := range cases {
		if got := glob(c.p, c.s); got != c.want {
			t.Errorf("glob(%q, %q) = %v, want %v", c.p, c.s, got, c.want)
		}
	}
}

func FuzzScope(f *testing.F) {
	f.Add("example.com\n!/admin\n", "http://example.com/admin")
	f.Add("*.x.y:80\n!*a*b*c*\n", "http://q.x.y/aXbXc")
	f.Add("!\n", "")
	f.Fuzz(func(t *testing.T, rules, u string) {
		s, err := Parse(strings.NewReader(rules))
		if err != nil {
			return
		}
		a := s.Allows(u)
		if a && s.Blocker(u) != "" {
			t.Fatalf("Allows(%q) is true but Blocker names %q", u, s.Blocker(u))
		}
	})
}
