package wordlist

import (
	"reflect"
	"testing"
)

func TestFromJSExtractsRoutes(t *testing.T) {
	src := []byte(`
		const API = "/api/v1/users";
		fetch('/api/internal/admin-tools').then(r => r.json());
		const img = "/static/logo.png"; // should be filtered
		router.get("/health", handler);
	`)
	got := FromJS(src)
	want := map[string]bool{"/api/v1/users": true, "/api/internal/admin-tools": true, "/health": true}
	if len(got) != len(want) {
		t.Fatalf("got %d routes, want %d: %v", len(got), len(want), got)
	}
	for _, g := range got {
		if !want[g] {
			t.Errorf("unexpected route extracted: %s", g)
		}
	}
}

func TestFromRobots(t *testing.T) {
	body := []byte("User-agent: *\nDisallow: /admin\nDisallow: /internal/\nAllow: /public\n")
	got := FromRobots(body)
	want := []string{"/admin", "/internal/", "/public"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestPathToWords(t *testing.T) {
	got := PathToWords([]string{"/api/v1/internal-tools", "/api/health"})
	want := []string{"api", "health", "internal-tools", "v1"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestFingerprint(t *testing.T) {
	headers := map[string][]string{"X-Powered-By": {"Express"}}
	hits := Fingerprint(headers, []byte("<html></html>"))
	if len(hits) != 1 || hits[0] != "express" {
		t.Errorf("expected [express], got %v", hits)
	}
}

func TestMergeDeduplicates(t *testing.T) {
	got := Merge([]string{"admin", "api"}, []string{"api", "health"})
	want := []string{"admin", "api", "health"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}
