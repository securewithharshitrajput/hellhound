// testserver is a throwaway local target used only to validate scout's
// behavior end-to-end: it has a dynamic "not found" page (embeds a
// timestamp + request id, exactly the case that defeats naive diffing),
// a handful of real hidden endpoints at varying depths, a Swagger spec,
// and a GraphQL endpoint with introspection enabled.
package main

import (
	"fmt"
	"log"
	"math/rand"
	"net/http"
	"regexp"
	"strconv"
	"time"
)

// blogPostRe requires an exact "/blog/post-N" match — no trailing
// extension, no extra path segment — so sloppy prefix matching doesn't
// make the test server itself return "real" content for junk fuzz
// candidates like "/blog/post-1.zip" or "/blog/post-10/admin".
var blogPostRe = regexp.MustCompile(`^/blog/post-(\d+)$`)

var realPaths = map[string]string{
	"/admin":         "<html><body><h1>Admin Panel</h1><p>Welcome, administrator.</p></body></html>",
	"/admin/users":   "<html><body><h1>User Management</h1><table><tr><td>alice</td></tr></table></body></html>",
	"/backup.zip":    "PK\x03\x04-fake-zip-bytes-for-testing-",
	"/api/v1/users":  `[{"id":1,"name":"alice"},{"id":2,"name":"bob"}]`,
	"/.git/config":   "[core]\n\trepositoryformatversion = 0\n",
	"/server-status": "<html><body>Apache Server Status</body></html>",
	"/swagger.json":  `{"openapi":"3.0.0","paths":{"/users":{"get":{},"post":{}},"/users/{id}":{"get":{},"delete":{}},"/orders":{"get":{}}}}`,

	// Real homepage, robots.txt and a same-origin JS bundle, plus the
	// endpoints they point at — these exist specifically so the test can
	// prove scout's wordlist MINING actually leads to real findings, not
	// just that it extracts strings in isolation.
	"/":                            `<html><head><title>Test Site</title><script src="/static/app.js"></script></head><body>Welcome</body></html>`,
	"/robots.txt":                  "User-agent: *\nDisallow: /secret-reports\n",
	"/static/app.js":               `fetch("/api/internal/billing-export").then(r=>r.json());`,
	"/secret-reports":              "<html><body><h1>Secret Reports</h1><p>Only in robots.txt, never linked.</p></body></html>",
	"/api":                         "<html><body>API index</body></html>",
	"/api/internal":                "<html><body>Internal API index</body></html>",
	"/api/internal/billing-export": "<html><body><h1>Billing Export</h1><p>Only reachable via the path mined out of app.js.</p></body></html>",
}

// 200 identically-templated "blog post" pages — tests clustering.
func blogPost(n int) string {
	return fmt.Sprintf(`<html><head><title>Post %d</title></head><body>
	<nav>Home | About | Archive</nav>
	<article><h1>Post number %d</h1><p>Posted recently by admin.</p>
	<div>This is filler content shared by every post on this test blog,
	demonstrating that scout clusters near-identical templated pages
	instead of reporting each one as a separate finding.</div></article>
	</body></html>`, n, n)
}

const graphqlSchema = `{"data":{"__schema":{"queryType":{"name":"Query"},"mutationType":{"name":"Mutation"},"types":[
	{"name":"Query","kind":"OBJECT","fields":[{"name":"user"},{"name":"listOrders"}]},
	{"name":"Mutation","kind":"OBJECT","fields":[{"name":"deleteUser"}]}
]}}}`

func main() {
	mux := http.NewServeMux()

	mux.HandleFunc("/graphql", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(graphqlSchema))
	})

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		// Virtual-host fixture: a real internal vhost not advertised in
		// DNS, reachable only by sending this exact Host header — proves
		// scout's -vhosts mode finds it among calibration noise.
		if r.Host == "internal-admin.test" {
			w.Write([]byte("<html><body><h1>Internal Admin Console (vhost)</h1><p>Only reachable via Host: internal-admin.test</p></body></html>"))
			return
		}

		path := r.URL.Path

		if body, ok := realPaths[path]; ok {
			w.Write([]byte(body))
			return
		}
		if m := blogPostRe.FindStringSubmatch(path); m != nil {
			n, _ := strconv.Atoi(m[1])
			if n >= 1 && n <= 50 {
				w.Write([]byte(blogPost(n)))
				return
			}
		}

		// Dynamic soft-404: embeds timestamp + random request id so a naive
		// exact-body-match tool sees a "different" page every single time.
		w.WriteHeader(http.StatusOK) // soft 404: status 200!
		fmt.Fprintf(w, `<html><body><h1>Oops!</h1><p>We could not find the page you were looking for: %s</p>
		<p>Request ID: %08x</p><p>Server time: %s</p>
		<p>If you believe this is an error, please contact support.</p></body></html>`,
			path, rand.Uint32(), time.Now().Format(time.RFC3339))
	})

	addr := "127.0.0.1:8899"
	log.Printf("testserver listening on %s", addr)
	log.Fatal(http.ListenAndServe(addr, mux))
}
