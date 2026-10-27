package discover

import "testing"

// FuzzParseOpenAPI feeds arbitrary bytes — not just malformed JSON, but
// adversarially-shaped JSON — to the spec parser. A real target's
// "swagger.json" is attacker-reachable-in-reverse: the TARGET controls
// what it sends back, so the parser must never panic no matter how the
// document is shaped.
func FuzzParseOpenAPI(f *testing.F) {
	seeds := []string{
		`{}`,
		`{"paths": {}}`,
		`{"paths": null}`,
		`{"paths": {"/x": null}}`,
		`{"paths": {"/x": {"get": null}}}`,
		`{"paths": {"/x": "not an object"}}`,
		`{"paths": 123}`,
		`{"paths": [1,2,3]}`,
		`not json at all`,
		``,
		`{"paths": {"/x": {"get": {}, "post": {}, "parameters": [], "$ref": "#/x"}}}`,
		`{"paths": {"` + string([]byte{0xff, 0xfe}) + `": {}}}`,
	}
	for _, s := range seeds {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, body []byte) {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("ParseOpenAPI panicked on input %q: %v", body, r)
			}
		}()
		_, _ = ParseOpenAPI(body)
	})
}

// FuzzParseGraphQLIntrospection does the same for the GraphQL schema
// parser, which walks several levels of nested, caller-shaped JSON.
func FuzzParseGraphQLIntrospection(f *testing.F) {
	seeds := []string{
		`{}`,
		`{"data": {}}`,
		`{"data": {"__schema": {}}}`,
		`{"data": {"__schema": {"queryType": null}}}`,
		`{"data": {"__schema": {"queryType": {"name": "Query"}, "types": null}}}`,
		`{"data": {"__schema": {"queryType": {"name": "Query"}, "types": [null]}}}`,
		`{"data": {"__schema": {"queryType": {"name": "Query"}, "types": [{"fields": null}]}}}`,
		`{"errors": [{"message": "introspection disabled"}]}`,
		`not json`,
		``,
	}
	for _, s := range seeds {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, body []byte) {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("ParseGraphQLIntrospection panicked on input %q: %v", body, r)
			}
		}()
		_, _ = ParseGraphQLIntrospection(body)
	})
}
