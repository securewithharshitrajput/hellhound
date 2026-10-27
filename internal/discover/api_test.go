package discover

import "testing"

func TestParseOpenAPI(t *testing.T) {
	spec := []byte(`{
		"openapi": "3.0.0",
		"paths": {
			"/users": {
				"get": {"summary": "list users"},
				"post": {"summary": "create user"}
			},
			"/users/{id}": {
				"get": {"summary": "get user"},
				"delete": {"summary": "delete user"},
				"parameters": [{"name": "id", "in": "path"}]
			}
		}
	}`)
	routes, err := ParseOpenAPI(spec)
	if err != nil {
		t.Fatalf("ParseOpenAPI: %v", err)
	}
	if len(routes) != 4 {
		t.Fatalf("expected 4 routes, got %d: %+v", len(routes), routes)
	}
	// Ensure the non-verb "parameters" key under /users/{id} wasn't treated
	// as a method.
	for _, r := range routes {
		if r.Method == "PARAMETERS" {
			t.Errorf("parameters key leaked in as a method: %+v", r)
		}
	}
}

func TestParseOpenAPIRejectsNonSpec(t *testing.T) {
	if _, err := ParseOpenAPI([]byte(`{"hello": "world"}`)); err == nil {
		t.Error("expected error for a JSON doc with no paths object")
	}
}

func TestParseGraphQLIntrospection(t *testing.T) {
	body := []byte(`{
		"data": {
			"__schema": {
				"queryType": {"name": "Query"},
				"mutationType": {"name": "Mutation"},
				"types": [
					{"name": "Query", "kind": "OBJECT", "fields": [
						{"name": "user"}, {"name": "listUsers"}
					]},
					{"name": "Mutation", "kind": "OBJECT", "fields": [
						{"name": "deleteUser"}
					]},
					{"name": "User", "kind": "OBJECT", "fields": [
						{"name": "id"}, {"name": "email"}
					]}
				]
			}
		}
	}`)
	fields, err := ParseGraphQLIntrospection(body)
	if err != nil {
		t.Fatalf("ParseGraphQLIntrospection: %v", err)
	}
	if len(fields) != 3 {
		t.Fatalf("expected 3 root fields (2 Query + 1 Mutation), got %d: %+v", len(fields), fields)
	}
	for _, f := range fields {
		if f.ParentType == "User" {
			t.Errorf("non-root type field leaked into results: %+v", f)
		}
	}
}

func TestParseGraphQLIntrospectionDisabled(t *testing.T) {
	// A typical "introspection disabled" GraphQL error response.
	body := []byte(`{"errors":[{"message":"GraphQL introspection is not allowed"}]}`)
	if _, err := ParseGraphQLIntrospection(body); err == nil {
		t.Error("expected error when introspection is disabled")
	}
}
