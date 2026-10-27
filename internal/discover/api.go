// API discovery: when a target exposes an OpenAPI/Swagger spec or a
// GraphQL endpoint with introspection enabled, we get the REAL route map
// instead of guessing it — a whole class of endpoints ffuf/katana can only
// stumble into by brute force, hellhound reads directly from the target's own
// documentation of itself.
package discover

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// OpenAPIRoute is one operation extracted from a parsed spec.
type OpenAPIRoute struct {
	Method string
	Path   string
	Params []string
}

// openAPIDoc is a minimal structural subset of OpenAPI 2/3 — enough to walk
// `paths` and method verbs without needing a full schema-validating parser.
type openAPIDoc struct {
	Paths map[string]map[string]json.RawMessage `json:"paths"`
}

var httpVerbs = map[string]bool{
	"get": true, "post": true, "put": true, "patch": true,
	"delete": true, "options": true, "head": true,
}

// ParseOpenAPI extracts every (method, path) pair from a Swagger 2.0 or
// OpenAPI 3.x JSON document. Intentionally tolerant of version differences
// since both put operations under paths[path][verb].
func ParseOpenAPI(body []byte) ([]OpenAPIRoute, error) {
	var doc openAPIDoc
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, fmt.Errorf("not valid JSON / no paths object: %w", err)
	}
	if len(doc.Paths) == 0 {
		return nil, fmt.Errorf("no paths found — not an OpenAPI/Swagger document")
	}
	var routes []OpenAPIRoute
	for path, methods := range doc.Paths {
		for verb := range methods {
			lv := strings.ToLower(verb)
			if !httpVerbs[lv] {
				continue // skip non-verb keys like "parameters", "$ref", "summary"
			}
			routes = append(routes, OpenAPIRoute{Method: strings.ToUpper(lv), Path: path})
		}
	}
	sort.Slice(routes, func(i, j int) bool {
		if routes[i].Path != routes[j].Path {
			return routes[i].Path < routes[j].Path
		}
		return routes[i].Method < routes[j].Method
	})
	return routes, nil
}

// CommonSpecPaths are the conventional locations to probe for an API spec
// before falling back to brute force.
var CommonSpecPaths = []string{
	"/swagger.json", "/swagger/v1/swagger.json", "/openapi.json",
	"/v2/api-docs", "/v3/api-docs", "/api-docs", "/api/swagger.json",
	"/.well-known/openapi.json", "/docs/swagger.json",
}

// GraphQLIntrospectionQuery is the standard introspection query used to
// enumerate a schema's queries/mutations when introspection is left
// enabled — a common misconfiguration that hands over the entire API
// surface, including fields with no other discoverable path.
const GraphQLIntrospectionQuery = `{"query":"query IntrospectionQuery { __schema { queryType { name } mutationType { name } types { name kind fields { name args { name type { name kind } } } } } }"}`

// CommonGraphQLPaths are conventional GraphQL endpoint locations to probe.
var CommonGraphQLPaths = []string{"/graphql", "/api/graphql", "/graphql/console", "/v1/graphql", "/query"}

// graphQLSchemaResp is the minimal shape needed to pull field names out of
// an introspection response.
type graphQLSchemaResp struct {
	Data struct {
		Schema struct {
			QueryType    *struct{ Name string } `json:"queryType"`
			MutationType *struct{ Name string } `json:"mutationType"`
			Types        []struct {
				Name   string `json:"name"`
				Kind   string `json:"kind"`
				Fields []struct {
					Name string `json:"name"`
				} `json:"fields"`
			} `json:"types"`
		} `json:"__schema"`
	} `json:"data"`
}

// GraphQLField is one discovered query/mutation field, with the parent type
// it belongs to (usually "Query" or "Mutation").
type GraphQLField struct {
	ParentType string
	Field      string
}

// ParseGraphQLIntrospection extracts the query/mutation field names from an
// introspection response body. Returns an error if introspection is
// disabled (the response won't have the expected __schema shape) rather
// than silently returning nothing, so callers can distinguish
// "not GraphQL"/"introspection disabled" from "schema is just empty".
func ParseGraphQLIntrospection(body []byte) ([]GraphQLField, error) {
	var r graphQLSchemaResp
	if err := json.Unmarshal(body, &r); err != nil {
		return nil, fmt.Errorf("invalid JSON: %w", err)
	}
	if r.Data.Schema.QueryType == nil {
		return nil, fmt.Errorf("no __schema.queryType in response — introspection likely disabled")
	}
	rootNames := map[string]bool{r.Data.Schema.QueryType.Name: true}
	if r.Data.Schema.MutationType != nil {
		rootNames[r.Data.Schema.MutationType.Name] = true
	}
	var fields []GraphQLField
	for _, t := range r.Data.Schema.Types {
		if !rootNames[t.Name] {
			continue
		}
		for _, f := range t.Fields {
			fields = append(fields, GraphQLField{ParentType: t.Name, Field: f.Name})
		}
	}
	sort.Slice(fields, func(i, j int) bool {
		if fields[i].ParentType != fields[j].ParentType {
			return fields[i].ParentType < fields[j].ParentType
		}
		return fields[i].Field < fields[j].Field
	})
	return fields, nil
}
