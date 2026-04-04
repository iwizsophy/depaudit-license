package configs

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

func TestLicenseCatalogMatchesSchema(t *testing.T) {
	t.Parallel()

	schema := mustCompileSchema(t, "licenses.schema.json")
	doc := mustReadJSON(t, "licenses.json")

	if err := schema.Validate(doc); err != nil {
		t.Fatalf("validate licenses.json: %v", err)
	}
}

func TestLicenseCatalogSchemaRejectsBrokenDefinition(t *testing.T) {
	t.Parallel()

	schema := mustCompileSchema(t, "licenses.schema.json")
	doc := mustReadJSON(t, "licenses.json")

	root, ok := doc.(map[string]any)
	if !ok {
		t.Fatalf("unexpected root type %T", doc)
	}

	licenses, ok := root["licenses"].([]any)
	if !ok || len(licenses) == 0 {
		t.Fatalf("unexpected licenses payload")
	}

	first, ok := licenses[0].(map[string]any)
	if !ok {
		t.Fatalf("unexpected license item type %T", licenses[0])
	}

	delete(first, "family")

	if err := schema.Validate(doc); err == nil {
		t.Fatalf("expected schema validation to fail")
	}
}

func TestLicenseTextBundleMatchesSchema(t *testing.T) {
	t.Parallel()

	schema := mustCompileSchema(t, "license-texts.schema.json")
	doc := mustReadJSON(t, "license-texts.ja.json")

	if err := schema.Validate(doc); err != nil {
		t.Fatalf("validate license-texts.ja.json: %v", err)
	}
}

func TestLicenseTextBundleSchemaRejectsBrokenDefinition(t *testing.T) {
	t.Parallel()

	schema := mustCompileSchema(t, "license-texts.schema.json")
	doc := mustReadJSON(t, "license-texts.ja.json")

	root, ok := doc.(map[string]any)
	if !ok {
		t.Fatalf("unexpected root type %T", doc)
	}

	licenses, ok := root["licenses"].([]any)
	if !ok || len(licenses) == 0 {
		t.Fatalf("unexpected licenses payload")
	}

	first, ok := licenses[0].(map[string]any)
	if !ok {
		t.Fatalf("unexpected license item type %T", licenses[0])
	}

	delete(first, "description")

	if err := schema.Validate(doc); err == nil {
		t.Fatalf("expected schema validation to fail")
	}
}

func mustCompileSchema(t *testing.T, name string) *jsonschema.Schema {
	t.Helper()

	schemaPath := filepath.Join(name)
	compiler := jsonschema.NewCompiler()
	schema, err := compiler.Compile(schemaPath)
	if err != nil {
		t.Fatalf("compile schema: %v", err)
	}
	return schema
}

func mustReadJSON(t *testing.T, name string) any {
	t.Helper()

	payload, err := os.ReadFile(filepath.Join(name))
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}

	var doc any
	if err := json.Unmarshal(payload, &doc); err != nil {
		t.Fatalf("parse %s: %v", name, err)
	}
	return doc
}
