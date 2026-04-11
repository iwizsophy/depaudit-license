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

func TestExcludePolicySampleMatchesSchema(t *testing.T) {
	t.Parallel()

	schema := mustCompileSchema(t, "exclude-policy.schema.json")
	doc := mustReadJSON(t, "exclude-policy.sample.json")

	if err := schema.Validate(doc); err != nil {
		t.Fatalf("validate exclude-policy.sample.json: %v", err)
	}
}

func TestExcludePolicySchemaRejectsBrokenSelector(t *testing.T) {
	t.Parallel()

	schema := mustCompileSchema(t, "exclude-policy.schema.json")
	doc := mustReadJSON(t, "exclude-policy.sample.json")

	root, ok := doc.(map[string]any)
	if !ok {
		t.Fatalf("unexpected root type %T", doc)
	}

	shallowRules, ok := root["shallowExcludes"].([]any)
	if !ok || len(shallowRules) == 0 {
		t.Fatalf("unexpected shallowExcludes payload")
	}

	first, ok := shallowRules[0].(map[string]any)
	if !ok {
		t.Fatalf("unexpected shallow rule type %T", shallowRules[0])
	}

	delete(first, "match")

	if err := schema.Validate(doc); err == nil {
		t.Fatalf("expected schema validation to fail")
	}
}

func TestLicenseOverridesSampleMatchesSchema(t *testing.T) {
	t.Parallel()

	schema := mustCompileSchema(t, "license-overrides.schema.json")
	doc := mustReadJSON(t, "license-overrides.sample.json")

	if err := schema.Validate(doc); err != nil {
		t.Fatalf("validate license-overrides.sample.json: %v", err)
	}
}

func TestLicenseOverridesSchemaRejectsMissingLicenseKey(t *testing.T) {
	t.Parallel()

	schema := mustCompileSchema(t, "license-overrides.schema.json")
	doc := mustReadJSON(t, "license-overrides.sample.json")

	root, ok := doc.(map[string]any)
	if !ok {
		t.Fatalf("unexpected root type %T", doc)
	}

	rules, ok := root["licenseOverrides"].([]any)
	if !ok || len(rules) == 0 {
		t.Fatalf("unexpected licenseOverrides payload")
	}

	first, ok := rules[0].(map[string]any)
	if !ok {
		t.Fatalf("unexpected license override type %T", rules[0])
	}

	delete(first, "licenseKey")

	if err := schema.Validate(doc); err == nil {
		t.Fatalf("expected schema validation to fail")
	}
}

func TestRuntimeConfigSampleMatchesSchema(t *testing.T) {
	t.Parallel()

	schema := mustCompileSchema(t, "runtime-config.schema.json")
	doc := mustReadJSON(t, "runtime-config.sample.json")

	if err := schema.Validate(doc); err != nil {
		t.Fatalf("validate runtime-config.sample.json: %v", err)
	}
}

func TestRuntimeConfigSchemaRejectsInvalidVersion(t *testing.T) {
	t.Parallel()

	schema := mustCompileSchema(t, "runtime-config.schema.json")
	doc := mustReadJSON(t, "runtime-config.sample.json")

	root, ok := doc.(map[string]any)
	if !ok {
		t.Fatalf("unexpected root type %T", doc)
	}

	root["version"] = "v2"

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
