package policy

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParseAcceptsValidPolicy(t *testing.T) {
	t.Parallel()

	doc, err := Parse([]byte(`{
  "version": "v1alpha1",
  "shallowExcludes": [
    {
      "id": "omit-dev-tooling",
      "reason": "hide analyzer packages from final output",
      "match": {
        "ecosystems": ["nuget"],
        "names": ["xunit.runner.visualstudio"]
      }
    }
  ],
  "subgraphExcludes": [
    {
      "id": "omit-build-subgraph",
      "onUnsupported": "warn",
      "match": {
        "projects": ["src/server/App.csproj"],
        "dependencyTypes": ["devDependency"],
        "hasRuntimeAssets": false
      }
    }
  ]
}`))
	if err != nil {
		t.Fatalf("parse policy: %v", err)
	}

	if len(doc.ShallowExcludes) != 1 || len(doc.SubgraphExcludes) != 1 {
		t.Fatalf("unexpected parsed rule counts: %#v", doc)
	}
}

func TestParseRejectsUnsupportedVersion(t *testing.T) {
	t.Parallel()

	_, err := Parse([]byte(`{"version":"v2","shallowExcludes":[{"match":{"names":["pkg"]}}]}`))
	if err == nil {
		t.Fatal("expected version validation error")
	}
}

func TestParseRejectsEmptySelector(t *testing.T) {
	t.Parallel()

	_, err := Parse([]byte(`{"version":"v1alpha1","shallowExcludes":[{"match":{}}]}`))
	if err == nil {
		t.Fatal("expected selector validation error")
	}
}

func TestParseRejectsInvalidOnUnsupported(t *testing.T) {
	t.Parallel()

	_, err := Parse([]byte(`{"version":"v1alpha1","subgraphExcludes":[{"onUnsupported":"later","match":{"names":["pkg"]}}]}`))
	if err == nil {
		t.Fatal("expected onUnsupported validation error")
	}
}

func TestParseRejectsDuplicateRuleIDs(t *testing.T) {
	t.Parallel()

	_, err := Parse([]byte(`{
  "version":"v1alpha1",
  "shallowExcludes":[{"id":"dup","match":{"names":["a"]}}],
  "subgraphExcludes":[{"id":"dup","match":{"names":["b"]}}]
}`))
	if err == nil {
		t.Fatal("expected duplicate rule id validation error")
	}
}

func TestParseRejectsOnUnsupportedOnShallowRule(t *testing.T) {
	t.Parallel()

	_, err := Parse([]byte(`{
  "version":"v1alpha1",
  "shallowExcludes":[{"onUnsupported":"warn","match":{"names":["pkg"]}}]
}`))
	if err == nil {
		t.Fatal("expected shallow onUnsupported validation error")
	}
}

func TestParseRejectsInvalidNameGlob(t *testing.T) {
	t.Parallel()

	_, err := Parse([]byte(`{
  "version":"v1alpha1",
  "shallowExcludes":[{"match":{"nameGlobs":["["]}}]
}`))
	if err == nil {
		t.Fatal("expected invalid name glob validation error")
	}
}

func TestValidateSelectorNormalizesAndRejectsEmptySelector(t *testing.T) {
	t.Parallel()

	selector, err := ValidateSelector(Selector{
		Ecosystems: []string{" npm ", ""},
		Names:      []string{" react "},
	})
	if err != nil {
		t.Fatalf("validate selector: %v", err)
	}
	if len(selector.Ecosystems) != 1 || selector.Ecosystems[0] != "npm" || selector.Names[0] != "react" {
		t.Fatalf("normalized selector = %#v", selector)
	}

	if _, err := ValidateSelector(Selector{}); err == nil {
		t.Fatal("expected empty selector validation error")
	}
}

func TestMergeLegacyPatternsSynthesizesShallowRule(t *testing.T) {
	t.Parallel()

	doc := MergeLegacyPatterns(File{Version: VersionV1Alpha1}, []string{"webpack", "eslint"})
	if len(doc.ShallowExcludes) != 1 {
		t.Fatalf("expected one synthesized shallow rule, got %d", len(doc.ShallowExcludes))
	}
	if doc.ShallowExcludes[0].ID != legacyExcludePatternsRuleID {
		t.Fatalf("unexpected synthesized rule id: %q", doc.ShallowExcludes[0].ID)
	}
	if got := doc.ShallowExcludes[0].Match.NameGlobs; len(got) != 2 || got[0] != "*webpack*" || got[1] != "*eslint*" {
		t.Fatalf("unexpected synthesized globs: %#v", got)
	}
}

func TestMergeLegacyPatternsIgnoresBlankValues(t *testing.T) {
	t.Parallel()

	doc := MergeLegacyPatterns(File{Version: VersionV1Alpha1}, []string{" ", "eslint", "", "webpack"})
	if len(doc.ShallowExcludes) != 1 {
		t.Fatalf("expected one synthesized rule, got %d", len(doc.ShallowExcludes))
	}
	if got := doc.ShallowExcludes[0].Match.NameGlobs; len(got) != 2 || got[0] != "*eslint*" || got[1] != "*webpack*" {
		t.Fatalf("unexpected normalized globs: %#v", got)
	}
}

func TestLoadFileReadsAndWrapsErrors(t *testing.T) {
	t.Parallel()

	if _, err := LoadFile(filepath.Join(t.TempDir(), "missing.json")); err == nil {
		t.Fatal("expected read error")
	}

	dir := t.TempDir()
	pathValue := filepath.Join(dir, "broken.json")
	if err := os.WriteFile(pathValue, []byte(`{broken`), 0o644); err != nil {
		t.Fatalf("write broken policy: %v", err)
	}
	if _, err := LoadFile(pathValue); err == nil {
		t.Fatal("expected parse error")
	}
}

func TestLoadFileParsesValidPolicy(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	pathValue := filepath.Join(dir, "policy.json")
	if err := os.WriteFile(pathValue, []byte(`{
  "version":"v1alpha1",
  "subgraphExcludes":[{"id":"omit-subgraph","onUnsupported":"IGNORE","match":{"names":["pkg"]}}]
}`), 0o644); err != nil {
		t.Fatalf("write policy: %v", err)
	}

	doc, err := LoadFile(pathValue)
	if err != nil {
		t.Fatalf("load policy: %v", err)
	}
	if len(doc.SubgraphExcludes) != 1 || doc.SubgraphExcludes[0].OnUnsupported != OnUnsupportedIgnore {
		t.Fatalf("loaded document = %#v", doc)
	}
}

func TestMergeLegacyPatternsLeavesDocumentUntouchedWhenPatternsBlank(t *testing.T) {
	t.Parallel()

	doc := File{Version: VersionV1Alpha1, ShallowExcludes: []Rule{{ID: "existing", Match: Selector{Names: []string{"pkg"}}}}}
	merged := MergeLegacyPatterns(doc, []string{" ", ""})
	if len(merged.ShallowExcludes) != 1 || merged.ShallowExcludes[0].ID != "existing" {
		t.Fatalf("merged = %#v", merged)
	}
}
