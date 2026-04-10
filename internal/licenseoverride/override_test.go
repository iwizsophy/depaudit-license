package licenseoverride

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"depaudit-license/internal/catalog"
	"depaudit-license/internal/inventory"
	"depaudit-license/internal/policy"
)

func TestParseValidatesCatalogKeysAndNormalizesRules(t *testing.T) {
	t.Parallel()

	doc, err := Parse([]byte(`{
  "version": "v1alpha1",
  "licenseOverrides": [
    {
      "id": " react-mit ",
      "reason": " reviewed ",
      "match": { "ecosystems": ["npm"], "names": ["react"], "versions": ["19.2.4"] },
      "licenseKey": " MIT "
    }
  ]
}`), testCatalog())
	if err != nil {
		t.Fatalf("parse override: %v", err)
	}
	if len(doc.LicenseOverrides) != 1 {
		t.Fatalf("rule count = %d", len(doc.LicenseOverrides))
	}
	rule := doc.LicenseOverrides[0]
	if rule.ID != "react-mit" || rule.Reason != "reviewed" || rule.LicenseKey != "MIT" || rule.Mode != ModeIfMissing {
		t.Fatalf("normalized rule = %#v", rule)
	}
}

func TestParseRejectsInvalidOverride(t *testing.T) {
	t.Parallel()

	cases := map[string]string{
		"version":     `{"version":"v2","licenseOverrides":[]}`,
		"emptyMatch":  `{"version":"v1alpha1","licenseOverrides":[{"match":{},"licenseKey":"MIT"}]}`,
		"unknownKey":  `{"version":"v1alpha1","licenseOverrides":[{"match":{"names":["react"]},"licenseKey":"BSD-2-Clause"}]}`,
		"badMode":     `{"version":"v1alpha1","licenseOverrides":[{"match":{"names":["react"]},"licenseKey":"MIT","mode":"sometimes"}]}`,
		"duplicateID": `{"version":"v1alpha1","licenseOverrides":[{"id":"dup","match":{"names":["react"]},"licenseKey":"MIT"},{"id":"dup","match":{"names":["vue"]},"licenseKey":"MIT"}]}`,
	}

	for name, payload := range cases {
		name := name
		payload := payload
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if _, err := Parse([]byte(payload), testCatalog()); err == nil {
				t.Fatal("expected parse error")
			}
		})
	}
}

func TestApplyIfMissingOverridesFallbackLicense(t *testing.T) {
	t.Parallel()

	doc := inventory.Document{
		Sources: []inventory.Source{{ID: "repo-scan", Kind: "repository-scan", Location: "."}},
		Packages: []inventory.Package{{
			Provenance: inventory.PackageProvenance{SourceIDs: []string{"repo-scan"}},
			Ecosystem:  "node",
			Project:    "web",
			Name:       "react",
			Version:    "19.2.4",
			RawLicense: "Unknown",
			LicenseKey: "Unknown",
			PURL:       "pkg:npm/react@19.2.4",
		}},
	}

	result, err := Apply(ApplyConfig{
		Catalog: testCatalog(),
		Rules: []Rule{{
			ID:         "react-mit",
			Match:      mustSelector(t, `{"ecosystems":["npm"],"names":["react"],"versions":["19.2.4"],"purls":["pkg:npm/react@19.2.4"]}`),
			LicenseKey: "MIT",
		}},
	}, doc)
	if err != nil {
		t.Fatalf("apply override: %v", err)
	}

	pkg := result.Packages[0]
	if pkg.LicenseKey != "MIT" || pkg.RawLicense != "MIT" {
		t.Fatalf("package license = %q / %q", pkg.LicenseKey, pkg.RawLicense)
	}
	if pkg.Provenance.FieldOrigins["licenseKey"] != "license-override:react-mit" {
		t.Fatalf("license origin = %#v", pkg.Provenance.FieldOrigins)
	}
	if len(result.Diagnostics) != 1 || result.Diagnostics[0].Code != "license_override_applied" {
		t.Fatalf("diagnostics = %#v", result.Diagnostics)
	}
	if !hasSource(result.Sources, "license-override:react-mit") {
		t.Fatalf("sources = %#v", result.Sources)
	}
}

func TestApplyIfMissingSkipsExistingLicenseAndForceOverrides(t *testing.T) {
	t.Parallel()

	doc := inventory.Document{Packages: []inventory.Package{{
		Provenance: inventory.PackageProvenance{SourceIDs: []string{"sbom"}},
		Ecosystem:  "node",
		Name:       "react",
		Version:    "19.2.4",
		RawLicense: "Apache-2.0",
		LicenseKey: "Apache-2.0",
	}}}

	skipped, err := Apply(ApplyConfig{
		Catalog: testCatalog(),
		Rules:   []Rule{{ID: "skip", Match: mustSelector(t, `{"names":["react"]}`), LicenseKey: "MIT", Mode: ModeIfMissing}},
	}, doc)
	if err != nil {
		t.Fatalf("apply ifMissing: %v", err)
	}
	if skipped.Packages[0].LicenseKey != "Apache-2.0" || len(skipped.Diagnostics) != 0 {
		t.Fatalf("expected unchanged package, got %#v", skipped)
	}

	forced, err := Apply(ApplyConfig{
		Catalog: testCatalog(),
		Rules:   []Rule{{ID: "force", Match: mustSelector(t, `{"names":["react"]}`), LicenseKey: "MIT", RawLicense: "MIT", Mode: ModeForce}},
	}, doc)
	if err != nil {
		t.Fatalf("apply force: %v", err)
	}
	if forced.Packages[0].LicenseKey != "MIT" || forced.Packages[0].RawLicense != "MIT" {
		t.Fatalf("forced package = %#v", forced.Packages[0])
	}
}

func TestApplyPreservesReviewedRawLicenseEvidenceWhenRuleOmitsRawLicense(t *testing.T) {
	t.Parallel()

	result, err := Apply(ApplyConfig{
		Catalog: testCatalog(),
		Rules: []Rule{{
			ID:         "custom-reviewed-as-mit",
			Match:      mustSelector(t, `{"names":["custom-lib"]}`),
			LicenseKey: "MIT",
		}},
	}, inventory.Document{Packages: []inventory.Package{{
		Provenance: inventory.PackageProvenance{SourceIDs: []string{"sbom"}},
		Ecosystem:  "generic",
		Name:       "custom-lib",
		Version:    "1.0.0",
		RawLicense: "Custom Notice",
		LicenseKey: "Unknown",
	}}})
	if err != nil {
		t.Fatalf("apply override: %v", err)
	}

	pkg := result.Packages[0]
	if pkg.LicenseKey != "MIT" || pkg.RawLicense != "Custom Notice" {
		t.Fatalf("package license = %q / %q", pkg.LicenseKey, pkg.RawLicense)
	}
	if _, ok := pkg.Provenance.FieldOrigins["rawLicense"]; ok {
		t.Fatalf("raw license origin should remain unchanged, got %#v", pkg.Provenance.FieldOrigins)
	}
}

func TestApplyRejectsMultipleMatchingRules(t *testing.T) {
	t.Parallel()

	_, err := Apply(ApplyConfig{
		Catalog: testCatalog(),
		Rules: []Rule{
			{ID: "a", Match: mustSelector(t, `{"names":["react"]}`), LicenseKey: "MIT"},
			{ID: "b", Match: mustSelector(t, `{"ecosystems":["node"]}`), LicenseKey: "Apache-2.0"},
		},
	}, inventory.Document{Packages: []inventory.Package{{Ecosystem: "node", Name: "react", LicenseKey: "Unknown"}}})
	if err == nil || !strings.Contains(err.Error(), "matches multiple license override rules") {
		t.Fatalf("expected multiple match error, got %v", err)
	}
}

func TestApplyClonesExistingDocumentStateAndSortsDiagnostics(t *testing.T) {
	t.Parallel()

	doc := inventory.Document{
		Sources: []inventory.Source{{ID: "repo-scan", Kind: "repository-scan", Location: "."}},
		Packages: []inventory.Package{{
			Provenance: inventory.PackageProvenance{
				SourceIDs:      []string{"repo-scan"},
				FieldOrigins:   map[string]string{"repository": "repo-scan"},
				ConflictFields: []string{"repository"},
			},
			Ecosystem:  "node",
			Project:    "web",
			Name:       "react",
			Version:    "19.2.4",
			RawLicense: "Unknown",
			LicenseKey: "Unknown",
		}},
		Conflicts: []inventory.Conflict{{
			Identity: "node/web/react/19.2.4",
			Field:    "repository",
			Values:   []inventory.ConflictValue{{SourceID: "repo-scan", Value: "https://example.test/repo"}},
		}},
		Diagnostics: []inventory.Diagnostic{
			{
				SourceID:          "z-source",
				RuleID:            "z-rule",
				Code:              "existing_z",
				Severity:          "warn",
				Message:           "z",
				MatchedRoots:      []string{"z-root"},
				RemovedPackages:   []string{"z-removed"},
				PreservedPackages: []string{"z-preserved"},
			},
			{
				SourceID: "a-source",
				RuleID:   "a-rule",
				Code:     "existing_a",
				Severity: "info",
				Message:  "a",
			},
		},
	}

	result, err := Apply(ApplyConfig{
		Catalog:        testCatalog(),
		SourceLocation: "configs/license-overrides.json",
		Rules: []Rule{{
			ID:         "react-mit",
			Match:      mustSelector(t, `{"names":["react"]}`),
			LicenseKey: "MIT",
		}},
	}, doc)
	if err != nil {
		t.Fatalf("apply override: %v", err)
	}
	if got := result.Diagnostics[0].SourceID; got != "a-source" {
		t.Fatalf("expected diagnostics to be sorted, first source = %q", got)
	}
	var overrideSource inventory.Source
	for _, source := range result.Sources {
		if source.ID == "license-override:react-mit" {
			overrideSource = source
		}
	}
	if overrideSource.Location != "configs/license-overrides.json" {
		t.Fatalf("license override source = %#v", overrideSource)
	}

	result.Packages[0].Provenance.SourceIDs[0] = "mutated-source"
	result.Packages[0].Provenance.FieldOrigins["repository"] = "mutated-origin"
	result.Packages[0].Provenance.ConflictFields[0] = "mutated-conflict"
	result.Conflicts[0].Values[0].Value = "mutated-conflict-value"
	result.Diagnostics[2].MatchedRoots[0] = "mutated-root"
	result.Diagnostics[2].RemovedPackages[0] = "mutated-removed"
	result.Diagnostics[2].PreservedPackages[0] = "mutated-preserved"

	if doc.Packages[0].Provenance.SourceIDs[0] != "repo-scan" ||
		doc.Packages[0].Provenance.FieldOrigins["repository"] != "repo-scan" ||
		doc.Packages[0].Provenance.ConflictFields[0] != "repository" {
		t.Fatalf("package provenance was mutated: %#v", doc.Packages[0].Provenance)
	}
	if doc.Conflicts[0].Values[0].Value != "https://example.test/repo" {
		t.Fatalf("conflict values were mutated: %#v", doc.Conflicts)
	}
	if doc.Diagnostics[0].MatchedRoots[0] != "z-root" ||
		doc.Diagnostics[0].RemovedPackages[0] != "z-removed" ||
		doc.Diagnostics[0].PreservedPackages[0] != "z-preserved" {
		t.Fatalf("diagnostics were mutated: %#v", doc.Diagnostics[0])
	}
}

func TestApplyUsesFallbackSourceForUnnamedRule(t *testing.T) {
	t.Parallel()

	result, err := Apply(ApplyConfig{
		Catalog: testCatalog(),
		Rules: []Rule{{
			Match:      mustSelector(t, `{"names":["react"]}`),
			LicenseKey: "MIT",
		}},
	}, inventory.Document{Packages: []inventory.Package{{Name: "react", LicenseKey: "Unknown"}}})
	if err != nil {
		t.Fatalf("apply unnamed rule: %v", err)
	}
	if got := result.Packages[0].Provenance.FieldOrigins["licenseKey"]; got != "license-override" {
		t.Fatalf("license origin = %q", got)
	}
	if len(result.Sources) != 1 || result.Sources[0].ID != "license-override" || result.Sources[0].Location != "license-override" {
		t.Fatalf("sources = %#v", result.Sources)
	}
}

func TestLoadFileWrapsReadAndParseErrors(t *testing.T) {
	t.Parallel()

	if _, err := LoadFile(filepath.Join(t.TempDir(), "missing.json"), testCatalog()); err == nil {
		t.Fatal("expected read error")
	}

	dir := t.TempDir()
	brokenPath := filepath.Join(dir, "broken.json")
	if err := os.WriteFile(brokenPath, []byte(`{"version":"v1alpha1","licenseOverrides":[{"match":{"names":["react"]},"licenseKey":"Missing"}]}`), 0o644); err != nil {
		t.Fatalf("write broken override: %v", err)
	}
	if _, err := LoadFile(brokenPath, testCatalog()); err == nil {
		t.Fatal("expected parse error")
	}

	validPath := filepath.Join(dir, "valid.json")
	if err := os.WriteFile(validPath, []byte(`{"version":"v1alpha1","licenseOverrides":[{"match":{"names":["react"]},"licenseKey":"MIT"}]}`), 0o644); err != nil {
		t.Fatalf("write valid override: %v", err)
	}
	doc, err := LoadFile(validPath, testCatalog())
	if err != nil {
		t.Fatalf("load valid override: %v", err)
	}
	if len(doc.LicenseOverrides) != 1 || doc.LicenseOverrides[0].LicenseKey != "MIT" {
		t.Fatalf("loaded override = %#v", doc)
	}
}

func testCatalog() *catalog.Catalog {
	return &catalog.Catalog{
		Fallback: "Unknown",
		Definitions: map[string]catalog.Definition{
			"Unknown":    {Key: "Unknown", Name: "Unknown"},
			"MIT":        {Key: "MIT", Name: "MIT License"},
			"Apache-2.0": {Key: "Apache-2.0", Name: "Apache License 2.0"},
		},
	}
}

func mustSelector(t *testing.T, payload string) policy.Selector {
	t.Helper()

	doc, err := Parse([]byte(`{"version":"v1alpha1","licenseOverrides":[{"match":`+payload+`,"licenseKey":"MIT"}]}`), testCatalog())
	if err != nil {
		t.Fatalf("parse selector: %v", err)
	}
	return doc.LicenseOverrides[0].Match
}
