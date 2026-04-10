package licenseoverride

import (
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

func TestLoadFileWrapsReadAndParseErrors(t *testing.T) {
	t.Parallel()

	if _, err := LoadFile(filepath.Join(t.TempDir(), "missing.json"), testCatalog()); err == nil {
		t.Fatal("expected read error")
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
