package catalog

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestNormalizeUsesStructuredMatchersAndFallback(t *testing.T) {
	t.Parallel()

	cat := loadCatalogFixture(t, `{
  "fallback": "Unknown",
  "licenses": [
    {
      "key": "MIT",
      "name": "MIT License",
      "family": "MIT",
      "version": "",
      "copyleft_strength": "none",
      "requires_manual_review": false,
      "spdx_ids": ["mit"],
      "names": ["mit license"],
      "exact_urls": [],
      "url_prefixes": [],
      "contains": ["opensource.org/licenses/mit"],
      "description": "desc",
      "obligations": ["notice"],
      "permissions": ["commercial"],
      "limitations": ["warranty"],
      "color": "#2f855a",
      "risk_level": "low",
      "notice_template": "template"
    },
    {
      "key": "Unknown",
      "name": "Unknown",
      "family": "Unknown",
      "version": "",
      "copyleft_strength": "unknown",
      "requires_manual_review": true,
      "spdx_ids": ["unknown"],
      "names": [],
      "exact_urls": [],
      "url_prefixes": [],
      "contains": ["see license"],
      "description": "desc",
      "obligations": ["review"],
      "permissions": ["unknown"],
      "limitations": ["unknown"],
      "color": "#718096",
      "risk_level": "unknown",
      "notice_template": "template"
    }
  ]
}`)

	cases := map[string]string{
		"MIT License":                         "MIT",
		"https://opensource.org/licenses/MIT": "MIT",
		"something-custom":                    "Unknown",
	}

	for input, want := range cases {
		got, _ := cat.Normalize(input)
		if got != want {
			t.Fatalf("normalize(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestNormalizeSeparatesLicenseVersions(t *testing.T) {
	t.Parallel()

	cat := loadCatalogFixture(t, `{
  "fallback": "Unknown",
  "licenses": [
    {
      "key": "EPL-1.0",
      "name": "Eclipse Public License 1.0",
      "family": "EPL",
      "version": "1.0",
      "copyleft_strength": "file",
      "requires_manual_review": false,
      "spdx_ids": ["epl-1.0"],
      "names": ["eclipse public license 1.0"],
      "exact_urls": [],
      "url_prefixes": [],
      "contains": [],
      "description": "desc",
      "obligations": ["notice"],
      "permissions": ["commercial"],
      "limitations": ["warranty"],
      "color": "#c05621",
      "risk_level": "medium",
      "notice_template": "template"
    },
    {
      "key": "EPL-2.0",
      "name": "Eclipse Public License 2.0",
      "family": "EPL",
      "version": "2.0",
      "copyleft_strength": "file",
      "requires_manual_review": false,
      "spdx_ids": ["epl-2.0"],
      "names": ["eclipse public license 2.0"],
      "exact_urls": [],
      "url_prefixes": [],
      "contains": [],
      "description": "desc",
      "obligations": ["notice"],
      "permissions": ["commercial"],
      "limitations": ["warranty"],
      "color": "#c05621",
      "risk_level": "medium",
      "notice_template": "template"
    },
    {
      "key": "CDDL-1.0",
      "name": "Common Development and Distribution License 1.0",
      "family": "CDDL",
      "version": "1.0",
      "copyleft_strength": "file",
      "requires_manual_review": false,
      "spdx_ids": ["cddl-1.0"],
      "names": ["common development and distribution license 1.0"],
      "exact_urls": [],
      "url_prefixes": [],
      "contains": [],
      "description": "desc",
      "obligations": ["notice"],
      "permissions": ["commercial"],
      "limitations": ["warranty"],
      "color": "#c05621",
      "risk_level": "medium",
      "notice_template": "template"
    },
    {
      "key": "CDDL-1.1",
      "name": "Common Development and Distribution License 1.1",
      "family": "CDDL",
      "version": "1.1",
      "copyleft_strength": "file",
      "requires_manual_review": false,
      "spdx_ids": ["cddl-1.1"],
      "names": ["common development and distribution license 1.1"],
      "exact_urls": [],
      "url_prefixes": [],
      "contains": [],
      "description": "desc",
      "obligations": ["notice"],
      "permissions": ["commercial"],
      "limitations": ["warranty"],
      "color": "#c05621",
      "risk_level": "medium",
      "notice_template": "template"
    },
    {
      "key": "Unknown",
      "name": "Unknown",
      "family": "Unknown",
      "version": "",
      "copyleft_strength": "unknown",
      "requires_manual_review": true,
      "spdx_ids": ["unknown"],
      "names": [],
      "exact_urls": [],
      "url_prefixes": [],
      "contains": [],
      "description": "desc",
      "obligations": ["review"],
      "permissions": ["unknown"],
      "limitations": ["unknown"],
      "color": "#718096",
      "risk_level": "unknown",
      "notice_template": "template"
    }
  ]
}`)

	cases := map[string]string{
		"EPL-1.0":  "EPL-1.0",
		"EPL-2.0":  "EPL-2.0",
		"CDDL-1.0": "CDDL-1.0",
		"CDDL-1.1": "CDDL-1.1",
	}

	for input, want := range cases {
		got, _ := cat.Normalize(input)
		if got != want {
			t.Fatalf("normalize(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestNormalizeSupportsStructuredMatchers(t *testing.T) {
	t.Parallel()

	cat := loadCatalogFixture(t, `{
  "fallback": "Unknown",
  "licenses": [
    {
      "key": "MIT",
      "name": "MIT License",
      "family": "MIT",
      "version": "",
      "copyleft_strength": "none",
      "requires_manual_review": false,
      "spdx_ids": ["MIT"],
      "names": ["MIT License"],
      "exact_urls": ["https://licenses.example.test/MIT"],
      "url_prefixes": ["https://opensource.org/licenses/mit"],
      "contains": ["license=mit"],
      "description": "desc",
      "obligations": ["notice"],
      "permissions": ["commercial"],
      "limitations": ["warranty"],
      "color": "#2f855a",
      "risk_level": "low",
      "notice_template": "template"
    },
    {
      "key": "Unknown",
      "name": "Unknown",
      "family": "Unknown",
      "version": "",
      "copyleft_strength": "unknown",
      "requires_manual_review": true,
      "spdx_ids": ["unknown"],
      "names": [],
      "exact_urls": [],
      "url_prefixes": [],
      "contains": [],
      "description": "desc",
      "obligations": ["review"],
      "permissions": ["unknown"],
      "limitations": ["unknown"],
      "color": "#718096",
      "risk_level": "unknown",
      "notice_template": "template"
    }
  ]
}`)

	cases := map[string]string{
		"MIT":                               "MIT",
		"MIT License":                       "MIT",
		"https://licenses.example.test/MIT": "MIT",
		"https://opensource.org/licenses/MIT?x=1": "MIT",
		"https://example.test/pkg?license=mit":    "MIT",
	}

	for input, want := range cases {
		got, _ := cat.Normalize(input)
		if got != want {
			t.Fatalf("normalize(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestLoadFileFormatReadsLocalCatalog(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "licenses.json")
	file := fileFormat{
		Fallback: "Unknown",
		Licenses: []Definition{{
			Key:                  "Unknown",
			Name:                 "Unknown",
			Family:               "Unknown",
			CopyleftStrength:     "unknown",
			RequiresManualReview: true,
			SPDXIDs:              []string{"unknown"},
			RiskLevel:            "unknown",
		}},
	}
	payload, err := json.Marshal(file)
	if err != nil {
		t.Fatalf("marshal file: %v", err)
	}
	if err := os.WriteFile(path, payload, 0o644); err != nil {
		t.Fatalf("write catalog: %v", err)
	}

	loaded, err := loadFileFormat(path)
	if err != nil {
		t.Fatalf("loadFileFormat: %v", err)
	}
	if loaded.Fallback != "Unknown" || len(loaded.Licenses) != 1 {
		t.Fatalf("loaded = %#v", loaded)
	}
}

func TestCatalogValidationHelpers(t *testing.T) {
	t.Parallel()

	valid := Definition{
		Key:              "MIT",
		Name:             "MIT License",
		Family:           "MIT",
		CopyleftStrength: "none",
		RiskLevel:        "low",
		SPDXIDs:          []string{"MIT"},
	}
	if err := validateDefinition(valid); err != nil {
		t.Fatalf("validateDefinition valid: %v", err)
	}

	if err := validateDefinition(Definition{
		Name:             "Broken",
		Family:           "Broken",
		CopyleftStrength: "none",
		RiskLevel:        "low",
		SPDXIDs:          []string{"Broken"},
	}); err == nil {
		t.Fatal("expected empty key error")
	}

	if err := validateDefinition(Definition{
		Key:              "Broken",
		Family:           "Broken",
		CopyleftStrength: "none",
		RiskLevel:        "low",
		SPDXIDs:          []string{"Broken"},
	}); err == nil {
		t.Fatal("expected empty name error")
	}

	if err := validateDefinition(Definition{
		Key:              "Broken",
		Name:             "Broken",
		CopyleftStrength: "none",
		RiskLevel:        "low",
		SPDXIDs:          []string{"Broken"},
	}); err == nil {
		t.Fatal("expected empty family error")
	}

	if err := validateDefinition(Definition{
		Key:              "Broken",
		Name:             "Broken",
		Family:           "Broken",
		CopyleftStrength: "none",
		RiskLevel:        "critical",
		SPDXIDs:          []string{"Broken"},
	}); err == nil {
		t.Fatal("expected invalid risk level error")
	}

	if err := validateDefinition(Definition{
		Key:              "Broken",
		Name:             "Broken",
		Family:           "Broken",
		CopyleftStrength: "invalid",
		RiskLevel:        "low",
		SPDXIDs:          []string{"Broken"},
	}); err == nil {
		t.Fatal("expected invalid copyleft strength error")
	}

	if err := validateDefinition(Definition{
		Key:              "Broken",
		Name:             "Broken",
		Family:           "Broken",
		CopyleftStrength: "none",
		RiskLevel:        "low",
	}); err == nil {
		t.Fatal("expected missing matcher error")
	}

	if err := validateDefinition(Definition{
		Key:              "Broken",
		Name:             "Broken",
		Family:           "Broken",
		CopyleftStrength: "none",
		RiskLevel:        "low",
		SPDXIDs:          []string{"Broken"},
		ExactURLs:        []string{"/relative"},
	}); err == nil {
		t.Fatal("expected invalid exact url error")
	}

	if err := validateDefinition(Definition{
		Key:              "Broken",
		Name:             "Broken",
		Family:           "Broken",
		CopyleftStrength: "none",
		RiskLevel:        "low",
		SPDXIDs:          []string{"Broken"},
		URLPrefixes:      []string{"/relative-prefix"},
	}); err == nil {
		t.Fatal("expected invalid url prefix error")
	}

	if !isAllowedRiskLevel("medium") || isAllowedRiskLevel("critical") {
		t.Fatal("unexpected risk level validation result")
	}
	if !isAllowedCopyleftStrength("network") || isAllowedCopyleftStrength("weak") {
		t.Fatal("unexpected copyleft validation result")
	}
	if err := validateAbsoluteURL("https://example.test/license"); err != nil {
		t.Fatalf("validateAbsoluteURL valid: %v", err)
	}
	if err := validateAbsoluteURL("not a url"); err == nil {
		t.Fatal("expected invalid absolute url error")
	}
}

func TestNormalizeHandlesCommonExpressionsWithRealCatalog(t *testing.T) {
	t.Parallel()

	cat, err := Load(filepath.Join("..", "..", "configs", "licenses.json"))
	if err != nil {
		t.Fatalf("load real catalog: %v", err)
	}

	cases := map[string]string{
		"GPL-2.0-only WITH Classpath-exception-2.0":   "GPL-2.0",
		"https://opensource.org/licenses/MIT?ref=abc": "MIT",
		"EPL-1.0":  "EPL-1.0",
		"CDDL-1.1": "CDDL-1.1",
	}

	for input, want := range cases {
		got, _ := cat.Normalize(input)
		if got != want {
			t.Fatalf("normalize(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestLoadRejectsDuplicateKeys(t *testing.T) {
	t.Parallel()

	assertLoadErrorContains(t, `{
  "fallback": "MIT",
  "licenses": [
    {
      "key": "MIT",
      "name": "MIT License",
      "family": "MIT",
      "version": "",
      "copyleft_strength": "none",
      "requires_manual_review": false,
      "spdx_ids": ["MIT"],
      "names": [],
      "exact_urls": [],
      "url_prefixes": [],
      "contains": [],
      "description": "desc",
      "obligations": ["notice"],
      "permissions": ["commercial"],
      "limitations": ["warranty"],
      "color": "#2f855a",
      "risk_level": "low",
      "notice_template": "template"
    },
    {
      "key": "MIT",
      "name": "MIT Second",
      "family": "MIT",
      "version": "",
      "copyleft_strength": "none",
      "requires_manual_review": false,
      "spdx_ids": ["MIT-2"],
      "names": [],
      "exact_urls": [],
      "url_prefixes": [],
      "contains": [],
      "description": "desc",
      "obligations": ["notice"],
      "permissions": ["commercial"],
      "limitations": ["warranty"],
      "color": "#2f855a",
      "risk_level": "low",
      "notice_template": "template"
    }
  ]
}`, "duplicate license definition key")
}

func TestLoadRejectsMissingMatchers(t *testing.T) {
	t.Parallel()

	assertLoadErrorContains(t, `{
  "fallback": "MIT",
  "licenses": [
    {
      "key": "MIT",
      "name": "MIT License",
      "family": "MIT",
      "version": "",
      "copyleft_strength": "none",
      "requires_manual_review": false,
      "spdx_ids": [],
      "names": [],
      "exact_urls": [],
      "url_prefixes": [],
      "contains": [],
      "description": "desc",
      "obligations": ["notice"],
      "permissions": ["commercial"],
      "limitations": ["warranty"],
      "color": "#2f855a",
      "risk_level": "low",
      "notice_template": "template"
    }
  ]
}`, "does not define any matchers")
}

func TestLoadRejectsInvalidMetadataEnums(t *testing.T) {
	t.Parallel()

	assertLoadErrorContains(t, `{
  "fallback": "MIT",
  "licenses": [
    {
      "key": "MIT",
      "name": "MIT License",
      "family": "MIT",
      "version": "",
      "copyleft_strength": "mystery",
      "requires_manual_review": false,
      "spdx_ids": ["MIT"],
      "names": [],
      "exact_urls": [],
      "url_prefixes": [],
      "contains": [],
      "description": "desc",
      "obligations": ["notice"],
      "permissions": ["commercial"],
      "limitations": ["warranty"],
      "color": "#2f855a",
      "risk_level": "low",
      "notice_template": "template"
    }
  ]
}`, "invalid copyleft_strength")
}

func TestLoadRejectsUndefinedFallback(t *testing.T) {
	t.Parallel()

	assertLoadErrorContains(t, `{
  "fallback": "Unknown",
  "licenses": [
    {
      "key": "MIT",
      "name": "MIT License",
      "family": "MIT",
      "version": "",
      "copyleft_strength": "none",
      "requires_manual_review": false,
      "spdx_ids": ["MIT"],
      "names": [],
      "exact_urls": [],
      "url_prefixes": [],
      "contains": [],
      "description": "desc",
      "obligations": ["notice"],
      "permissions": ["commercial"],
      "limitations": ["warranty"],
      "color": "#2f855a",
      "risk_level": "low",
      "notice_template": "template"
    }
  ]
}`, "fallback license")
}

func TestLoadSourcesWithOptionsRejectsEmptySourceList(t *testing.T) {
	t.Parallel()

	if _, err := LoadSourcesWithOptions(LoadOptions{}); err == nil || !strings.Contains(err.Error(), "license catalog path list is empty") {
		t.Fatalf("expected empty source list error, got %v", err)
	}
}

func TestLoadSourcesWithOptionsRejectsInvalidRemoteCatalogMode(t *testing.T) {
	t.Parallel()

	if _, err := LoadSourcesWithOptions(LoadOptions{RemoteCatalogMode: "mystery"}, "configs/licenses.json"); err == nil || !strings.Contains(err.Error(), `invalid remote catalog mode "mystery"`) {
		t.Fatalf("expected invalid remote catalog mode error, got %v", err)
	}
}

func TestLoadPathsMergesAndOverridesDefinitions(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	basePath := filepath.Join(dir, "base.json")
	overridePath := filepath.Join(dir, "override.json")

	base := `{
  "fallback": "Unknown",
  "licenses": [
    {
      "key": "MIT",
      "name": "MIT License",
      "family": "MIT",
      "version": "",
      "copyleft_strength": "none",
      "requires_manual_review": false,
      "spdx_ids": ["MIT"],
      "names": [],
      "exact_urls": [],
      "url_prefixes": [],
      "contains": [],
      "description": "base",
      "obligations": ["notice"],
      "permissions": ["commercial"],
      "limitations": ["warranty"],
      "color": "#2f855a",
      "risk_level": "low",
      "notice_template": "base-template"
    },
    {
      "key": "Unknown",
      "name": "Unknown",
      "family": "Unknown",
      "version": "",
      "copyleft_strength": "unknown",
      "requires_manual_review": true,
      "spdx_ids": ["Unknown"],
      "names": [],
      "exact_urls": [],
      "url_prefixes": [],
      "contains": [],
      "description": "unknown",
      "obligations": ["review"],
      "permissions": ["unknown"],
      "limitations": ["unknown"],
      "color": "#718096",
      "risk_level": "unknown",
      "notice_template": "unknown-template"
    }
  ]
}`
	override := `{
  "fallback": "Unknown",
  "licenses": [
    {
      "key": "MIT",
      "name": "Custom MIT",
      "family": "MIT",
      "version": "",
      "copyleft_strength": "none",
      "requires_manual_review": false,
      "spdx_ids": ["MIT"],
      "names": ["Custom MIT"],
      "exact_urls": [],
      "url_prefixes": [],
      "contains": [],
      "description": "override",
      "obligations": ["custom notice"],
      "permissions": ["commercial"],
      "limitations": ["warranty"],
      "color": "#1a202c",
      "risk_level": "low",
      "notice_template": "override-template"
    }
  ]
}`

	if err := os.WriteFile(basePath, []byte(base), 0o644); err != nil {
		t.Fatalf("write base catalog: %v", err)
	}
	if err := os.WriteFile(overridePath, []byte(override), 0o644); err != nil {
		t.Fatalf("write override catalog: %v", err)
	}

	cat, err := LoadPaths(basePath, overridePath)
	if err != nil {
		t.Fatalf("load merged catalogs: %v", err)
	}

	def := cat.Lookup("MIT")
	if def.Name != "Custom MIT" {
		t.Fatalf("expected override definition, got %q", def.Name)
	}
	if def.Description != "override" {
		t.Fatalf("expected override description, got %q", def.Description)
	}
	if got, _ := cat.Normalize("Custom MIT"); got != "MIT" {
		t.Fatalf("expected override match, got %q", got)
	}
}

func TestLoadPathsAllowsOverrideToChangeFallback(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	basePath := filepath.Join(dir, "base.json")
	overridePath := filepath.Join(dir, "override.json")

	base := `{
  "fallback": "Unknown",
  "licenses": [
    {
      "key": "MIT",
      "name": "MIT License",
      "family": "MIT",
      "version": "",
      "copyleft_strength": "none",
      "requires_manual_review": false,
      "spdx_ids": ["MIT"],
      "names": [],
      "exact_urls": [],
      "url_prefixes": [],
      "contains": [],
      "description": "desc",
      "obligations": ["notice"],
      "permissions": ["commercial"],
      "limitations": ["warranty"],
      "color": "#2f855a",
      "risk_level": "low",
      "notice_template": "template"
    },
    {
      "key": "Unknown",
      "name": "Unknown",
      "family": "Unknown",
      "version": "",
      "copyleft_strength": "unknown",
      "requires_manual_review": true,
      "spdx_ids": ["Unknown"],
      "names": [],
      "exact_urls": [],
      "url_prefixes": [],
      "contains": [],
      "description": "desc",
      "obligations": ["review"],
      "permissions": ["unknown"],
      "limitations": ["unknown"],
      "color": "#718096",
      "risk_level": "unknown",
      "notice_template": "template"
    }
  ]
}`
	override := `{
  "fallback": "MIT",
  "licenses": [
    {
      "key": "MIT",
      "name": "MIT License",
      "family": "MIT",
      "version": "",
      "copyleft_strength": "none",
      "requires_manual_review": false,
      "spdx_ids": ["MIT"],
      "names": [],
      "exact_urls": [],
      "url_prefixes": [],
      "contains": [],
      "description": "desc",
      "obligations": ["notice"],
      "permissions": ["commercial"],
      "limitations": ["warranty"],
      "color": "#2f855a",
      "risk_level": "low",
      "notice_template": "template"
    }
  ]
}`

	if err := os.WriteFile(basePath, []byte(base), 0o644); err != nil {
		t.Fatalf("write base catalog: %v", err)
	}
	if err := os.WriteFile(overridePath, []byte(override), 0o644); err != nil {
		t.Fatalf("write override catalog: %v", err)
	}

	cat, err := LoadPaths(basePath, overridePath)
	if err != nil {
		t.Fatalf("load merged catalogs: %v", err)
	}

	if cat.Fallback != "MIT" {
		t.Fatalf("expected fallback MIT, got %q", cat.Fallback)
	}
}

func TestLoadSourcesSupportsRemoteCatalog(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
  "fallback": "Unknown",
  "licenses": [
    {
      "key": "MIT",
      "name": "MIT License",
      "family": "MIT",
      "version": "",
      "copyleft_strength": "none",
      "requires_manual_review": false,
      "spdx_ids": ["MIT"],
      "names": [],
      "exact_urls": [],
      "url_prefixes": [],
      "contains": [],
      "description": "desc",
      "obligations": ["notice"],
      "permissions": ["commercial"],
      "limitations": ["warranty"],
      "color": "#2f855a",
      "risk_level": "low",
      "notice_template": "template"
    },
    {
      "key": "Unknown",
      "name": "Unknown",
      "family": "Unknown",
      "version": "",
      "copyleft_strength": "unknown",
      "requires_manual_review": true,
      "spdx_ids": ["Unknown"],
      "names": [],
      "exact_urls": [],
      "url_prefixes": [],
      "contains": [],
      "description": "desc",
      "obligations": ["review"],
      "permissions": ["unknown"],
      "limitations": ["unknown"],
      "color": "#718096",
      "risk_level": "unknown",
      "notice_template": "template"
    }
  ]
}`))
	}))
	defer server.Close()

	result, err := LoadSources(server.Client(), server.URL+"/licenses.json")
	if err != nil {
		t.Fatalf("load remote catalog: %v", err)
	}
	cat := result.Catalog

	if got, _ := cat.Normalize("MIT"); got != "MIT" {
		t.Fatalf("unexpected normalized key %q", got)
	}
	if len(result.SourceMetadata) != 1 || result.SourceMetadata[0].Kind != "remote" {
		t.Fatalf("unexpected source metadata: %#v", result.SourceMetadata)
	}
}

func TestLoadSourcesMergesRemoteAndLocalOverride(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = w.Write([]byte(`{
  "fallback": "Unknown",
  "licenses": [
    {
      "key": "MIT",
      "name": "MIT License",
      "family": "MIT",
      "version": "",
      "copyleft_strength": "none",
      "requires_manual_review": false,
      "spdx_ids": ["MIT"],
      "names": [],
      "exact_urls": [],
      "url_prefixes": [],
      "contains": [],
      "description": "base",
      "obligations": ["notice"],
      "permissions": ["commercial"],
      "limitations": ["warranty"],
      "color": "#2f855a",
      "risk_level": "low",
      "notice_template": "template"
    },
    {
      "key": "Unknown",
      "name": "Unknown",
      "family": "Unknown",
      "version": "",
      "copyleft_strength": "unknown",
      "requires_manual_review": true,
      "spdx_ids": ["Unknown"],
      "names": [],
      "exact_urls": [],
      "url_prefixes": [],
      "contains": [],
      "description": "desc",
      "obligations": ["review"],
      "permissions": ["unknown"],
      "limitations": ["unknown"],
      "color": "#718096",
      "risk_level": "unknown",
      "notice_template": "template"
    }
  ]
}`))
	}))
	defer server.Close()

	dir := t.TempDir()
	overridePath := filepath.Join(dir, "override.json")
	override := `{
  "fallback": "Unknown",
  "licenses": [
    {
      "key": "MIT",
      "name": "Custom MIT",
      "family": "MIT",
      "version": "",
      "copyleft_strength": "none",
      "requires_manual_review": false,
      "spdx_ids": ["MIT"],
      "names": ["Custom MIT"],
      "exact_urls": [],
      "url_prefixes": [],
      "contains": [],
      "description": "override",
      "obligations": ["custom notice"],
      "permissions": ["commercial"],
      "limitations": ["warranty"],
      "color": "#1a202c",
      "risk_level": "low",
      "notice_template": "override-template"
    }
  ]
}`
	if err := os.WriteFile(overridePath, []byte(override), 0o644); err != nil {
		t.Fatalf("write override catalog: %v", err)
	}

	result, err := LoadSources(server.Client(), server.URL+"/licenses.json", overridePath)
	if err != nil {
		t.Fatalf("load mixed catalogs: %v", err)
	}
	cat := result.Catalog

	def := cat.Lookup("MIT")
	if def.Name != "Custom MIT" {
		t.Fatalf("expected override definition, got %q", def.Name)
	}
}

func TestLoadSourcesRejectsUnexpectedRemoteContentType(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte("<html></html>"))
	}))
	defer server.Close()

	_, err := LoadSources(server.Client(), server.URL+"/licenses.json")
	if err == nil {
		t.Fatal("expected remote content type error")
	}
	if !strings.Contains(err.Error(), "unexpected content type") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestLoadSourcesVerifiesPinnedRemoteSHA256(t *testing.T) {
	t.Parallel()

	body := `{
  "fallback": "Unknown",
  "licenses": [
    {
      "key": "Unknown",
      "name": "Unknown",
      "family": "Unknown",
      "version": "",
      "copyleft_strength": "unknown",
      "requires_manual_review": true,
      "spdx_ids": ["Unknown"],
      "names": [],
      "exact_urls": [],
      "url_prefixes": [],
      "contains": ["unknown"],
      "color": "#718096",
      "risk_level": "unknown",
      "notice_template": "template"
    }
  ]
}`
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("ETag", `"v1"`)
		_, _ = w.Write([]byte(body))
	}))
	defer server.Close()

	hash := sha256Hex([]byte(body))
	result, err := LoadSources(server.Client(), server.URL+"/licenses.json#sha256="+hash)
	if err != nil {
		t.Fatalf("load pinned source: %v", err)
	}
	if result.SourceMetadata[0].PinningMode != "pinned" {
		t.Fatalf("pinning mode = %q", result.SourceMetadata[0].PinningMode)
	}
	if result.SourceMetadata[0].RequestedSHA256 != hash {
		t.Fatalf("requested sha = %q", result.SourceMetadata[0].RequestedSHA256)
	}
	if result.SourceMetadata[0].ETag != `"v1"` {
		t.Fatalf("etag = %q", result.SourceMetadata[0].ETag)
	}
	if string(result.EffectiveCatalog) == "" {
		t.Fatal("expected effective catalog snapshot")
	}
}

func TestLoadSourcesRejectsPinnedRemoteSHA256Mismatch(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"fallback":"Unknown","licenses":[{"key":"Unknown","name":"Unknown","family":"Unknown","version":"","copyleft_strength":"unknown","requires_manual_review":true,"spdx_ids":["Unknown"],"names":[],"exact_urls":[],"url_prefixes":[],"contains":["unknown"],"color":"#718096","risk_level":"unknown","notice_template":"template"}]}`))
	}))
	defer server.Close()

	_, err := LoadSources(server.Client(), server.URL+"/licenses.json#sha256=deadbeef")
	if err == nil {
		t.Fatal("expected sha256 mismatch")
	}
	if !strings.Contains(err.Error(), "sha256 mismatch") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestLoadSourcesWithOptionsFallsBackToStaleCache(t *testing.T) {
	t.Parallel()

	body := `{
  "fallback": "Unknown",
  "licenses": [
    {
      "key": "Unknown",
      "name": "Unknown",
      "family": "Unknown",
      "version": "",
      "copyleft_strength": "unknown",
      "requires_manual_review": true,
      "spdx_ids": ["Unknown"],
      "names": [],
      "exact_urls": [],
      "url_prefixes": [],
      "contains": ["unknown"],
      "color": "#718096",
      "risk_level": "unknown",
      "notice_template": "template"
    }
  ]
}`
	cacheDir := t.TempDir()
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
	}))

	source := server.URL + "/licenses.json"
	_, err := LoadSourcesWithOptions(LoadOptions{
		Client:            server.Client(),
		RemoteCatalogMode: RemoteCatalogModeStaleFallback,
		CacheDir:          cacheDir,
	}, source)
	if err != nil {
		t.Fatalf("prime cache: %v", err)
	}
	server.Close()

	result, err := LoadSourcesWithOptions(LoadOptions{
		Client:            server.Client(),
		RemoteCatalogMode: RemoteCatalogModeStaleFallback,
		CacheDir:          cacheDir,
	}, source)
	if err != nil {
		t.Fatalf("load from stale cache: %v", err)
	}
	if result.SourceMetadata[0].CacheStatus != "stale-cache" {
		t.Fatalf("cache status = %q", result.SourceMetadata[0].CacheStatus)
	}
	if requests != 1 {
		t.Fatalf("unexpected request count %d", requests)
	}
}

func TestLoadSourcesWithOptionsFailFastDoesNotUseStaleCache(t *testing.T) {
	t.Parallel()

	cacheDir := t.TempDir()
	source := "http://127.0.0.1:9/licenses.json"
	_, err := LoadSourcesWithOptions(LoadOptions{
		Client:            &http.Client{},
		RemoteCatalogMode: RemoteCatalogModeFailFast,
		CacheDir:          cacheDir,
	}, source)
	if err == nil {
		t.Fatal("expected fail-fast error")
	}
}

func TestLoadSourcesWithOptionsMergesRemoteBaseAndLocalOverride(t *testing.T) {
	t.Parallel()

	remoteBody := `{
  "fallback": "Unknown",
  "licenses": [
    {
      "key": "MIT",
      "name": "MIT License",
      "family": "Permissive",
      "version": "",
      "copyleft_strength": "none",
      "requires_manual_review": false,
      "spdx_ids": ["MIT"],
      "names": ["MIT License"],
      "exact_urls": [],
      "url_prefixes": [],
      "contains": ["mit license"],
      "color": "#10b981",
      "risk_level": "low",
      "notice_template": "remote notice"
    }
  ]
}`
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(remoteBody))
	}))
	defer server.Close()

	dir := t.TempDir()
	overridePath := filepath.Join(dir, "override.json")
	overrideBody := `{
  "fallback": "LicenseRef-Local",
  "licenses": [
    {
      "key": "LicenseRef-Local",
      "name": "Local Fallback",
      "family": "Unknown",
      "version": "",
      "copyleft_strength": "unknown",
      "requires_manual_review": true,
      "spdx_ids": ["LicenseRef-Local"],
      "names": ["Local Fallback"],
      "exact_urls": [],
      "url_prefixes": [],
      "contains": ["local fallback"],
      "color": "#718096",
      "risk_level": "unknown",
      "notice_template": "local fallback notice"
    },
    {
      "key": "MIT",
      "name": "MIT License (Local Override)",
      "family": "Permissive",
      "version": "",
      "copyleft_strength": "none",
      "requires_manual_review": false,
      "spdx_ids": ["MIT"],
      "names": ["MIT License (Local Override)"],
      "exact_urls": [],
      "url_prefixes": [],
      "contains": ["mit license"],
      "color": "#22c55e",
      "risk_level": "low",
      "notice_template": "local notice"
    }
  ]
}`
	if err := os.WriteFile(overridePath, []byte(overrideBody), 0o644); err != nil {
		t.Fatalf("write override: %v", err)
	}

	result, err := LoadSourcesWithOptions(LoadOptions{
		Client:   server.Client(),
		CacheDir: t.TempDir(),
	}, server.URL+"/licenses.json", overridePath)
	if err != nil {
		t.Fatalf("load remote + local override: %v", err)
	}

	if result.Catalog.Fallback != "LicenseRef-Local" {
		t.Fatalf("fallback = %q", result.Catalog.Fallback)
	}
	def, ok := result.Catalog.Definitions["MIT"]
	if !ok {
		t.Fatal("expected MIT definition")
	}
	if def.Name != "MIT License (Local Override)" || def.NoticeTemplate != "local notice" {
		t.Fatalf("definition = %#v", def)
	}
	if len(result.SourceMetadata) != 2 {
		t.Fatalf("source metadata = %#v", result.SourceMetadata)
	}
	if result.SourceMetadata[0].Kind != "remote" || result.SourceMetadata[1].Kind != "file" {
		t.Fatalf("source metadata order = %#v", result.SourceMetadata)
	}
}

func loadCatalogFixture(t *testing.T, content string) *Catalog {
	t.Helper()

	dir := t.TempDir()
	path := filepath.Join(dir, "licenses.json")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write temp catalog: %v", err)
	}

	cat, err := Load(path)
	if err != nil {
		t.Fatalf("load catalog: %v", err)
	}
	return cat
}

func assertLoadErrorContains(t *testing.T, content string, want string) {
	t.Helper()

	dir := t.TempDir()
	path := filepath.Join(dir, "licenses.json")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write temp catalog: %v", err)
	}

	_, err := Load(path)
	if err == nil {
		t.Fatalf("expected load error containing %q", want)
	}
	if got := err.Error(); !strings.Contains(got, want) {
		t.Fatalf("load error %q does not contain %q", got, want)
	}
}
