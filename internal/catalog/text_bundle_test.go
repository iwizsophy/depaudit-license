package catalog

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestApplyTextBundleOverridesHumanFacingText(t *testing.T) {
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
      "names": [],
      "exact_urls": [],
      "url_prefixes": [],
      "contains": [],
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
      "color": "#718096",
      "risk_level": "unknown",
      "notice_template": "template"
    }
  ]
}`)

	bundle := loadTextBundleFixture(t, `{
  "locale": "ja",
  "licenses": [
    {
      "key": "MIT",
      "description": "mit desc",
      "obligations": ["notice"],
      "permissions": ["commercial"],
      "limitations": ["warranty"]
    },
    {
      "key": "Unknown",
      "description": "unknown desc",
      "obligations": ["review"],
      "permissions": ["unknown"],
      "limitations": ["unknown"]
    }
  ]
}`)

	localized, err := ApplyTextBundle(cat, bundle)
	if err != nil {
		t.Fatalf("apply text bundle: %v", err)
	}

	if localized.Lookup("MIT").Description != "mit desc" {
		t.Fatalf("description = %q", localized.Lookup("MIT").Description)
	}
}

func TestApplyTextBundleRejectsMissingAndExtraKeys(t *testing.T) {
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
      "names": [],
      "exact_urls": [],
      "url_prefixes": [],
      "contains": [],
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
      "color": "#718096",
      "risk_level": "unknown",
      "notice_template": "template"
    }
  ]
}`)

	bundle := loadTextBundleFixture(t, `{
  "locale": "ja",
  "licenses": [
    {
      "key": "Apache-2.0",
      "description": "apache desc",
      "obligations": ["notice"],
      "permissions": ["commercial"],
      "limitations": ["warranty"]
    }
  ]
}`)

	_, err := ApplyTextBundle(cat, bundle)
	if err == nil {
		t.Fatal("expected bundle application error")
	}
	if !strings.Contains(err.Error(), "missing keys") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestApplyTextBundleRejectsExtraKeysWhenCatalogCoverageIsComplete(t *testing.T) {
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
      "names": [],
      "exact_urls": [],
      "url_prefixes": [],
      "contains": [],
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
      "color": "#718096",
      "risk_level": "unknown",
      "notice_template": "template"
    }
  ]
}`)

	bundle := loadTextBundleFixture(t, `{
  "locale": "ja",
  "licenses": [
    {
      "key": "MIT",
      "description": "mit desc",
      "obligations": ["notice"],
      "permissions": ["commercial"],
      "limitations": ["warranty"]
    },
    {
      "key": "Unknown",
      "description": "unknown desc",
      "obligations": ["review"],
      "permissions": ["unknown"],
      "limitations": ["unknown"]
    },
    {
      "key": "Apache-2.0",
      "description": "apache desc",
      "obligations": ["notice"],
      "permissions": ["commercial"],
      "limitations": ["warranty"]
    }
  ]
}`)

	_, err := ApplyTextBundle(cat, bundle)
	if err == nil {
		t.Fatal("expected bundle application error")
	}
	if !strings.Contains(err.Error(), "defines unknown keys: Apache-2.0") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestLoadTextBundleRejectsInvalidDefinitions(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	cases := map[string]string{
		"missing-locale.json":      `{"licenses":[{"key":"MIT","description":"x","obligations":["n"],"permissions":["p"],"limitations":["l"]}]}`,
		"empty-licenses.json":      `{"locale":"ja","licenses":[]}`,
		"duplicate-keys.json":      `{"locale":"ja","licenses":[{"key":"MIT","description":"x","obligations":["n"],"permissions":["p"],"limitations":["l"]},{"key":"MIT","description":"y","obligations":["n"],"permissions":["p"],"limitations":["l"]}]}`,
		"missing-description.json": `{"locale":"ja","licenses":[{"key":"MIT","description":"","obligations":["n"],"permissions":["p"],"limitations":["l"]}]}`,
		"missing-obligations.json": `{"locale":"ja","licenses":[{"key":"MIT","description":"x","obligations":[],"permissions":["p"],"limitations":["l"]}]}`,
		"missing-permissions.json": `{"locale":"ja","licenses":[{"key":"MIT","description":"x","obligations":["n"],"permissions":[],"limitations":["l"]}]}`,
		"missing-limitations.json": `{"locale":"ja","licenses":[{"key":"MIT","description":"x","obligations":["n"],"permissions":["p"],"limitations":[]}]}`,
		"blank-key.json":           `{"locale":"ja","licenses":[{"key":" ","description":"x","obligations":["n"],"permissions":["p"],"limitations":["l"]}]}`,
	}

	for name, payload := range cases {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(payload), 0o644); err != nil {
			t.Fatalf("write bundle %s: %v", name, err)
		}
		if _, err := LoadTextBundle(path); err == nil {
			t.Fatalf("expected LoadTextBundle error for %s", name)
		}
	}
}

func TestLoadTextBundleBuildsByKeyWhilePreservingLocaleValue(t *testing.T) {
	t.Parallel()

	bundle := loadTextBundleFixture(t, `{
  "locale": " ja ",
  "licenses": [
    {
      "key": "MIT",
      "description": "mit desc",
      "obligations": ["notice"],
      "permissions": ["commercial"],
      "limitations": ["warranty"]
    }
  ]
}`)

	if bundle.Locale != " ja " {
		t.Fatalf("locale = %q", bundle.Locale)
	}
	if got := bundle.ByKey["MIT"].Description; got != "mit desc" {
		t.Fatalf("ByKey[MIT].Description = %q", got)
	}
}

func TestApplyTextBundleRejectsNilInputsAndPreservesFallback(t *testing.T) {
	t.Parallel()

	if _, err := ApplyTextBundle(nil, &TextBundle{}); err == nil {
		t.Fatal("expected nil catalog error")
	}
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
      "names": [],
      "exact_urls": [],
      "url_prefixes": [],
      "contains": [],
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
      "color": "#718096",
      "risk_level": "unknown",
      "notice_template": "template"
    }
  ]
}`)
	if _, err := ApplyTextBundle(cat, nil); err == nil {
		t.Fatal("expected nil bundle error")
	}
	bundle := loadTextBundleFixture(t, `{
  "locale": "ja",
  "licenses": [
    {
      "key": "MIT",
      "description": "mit desc",
      "obligations": ["notice"],
      "permissions": ["commercial"],
      "limitations": ["warranty"]
    },
    {
      "key": "Unknown",
      "description": "unknown desc",
      "obligations": ["review"],
      "permissions": ["unknown"],
      "limitations": ["unknown"]
    }
  ]
}`)
	localized, err := ApplyTextBundle(cat, bundle)
	if err != nil {
		t.Fatalf("ApplyTextBundle: %v", err)
	}
	if localized.Fallback != cat.Fallback {
		t.Fatalf("fallback = %q", localized.Fallback)
	}
}

func TestApplyTextBundleClonesCatalogStructureAndTextSlices(t *testing.T) {
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
      "text_matchers": ["MIT License"],
      "text_match_threshold": 1,
      "description": "base desc",
      "obligations": ["base obligation"],
      "permissions": ["base permission"],
      "limitations": ["base limitation"],
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
      "description": "unknown base",
      "obligations": ["review"],
      "permissions": ["unknown"],
      "limitations": ["unknown"],
      "color": "#718096",
      "risk_level": "unknown",
      "notice_template": "template"
    }
  ]
}`)

	bundle := loadTextBundleFixture(t, `{
  "locale": "ja",
  "licenses": [
    {
      "key": "MIT",
      "description": "localized desc",
      "obligations": ["localized obligation"],
      "permissions": ["localized permission"],
      "limitations": ["localized limitation"]
    },
    {
      "key": "Unknown",
      "description": "localized unknown",
      "obligations": ["review"],
      "permissions": ["unknown"],
      "limitations": ["unknown"]
    }
  ]
}`)

	localized, err := ApplyTextBundle(cat, bundle)
	if err != nil {
		t.Fatalf("ApplyTextBundle: %v", err)
	}

	if localized == cat {
		t.Fatal("expected cloned catalog")
	}
	if &localized.contains[0] == &cat.contains[0] {
		t.Fatal("expected contains slice to be cloned")
	}
	if &localized.text[0] == &cat.text[0] {
		t.Fatal("expected text matcher slice to be cloned")
	}
	localized.exact["mit"] = "Unknown"
	if got := cat.exact["mit"]; got != "MIT" {
		t.Fatalf("original exact map mutated: %q", got)
	}

	localizedMIT := localized.Definitions["MIT"]
	localizedMIT.Obligations[0] = "mutated obligation"
	localizedMIT.Permissions[0] = "mutated permission"
	localizedMIT.Limitations[0] = "mutated limitation"

	originalMIT := cat.Definitions["MIT"]
	if originalMIT.Description != "base desc" {
		t.Fatalf("original description mutated: %q", originalMIT.Description)
	}
	if originalMIT.Obligations[0] != "base obligation" {
		t.Fatalf("original obligations mutated: %#v", originalMIT.Obligations)
	}
	if originalMIT.Permissions[0] != "base permission" {
		t.Fatalf("original permissions mutated: %#v", originalMIT.Permissions)
	}
	if originalMIT.Limitations[0] != "base limitation" {
		t.Fatalf("original limitations mutated: %#v", originalMIT.Limitations)
	}
}

func loadTextBundleFixture(t *testing.T, content string) *TextBundle {
	t.Helper()

	dir := t.TempDir()
	path := filepath.Join(dir, "license-texts.ja.json")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write temp bundle: %v", err)
	}

	bundle, err := LoadTextBundle(path)
	if err != nil {
		t.Fatalf("load text bundle: %v", err)
	}
	return bundle
}
