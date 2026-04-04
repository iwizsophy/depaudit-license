package inventory

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestDocumentJSONShapeOmitsEmptyOptionalFieldsExceptValueStructProvenance(t *testing.T) {
	t.Parallel()

	doc := Document{
		Packages: []Package{{
			Ecosystem:      "npm",
			Project:        "web",
			Name:           "react",
			Version:        "19.2.0",
			DependencyType: "direct",
			RawLicense:     "MIT",
			LicenseKey:     "MIT",
		}},
	}

	payload, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("marshal document: %v", err)
	}
	text := string(payload)
	for _, unwanted := range []string{`"sources"`, `"conflicts"`, `"sourceIds"`, `"fieldOrigins"`, `"conflictFields"`} {
		if strings.Contains(text, unwanted) {
			t.Fatalf("payload unexpectedly contains %s: %s", unwanted, text)
		}
	}
	for _, wanted := range []string{`"packages"`, `"provenance":{}`, `"ecosystem":"npm"`, `"name":"react"`, `"licenseKey":"MIT"`} {
		if !strings.Contains(text, wanted) {
			t.Fatalf("payload missing %s: %s", wanted, text)
		}
	}
}

func TestDocumentJSONShapeIncludesSharedModelContracts(t *testing.T) {
	t.Parallel()

	doc := Document{
		Sources: []Source{{
			ID:              "sbom-1",
			Kind:            "cyclonedx-json",
			Location:        "/work/app.json",
			DisplayLocation: "app.json",
		}},
		Packages: []Package{{
			Provenance: PackageProvenance{
				SourceIDs:      []string{"sbom-1"},
				FieldOrigins:   map[string]string{"licenseKey": "sbom-1"},
				ConflictFields: []string{"licenseKey"},
			},
			Ecosystem:           "npm",
			Project:             "web",
			Name:                "react",
			Version:             "19.2.0",
			PURL:                "pkg:npm/react@19.2.0",
			DependencyType:      "direct",
			HasRuntimeAssets:    true,
			RawLicense:          "MIT",
			LicenseKey:          "MIT",
			Repository:          "https://github.com/facebook/react",
			Homepage:            "https://react.dev",
			CopyrightHolder:     "Meta",
			CopyrightYear:       2024,
			MetadataSource:      "npm-registry",
			EmbeddedLicensePath: "LICENSE",
			EmbeddedLicenseText: "MIT text",
		}},
		Conflicts: []Conflict{{
			Identity: "pkg:npm/react@19.2.0",
			Field:    "licenseKey",
			Values: []ConflictValue{{
				SourceID: "sbom-1",
				Value:    "MIT",
			}},
		}},
	}

	payload, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("marshal document: %v", err)
	}

	var decoded map[string]any
	if err := json.Unmarshal(payload, &decoded); err != nil {
		t.Fatalf("unmarshal document: %v", err)
	}

	sources, ok := decoded["sources"].([]any)
	if !ok || len(sources) != 1 {
		t.Fatalf("sources = %#v", decoded["sources"])
	}
	packages, ok := decoded["packages"].([]any)
	if !ok || len(packages) != 1 {
		t.Fatalf("packages = %#v", decoded["packages"])
	}
	pkg, ok := packages[0].(map[string]any)
	if !ok {
		t.Fatalf("package = %#v", packages[0])
	}
	provenance, ok := pkg["provenance"].(map[string]any)
	if !ok {
		t.Fatalf("provenance = %#v", pkg["provenance"])
	}
	if sourceIDs, ok := provenance["sourceIds"].([]any); !ok || len(sourceIDs) != 1 || sourceIDs[0] != "sbom-1" {
		t.Fatalf("sourceIds = %#v", provenance["sourceIds"])
	}
	if fieldOrigins, ok := provenance["fieldOrigins"].(map[string]any); !ok || fieldOrigins["licenseKey"] != "sbom-1" {
		t.Fatalf("fieldOrigins = %#v", provenance["fieldOrigins"])
	}
	conflicts, ok := decoded["conflicts"].([]any)
	if !ok || len(conflicts) != 1 {
		t.Fatalf("conflicts = %#v", decoded["conflicts"])
	}
}
