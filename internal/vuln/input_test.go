package vuln

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"depaudit-license/internal/inventory"
)

func TestBuildAssessmentInputUsesMergedInventoryAsSingleSourceOfTruth(t *testing.T) {
	t.Parallel()

	doc := loadFixtureDocument(t, "merged-inventory.json")
	input, err := BuildAssessmentInput(doc)
	if err != nil {
		t.Fatalf("build assessment input: %v", err)
	}

	if input.SchemaVersion != InputSchemaVersion {
		t.Fatalf("schema version = %q", input.SchemaVersion)
	}
	if len(input.Sources) != 3 {
		t.Fatalf("sources = %d", len(input.Sources))
	}
	if findSourceRef(t, input.Sources, "repo-scan").Location != "/workspace/testdata" {
		t.Fatalf("source location = %q", findSourceRef(t, input.Sources, "repo-scan").Location)
	}
	if len(input.Packages) != 3 {
		t.Fatalf("packages = %d", len(input.Packages))
	}

	react := findPackageRef(t, input.Packages, "react")
	if react.PURL != "pkg:npm/react@19.2.4" {
		t.Fatalf("react purl = %q", react.PURL)
	}
	if react.Key != "pkg:npm/react@19.2.4" {
		t.Fatalf("react key = %q", react.Key)
	}
	if len(react.SourceIDs) != 3 {
		t.Fatalf("react source ids = %#v", react.SourceIDs)
	}
	if react.FieldOrigins["repository"] != "enrich:node-modules" {
		t.Fatalf("repository origin = %q", react.FieldOrigins["repository"])
	}
	if react.ConflictFields[0] != "project" {
		t.Fatalf("react conflict fields = %#v", react.ConflictFields)
	}

	custom := findPackageRef(t, input.Packages, "custom-lib")
	if custom.PURL != "pkg:generic/custom-lib@1.0.0" {
		t.Fatalf("custom purl = %q", custom.PURL)
	}
}

func TestAssessmentInputHelpersHandleEdgeCases(t *testing.T) {
	t.Parallel()

	if _, err := buildPackageRef(inventory.Package{}); err == nil {
		t.Fatal("expected missing package name error")
	}

	ref, err := buildPackageRef(inventory.Package{
		Ecosystem: " node ",
		Name:      " react ",
		Version:   " 19.2.4 ",
		Provenance: inventory.PackageProvenance{
			SourceIDs:      []string{"b", "a"},
			FieldOrigins:   map[string]string{"repository": " enrich:node "},
			ConflictFields: []string{"version", "name"},
			ArtifactResolution: &inventory.ArtifactResolution{
				Kind:           "remote-package-content",
				Detail:         "nuget-package-content",
				ReviewRequired: true,
				ReviewReason:   "local-package-manager-artifact-not-available",
			},
		},
	})
	if err != nil {
		t.Fatalf("buildPackageRef: %v", err)
	}
	if ref.Ecosystem != "node" {
		t.Fatalf("ecosystem = %q", ref.Ecosystem)
	}
	if len(ref.SourceIDs) != 2 || ref.SourceIDs[0] != "a" {
		t.Fatalf("source ids = %#v", ref.SourceIDs)
	}
	if ref.FieldOrigins["repository"] != "enrich:node" {
		t.Fatalf("field origins = %#v", ref.FieldOrigins)
	}
	if len(ref.ConflictFields) != 2 || ref.ConflictFields[0] != "name" {
		t.Fatalf("conflict fields = %#v", ref.ConflictFields)
	}
	if ref.ArtifactResolution == nil || ref.ArtifactResolution.Kind != "remote-package-content" || !ref.ArtifactResolution.ReviewRequired {
		t.Fatalf("artifact resolution = %#v", ref.ArtifactResolution)
	}

	aliases := aliasesForPackage(inventory.Package{
		Ecosystem: "node",
		Name:      "react",
		Version:   "19.2.4",
	}, "pkg:npm/react@19.2.4")
	if len(aliases) != 4 {
		t.Fatalf("aliases = %#v", aliases)
	}

	aliases = aliasesForPackage(inventory.Package{
		Ecosystem: " ",
		Name:      " custom ",
		Version:   " ",
	}, "")
	if len(aliases) != 2 || aliases[0] != ":custom" {
		t.Fatalf("fallback aliases = %#v", aliases)
	}

	if cloneStrings(nil) != nil {
		t.Fatal("expected nil cloneStrings for nil input")
	}
	if got := cloneStrings([]string{"b", "a"}); len(got) != 2 || got[0] != "a" {
		t.Fatalf("cloneStrings = %#v", got)
	}
	if cloneMap(nil) != nil {
		t.Fatal("expected nil cloneMap for nil input")
	}
	if got := cloneMap(map[string]string{"key": " value "}); got["key"] != "value" {
		t.Fatalf("cloneMap = %#v", got)
	}
	if got := uniqueSorted([]string{" b ", "", "a", "b", "a"}); len(got) != 2 || got[0] != "a" || got[1] != "b" {
		t.Fatalf("uniqueSorted = %#v", got)
	}
	if got := sourceLocationForDisplay(inventory.Source{DisplayLocation: " shown ", Location: "hidden"}); got != "shown" {
		t.Fatalf("display location = %q", got)
	}
	if got := sourceLocationForDisplay(inventory.Source{Location: " path "}); got != "path" {
		t.Fatalf("location fallback = %q", got)
	}
}

func loadFixtureDocument(t *testing.T, name string) inventory.Document {
	t.Helper()

	payload, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	var doc inventory.Document
	if err := json.Unmarshal(payload, &doc); err != nil {
		t.Fatalf("parse fixture: %v", err)
	}
	return doc
}

func findPackageRef(t *testing.T, packages []PackageRef, name string) PackageRef {
	t.Helper()
	for _, pkg := range packages {
		if pkg.Name == name {
			return pkg
		}
	}
	t.Fatalf("package %q not found", name)
	return PackageRef{}
}

func findSourceRef(t *testing.T, sources []SourceRef, id string) SourceRef {
	t.Helper()
	for _, source := range sources {
		if source.ID == id {
			return source
		}
	}
	t.Fatalf("source %q not found", id)
	return SourceRef{}
}
