package merge

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"depaudit-license/internal/inventory"
)

func TestDocumentsMergesRepositoryAndSBOMPackages(t *testing.T) {
	t.Parallel()

	docA := loadFixtureDocument(t, "repo-scan.json")
	docB := loadFixtureDocument(t, "cyclonedx.json")

	merged := Documents(Config{}, docA, docB)
	if err := ValidateDocument(merged); err != nil {
		t.Fatalf("validate merged document: %v", err)
	}
	if len(merged.Packages) != 2 {
		t.Fatalf("expected 2 merged packages, got %d", len(merged.Packages))
	}

	react := findPackage(t, merged.Packages, "react")
	if len(react.Provenance.SourceIDs) != 2 {
		t.Fatalf("react source ids = %#v", react.Provenance.SourceIDs)
	}
	if react.Repository != "https://github.com/facebook/react.git" {
		t.Fatalf("react repository = %q", react.Repository)
	}
	if react.EmbeddedLicenseText != "MIT License" {
		t.Fatalf("react embedded license text = %q", react.EmbeddedLicenseText)
	}
	if react.Provenance.FieldOrigins["repository"] != "repo-scan" {
		t.Fatalf("repository origin = %q", react.Provenance.FieldOrigins["repository"])
	}
	if react.Provenance.FieldOrigins["embeddedLicenseText"] != "cyclonedx" {
		t.Fatalf("embedded text origin = %q", react.Provenance.FieldOrigins["embeddedLicenseText"])
	}
	if len(merged.Conflicts) != 0 {
		t.Fatalf("unexpected conflicts: %#v", merged.Conflicts)
	}
}

func TestDocumentsKeepConflictsWhenFieldsDisagree(t *testing.T) {
	t.Parallel()

	docA := loadFixtureDocument(t, "cyclonedx.json")
	docB := loadFixtureDocument(t, "spdx-conflict.json")

	merged := Documents(Config{}, docA, docB)
	if len(merged.Conflicts) == 0 {
		t.Fatal("expected merge conflicts")
	}
	react := findPackage(t, merged.Packages, "react")
	if len(react.Provenance.ConflictFields) == 0 {
		t.Fatal("expected package conflict fields")
	}
}

func TestMergePackageHelperBranches(t *testing.T) {
	t.Parallel()

	base := inventory.Package{
		Ecosystem:        "node",
		Name:             "react",
		Version:          "19.2.4",
		MetadataSource:   "repo-scan",
		HasRuntimeAssets: false,
		Provenance: inventory.PackageProvenance{
			SourceIDs:      []string{"repo"},
			FieldOrigins:   map[string]string{"repository": "repo"},
			ConflictFields: []string{},
		},
	}
	incoming := inventory.Package{
		Ecosystem:        "node",
		Name:             "react",
		Version:          "19.2.4",
		Repository:       "https://github.com/facebook/react",
		CopyrightYear:    2024,
		MetadataSource:   "sbom",
		HasRuntimeAssets: true,
		Provenance: inventory.PackageProvenance{
			SourceIDs: []string{"sbom"},
		},
	}

	merged, conflicts := mergePackage(base, incoming)
	if len(conflicts) != 0 {
		t.Fatalf("unexpected conflicts: %#v", conflicts)
	}
	if merged.Repository != "https://github.com/facebook/react" {
		t.Fatalf("repository = %q", merged.Repository)
	}
	if merged.CopyrightYear != 2024 || !merged.HasRuntimeAssets {
		t.Fatalf("merged package = %#v", merged)
	}
	if merged.MetadataSource != "merged" {
		t.Fatalf("metadata source = %q", merged.MetadataSource)
	}
	if merged.Provenance.FieldOrigins["repository"] != "sbom" || merged.Provenance.FieldOrigins["copyrightYear"] != "sbom" {
		t.Fatalf("field origins = %#v", merged.Provenance.FieldOrigins)
	}
	if !slices.Equal(merged.Provenance.SourceIDs, []string{"repo", "sbom"}) {
		t.Fatalf("source ids = %#v", merged.Provenance.SourceIDs)
	}

	base.CopyrightYear = 2020
	base.MetadataSource = "repo-scan"
	base.Provenance.SourceIDs = []string{"repo"}
	incoming.CopyrightYear = 2024
	incoming.MetadataSource = ""
	incoming.Provenance.SourceIDs = []string{"sbom"}

	merged, conflicts = mergePackage(base, incoming)
	if len(conflicts) != 1 || conflicts[0].Field != "copyrightYear" {
		t.Fatalf("copyright conflict = %#v", conflicts)
	}
	if !slices.Contains(merged.Provenance.ConflictFields, "copyrightYear") {
		t.Fatalf("conflict fields = %#v", merged.Provenance.ConflictFields)
	}
	if merged.MetadataSource != "repo-scan" {
		t.Fatalf("metadata source should preserve base when incoming empty: %q", merged.MetadataSource)
	}
}

func TestMergeMetadataSourceHelperBranches(t *testing.T) {
	t.Parallel()

	if got := mergeMetadataSource("", "node-modules"); got != "node-modules" {
		t.Fatalf("mergeMetadataSource empty base = %q", got)
	}
	if got := mergeMetadataSource("repo-scan", ""); got != "repo-scan" {
		t.Fatalf("mergeMetadataSource empty incoming = %q", got)
	}
	if got := mergeMetadataSource("repo-scan", "repo-scan"); got != "repo-scan" {
		t.Fatalf("mergeMetadataSource same = %q", got)
	}
	if got := mergeMetadataSource("repo-scan", "sbom"); got != "merged" {
		t.Fatalf("mergeMetadataSource merged = %q", got)
	}
}

func TestFindMergeTargetPrefersPURLAndFallsBackToUniqueSecondaryKey(t *testing.T) {
	t.Parallel()

	existing := []inventory.Package{
		{
			Ecosystem: "node",
			Project:   "web",
			Name:      "react",
			Version:   "18.2.0",
			PURL:      "pkg:npm/react@18.2.0",
		},
		{
			Ecosystem: "node",
			Project:   "client",
			Name:      "lodash",
			Version:   "4.17.21",
		},
	}

	primary := map[string]int{
		primaryKey(existing[0]): 0,
		primaryKey(existing[1]): 1,
	}
	secondary := map[string][]int{
		secondaryKey(existing[0]): {0},
		secondaryKey(existing[1]): {1},
	}

	if idx, ok := findMergeTarget(inventory.Package{
		Ecosystem: "node",
		Project:   "other-project",
		Name:      "react",
		Version:   "18.2.0",
		PURL:      "pkg:npm/react@18.2.0",
	}, existing, primary, secondary); !ok || idx != 0 {
		t.Fatalf("purl precedence target = (%d, %v)", idx, ok)
	}

	if idx, ok := findMergeTarget(inventory.Package{
		Ecosystem: "node",
		Project:   "other-project",
		Name:      "lodash",
		Version:   "4.17.21",
	}, existing, primary, secondary); !ok || idx != 1 {
		t.Fatalf("secondary precedence target = (%d, %v)", idx, ok)
	}

	secondary[secondaryKey(inventory.Package{
		Ecosystem: "node",
		Name:      "dupe",
		Version:   "1.0.0",
	})] = []int{0, 1}
	if _, ok := findMergeTarget(inventory.Package{
		Ecosystem: "node",
		Name:      "dupe",
		Version:   "1.0.0",
	}, existing, primary, secondary); ok {
		t.Fatal("expected ambiguous secondary key to be rejected")
	}
}

func TestMergeStringFieldSetsOriginWhenValuesMatch(t *testing.T) {
	t.Parallel()

	target := "https://react.dev"
	provenance := inventory.PackageProvenance{}
	base := inventory.Package{
		Provenance: inventory.PackageProvenance{SourceIDs: []string{"repo-scan"}},
	}
	incoming := inventory.Package{
		Provenance: inventory.PackageProvenance{SourceIDs: []string{"sbom"}},
	}

	conflicts := mergeStringField(
		"node\x00web\x00react\x0018.2.0",
		"homepage",
		&target,
		&provenance,
		"https://react.dev",
		"https://react.dev",
		base,
		incoming,
	)
	if len(conflicts) != 0 {
		t.Fatalf("unexpected conflicts: %#v", conflicts)
	}
	if target != "https://react.dev" {
		t.Fatalf("target = %q", target)
	}
	if provenance.FieldOrigins["homepage"] != "repo-scan" {
		t.Fatalf("field origins = %#v", provenance.FieldOrigins)
	}
}

func TestDocumentsSortsSourcesAndConflicts(t *testing.T) {
	t.Parallel()

	docA := inventory.Document{
		Sources: []inventory.Source{
			{ID: "z-source"},
			{ID: "a-source"},
		},
		Packages: []inventory.Package{{
			Ecosystem: "node",
			Project:   "web",
			Name:      "react",
			Version:   "18.2.0",
			Homepage:  "https://react.dev",
			Provenance: inventory.PackageProvenance{
				SourceIDs: []string{"z-source"},
			},
		}},
	}
	docB := inventory.Document{
		Sources: []inventory.Source{
			{ID: "m-source"},
		},
		Packages: []inventory.Package{{
			Ecosystem: "node",
			Project:   "web",
			Name:      "react",
			Version:   "18.2.0",
			Homepage:  "https://example.test/react",
			Provenance: inventory.PackageProvenance{
				SourceIDs: []string{"m-source"},
			},
		}},
	}

	merged := Documents(Config{}, docA, docB)
	if got := []string{merged.Sources[0].ID, merged.Sources[1].ID, merged.Sources[2].ID}; !slices.Equal(got, []string{"a-source", "m-source", "z-source"}) {
		t.Fatalf("sources = %#v", got)
	}
	if len(merged.Conflicts) != 1 || merged.Conflicts[0].Field != "homepage" {
		t.Fatalf("conflicts = %#v", merged.Conflicts)
	}
}

func loadFixtureDocument(t *testing.T, name string) inventory.Document {
	t.Helper()

	payload, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("read fixture %s: %v", name, err)
	}
	var doc inventory.Document
	if err := json.Unmarshal(payload, &doc); err != nil {
		t.Fatalf("parse fixture %s: %v", name, err)
	}
	return doc
}

func findPackage(t *testing.T, packages []inventory.Package, name string) inventory.Package {
	t.Helper()
	for _, pkg := range packages {
		if pkg.Name == name {
			return pkg
		}
	}
	t.Fatalf("package %q not found", name)
	return inventory.Package{}
}
