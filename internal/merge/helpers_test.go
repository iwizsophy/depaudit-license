package merge

import (
	"testing"

	"depaudit-license/internal/inventory"
)

func TestNewSourceAndSingleSourceDocumentSeedProvenance(t *testing.T) {
	t.Parallel()

	source := NewSource("repo", "repository-scan", "/workspace/repo", ".")
	doc := SingleSourceDocument(source, []inventory.Package{{
		Ecosystem:      "node",
		Project:        "web",
		Name:           "react",
		Version:        "19.2.4",
		DependencyType: "dependency",
		LicenseKey:     "MIT",
		Repository:     "https://github.com/facebook/react",
	}})

	if doc.Sources[0].DisplayLocation != "." {
		t.Fatalf("display location = %q", doc.Sources[0].DisplayLocation)
	}
	pkg := doc.Packages[0]
	if len(pkg.Provenance.SourceIDs) != 1 || pkg.Provenance.SourceIDs[0] != "repo" {
		t.Fatalf("source ids = %#v", pkg.Provenance.SourceIDs)
	}
	if pkg.Provenance.FieldOrigins["repository"] != "repo" {
		t.Fatalf("field origins = %#v", pkg.Provenance.FieldOrigins)
	}
}

func TestValidateDocumentRejectsMissingAndDuplicateSources(t *testing.T) {
	t.Parallel()

	err := ValidateDocument(inventory.Document{
		Sources: []inventory.Source{{ID: ""}},
	})
	if err == nil {
		t.Fatal("expected empty source id error")
	}

	err = ValidateDocument(inventory.Document{
		Sources: []inventory.Source{{ID: "a"}, {ID: "a"}},
	})
	if err == nil {
		t.Fatal("expected duplicate source error")
	}

	err = ValidateDocument(inventory.Document{
		Sources:  []inventory.Source{{ID: "repo"}},
		Packages: []inventory.Package{{Name: "react", Provenance: inventory.PackageProvenance{SourceIDs: []string{"missing"}}}},
	})
	if err == nil {
		t.Fatal("expected missing source error")
	}
}

func TestMergeMetadataSourceAndHelpers(t *testing.T) {
	t.Parallel()

	if got := mergeMetadataSource("", "spdx"); got != "spdx" {
		t.Fatalf("mergeMetadataSource empty = %q", got)
	}
	if got := mergeMetadataSource("spdx", "node-modules"); got != "merged" {
		t.Fatalf("mergeMetadataSource merged = %q", got)
	}
	if got := firstSource(nil); got != "" {
		t.Fatalf("firstSource nil = %q", got)
	}

	prov := inventory.PackageProvenance{}
	ensurePackageProvenance(&prov)
	if prov.FieldOrigins == nil {
		t.Fatal("expected field origins map")
	}
}

func TestMergeHelpersCoverTargetSelectionAndOrigins(t *testing.T) {
	t.Parallel()

	existing := []inventory.Package{
		{Ecosystem: "node", Project: "web", Name: "react", Version: "1.0.0", PURL: "pkg:npm/react@1.0.0"},
		{Ecosystem: "node", Project: "admin", Name: "shared", Version: "2.0.0"},
	}
	primary := map[string]int{primaryKey(existing[0]): 0}
	secondary := map[string][]int{
		secondaryKey(existing[1]): {1},
	}

	if idx, ok := findMergeTarget(inventory.Package{PURL: "pkg:npm/react@1.0.0"}, existing, primary, secondary); !ok || idx != 0 {
		t.Fatalf("expected purl merge target, got %d %v", idx, ok)
	}
	if idx, ok := findMergeTarget(inventory.Package{Ecosystem: "node", Name: "shared", Version: "2.0.0"}, existing, primary, secondary); !ok || idx != 1 {
		t.Fatalf("expected secondary merge target, got %d %v", idx, ok)
	}
	if _, ok := findMergeTarget(inventory.Package{Ecosystem: "node", Name: "missing", Version: "1.0.0"}, existing, primary, secondary); ok {
		t.Fatal("expected no merge target")
	}

	pkg := normalizePackage(inventory.Package{
		Provenance: inventory.PackageProvenance{
			SourceIDs:      []string{" b ", "", "a", "a"},
			ConflictFields: []string{" version ", "", "name"},
			FieldOrigins:   map[string]string{"name": " repo "},
		},
		Ecosystem:      " node ",
		Project:        " web ",
		Name:           " react ",
		Version:        " 1.0.0 ",
		DependencyType: " dependency ",
	})
	if got := pkg.Provenance.SourceIDs; len(got) != 2 || got[0] != "a" || got[1] != "b" {
		t.Fatalf("source ids = %#v", got)
	}
	if got := pkg.Provenance.ConflictFields; len(got) != 2 || got[0] != "name" || got[1] != "version" {
		t.Fatalf("conflict fields = %#v", got)
	}
	if pkg.Provenance.FieldOrigins["name"] != "repo" || pkg.Ecosystem != "node" || pkg.Project != "web" || pkg.Name != "react" || pkg.Version != "1.0.0" {
		t.Fatalf("normalized package = %#v", pkg)
	}

	if got := uniqueSorted([]string{" b ", "", "a", "b"}); len(got) != 2 || got[0] != "a" || got[1] != "b" {
		t.Fatalf("uniqueSorted = %#v", got)
	}
}

func TestMergeStringFieldAndSeedingHelpers(t *testing.T) {
	t.Parallel()

	target := ""
	prov := inventory.PackageProvenance{}
	conflicts := mergeStringField("pkg:key", "repository", &target, &prov, "", "https://example.test/repo", inventory.Package{}, inventory.Package{
		Provenance: inventory.PackageProvenance{SourceIDs: []string{"incoming"}},
	})
	if len(conflicts) != 0 || target != "https://example.test/repo" || prov.FieldOrigins["repository"] != "incoming" {
		t.Fatalf("fill branch = %#v %#v %q", conflicts, prov, target)
	}

	target = "same"
	prov = inventory.PackageProvenance{FieldOrigins: map[string]string{}}
	conflicts = mergeStringField("pkg:key", "repository", &target, &prov, "same", "same", inventory.Package{
		Provenance: inventory.PackageProvenance{SourceIDs: []string{"base"}},
	}, inventory.Package{
		Provenance: inventory.PackageProvenance{SourceIDs: []string{"incoming"}},
	})
	if len(conflicts) != 0 || prov.FieldOrigins["repository"] != "base" {
		t.Fatalf("equal branch = %#v %#v", conflicts, prov)
	}

	target = "left"
	prov = inventory.PackageProvenance{}
	conflicts = mergeStringField("pkg:key", "repository", &target, &prov, "left", "right", inventory.Package{
		Provenance: inventory.PackageProvenance{SourceIDs: []string{"base"}},
	}, inventory.Package{
		Provenance: inventory.PackageProvenance{SourceIDs: []string{"incoming"}},
	})
	if len(conflicts) != 1 || conflicts[0].Field != "repository" || len(prov.ConflictFields) != 1 || prov.ConflictFields[0] != "repository" {
		t.Fatalf("conflict branch = %#v %#v", conflicts, prov)
	}

	pkg := inventory.Package{
		Ecosystem:      "node",
		Name:           "react",
		Version:        "1.0.0",
		Repository:     "https://example.test/repo",
		CopyrightYear:  2026,
		MetadataSource: "sbom",
		Provenance:     inventory.PackageProvenance{},
	}
	ensureFieldOrigins(&pkg)
	seedFieldOrigins(&pkg, "repo")
	if pkg.Provenance.FieldOrigins["repository"] != "repo" || pkg.Provenance.FieldOrigins["copyrightYear"] != "repo" || pkg.Provenance.FieldOrigins["metadataSource"] != "repo" {
		t.Fatalf("seeded field origins = %#v", pkg.Provenance.FieldOrigins)
	}

	prov = inventory.PackageProvenance{}
	setFieldOrigin(&prov, "repository", "")
	if len(prov.FieldOrigins) != 0 {
		t.Fatalf("expected empty origin map, got %#v", prov.FieldOrigins)
	}
}

func TestSingleSourceDocumentClonesDiagnostics(t *testing.T) {
	t.Parallel()

	source := NewSource("repo", "repository-scan", "/workspace/repo", ".")
	inputDiagnostic := inventory.Diagnostic{
		SourceID:          "repo",
		RuleID:            "omit-analyzer-subgraph",
		Code:              "subgraph-exclude-applied",
		Severity:          "info",
		Message:           "applied",
		MatchedRoots:      []string{"Analyzer.Core/1.0.0"},
		RemovedPackages:   []string{"Analyzer.Core/1.0.0"},
		PreservedPackages: []string{"Shared.Lib/1.0.0"},
	}

	doc := SingleSourceDocument(source, nil, inputDiagnostic)
	if len(doc.Diagnostics) != 1 {
		t.Fatalf("diagnostics = %#v", doc.Diagnostics)
	}

	doc.Diagnostics[0].MatchedRoots[0] = "mutated"
	doc.Diagnostics[0].RemovedPackages[0] = "mutated"
	doc.Diagnostics[0].PreservedPackages[0] = "mutated"
	if inputDiagnostic.MatchedRoots[0] != "Analyzer.Core/1.0.0" || inputDiagnostic.RemovedPackages[0] != "Analyzer.Core/1.0.0" || inputDiagnostic.PreservedPackages[0] != "Shared.Lib/1.0.0" {
		t.Fatalf("input diagnostic mutated = %#v", inputDiagnostic)
	}
}

func TestValidateDocumentAndDocumentsHandleDiagnostics(t *testing.T) {
	t.Parallel()

	docA := inventory.Document{
		Sources: []inventory.Source{{ID: "b"}},
		Diagnostics: []inventory.Diagnostic{{
			SourceID: "b",
			RuleID:   "rule-b",
			Code:     "diag-b",
			Message:  "b",
		}},
	}
	docB := inventory.Document{
		Sources: []inventory.Source{{ID: "a"}},
		Diagnostics: []inventory.Diagnostic{
			{
				SourceID: "a",
				RuleID:   "rule-a",
				Code:     "diag-a",
				Message:  "a",
			},
			{
				Code:    "diag-no-source",
				Message: "no source id is allowed",
			},
		},
	}

	merged := Documents(Config{}, docA, docB)
	if len(merged.Diagnostics) != 3 {
		t.Fatalf("diagnostics = %#v", merged.Diagnostics)
	}
	if got := []string{merged.Diagnostics[0].Code, merged.Diagnostics[1].Code, merged.Diagnostics[2].Code}; got[0] != "diag-no-source" || got[1] != "diag-a" || got[2] != "diag-b" {
		t.Fatalf("sorted diagnostics = %#v", got)
	}

	merged.Diagnostics[0].Message = "mutated"
	if docB.Diagnostics[0].Message != "a" {
		t.Fatalf("source diagnostic mutated = %#v", docB.Diagnostics)
	}

	if err := ValidateDocument(merged); err != nil {
		t.Fatalf("ValidateDocument merged diagnostics: %v", err)
	}
	err := ValidateDocument(inventory.Document{
		Sources: []inventory.Source{{ID: "repo"}},
		Diagnostics: []inventory.Diagnostic{{
			SourceID: "missing",
			Code:     "diag",
			Message:  "missing source",
		}},
	})
	if err == nil {
		t.Fatal("expected missing diagnostic source error")
	}
}
