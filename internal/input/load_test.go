package input

import (
	"os"
	"path/filepath"
	"slices"
	"testing"

	"depaudit-license/internal/catalog"
	"depaudit-license/internal/enrich"
	"depaudit-license/internal/inventory"
)

func repoScanFixtureRoot() string {
	return filepath.Join("..", "ci", "testdata", "repo")
}

func TestLoadCycloneDXInput(t *testing.T) {
	t.Parallel()

	cat, err := catalog.Load(filepath.Join("..", "..", "configs", "licenses.json"))
	if err != nil {
		t.Fatalf("load catalog: %v", err)
	}

	result, err := Load(LoadConfig{
		Sources: []SourceSpec{{
			ID:       "cyclonedx",
			Kind:     InputKindCycloneDXJSON,
			Location: filepath.Join("..", "sbom", "testdata", "cyclonedx", "app.json"),
		}},
		Catalog: cat,
	})
	if err != nil {
		t.Fatalf("load input: %v", err)
	}
	if result.InputKind != InputKindCycloneDXJSON {
		t.Fatalf("input kind = %q", result.InputKind)
	}
	if result.Root != filepath.Join("..", "sbom", "testdata", "cyclonedx", "app.json") {
		t.Fatalf("root = %q", result.Root)
	}
	if len(result.Document.Packages) != 3 {
		t.Fatalf("packages = %d", len(result.Document.Packages))
	}
	if len(result.Document.Sources) != 1 {
		t.Fatalf("sources = %d", len(result.Document.Sources))
	}
	if result.Document.Sources[0].DisplayLocation != filepath.Join("..", "sbom", "testdata", "cyclonedx", "app.json") {
		t.Fatalf("display location = %q", result.Document.Sources[0].DisplayLocation)
	}
}

func TestLoadRejectsEmptySourceList(t *testing.T) {
	t.Parallel()

	if _, err := Load(LoadConfig{}); err == nil {
		t.Fatal("expected empty source list error")
	}
}

func TestLoadRejectsUnknownInputKind(t *testing.T) {
	t.Parallel()

	if _, err := Load(LoadConfig{Sources: []SourceSpec{{Kind: "unknown", Location: "."}}}); err == nil {
		t.Fatal("expected input kind error")
	}
}

func TestLoadSPDXInput(t *testing.T) {
	t.Parallel()

	cat, err := catalog.Load(filepath.Join("..", "..", "configs", "licenses.json"))
	if err != nil {
		t.Fatalf("load catalog: %v", err)
	}

	result, err := Load(LoadConfig{
		Sources: []SourceSpec{{
			ID:       "spdx",
			Kind:     InputKindSPDXJSON,
			Location: filepath.Join("..", "sbom", "testdata", "spdx", "app.json"),
		}},
		Catalog: cat,
	})
	if err != nil {
		t.Fatalf("load input: %v", err)
	}
	if result.InputKind != InputKindSPDXJSON {
		t.Fatalf("input kind = %q", result.InputKind)
	}
	if len(result.Document.Packages) != 3 {
		t.Fatalf("packages = %d", len(result.Document.Packages))
	}
}

func TestLoadMergesMultipleSources(t *testing.T) {
	t.Parallel()

	cat, err := catalog.Load(filepath.Join("..", "..", "configs", "licenses.json"))
	if err != nil {
		t.Fatalf("load catalog: %v", err)
	}

	result, err := Load(LoadConfig{
		Sources: []SourceSpec{
			{ID: "repo-scan", Kind: InputKindRepositoryScan, Location: repoScanFixtureRoot()},
			{ID: "cyclonedx", Kind: InputKindCycloneDXJSON, Location: filepath.Join("..", "sbom", "testdata", "cyclonedx", "app.json")},
		},
		Catalog: cat,
	})
	if err != nil {
		t.Fatalf("load inputs: %v", err)
	}
	if result.InputKind != InputKindMultiSource {
		t.Fatalf("input kind = %q", result.InputKind)
	}
	if len(result.Document.Sources) != 2 {
		t.Fatalf("sources = %d", len(result.Document.Sources))
	}
}

func TestLoadMergesRepositoryScanAndSPDXSources(t *testing.T) {
	t.Parallel()

	cat, err := catalog.Load(filepath.Join("..", "..", "configs", "licenses.json"))
	if err != nil {
		t.Fatalf("load catalog: %v", err)
	}

	result, err := Load(LoadConfig{
		Sources: []SourceSpec{
			{ID: "repo-scan", Kind: InputKindRepositoryScan, Location: repoScanFixtureRoot()},
			{ID: "spdx", Kind: InputKindSPDXJSON, Location: filepath.Join("..", "sbom", "testdata", "spdx", "app.json")},
		},
		Catalog: cat,
	})
	if err != nil {
		t.Fatalf("load inputs: %v", err)
	}
	result.Document, err = enrich.Apply(enrich.Config{
		Catalog:         cat,
		RepositoryRoots: []string{repoScanFixtureRoot()},
	}, result.Document)
	if err != nil {
		t.Fatalf("enrich inputs: %v", err)
	}

	react := findPackage(t, result.Document.Packages, "react")
	if !slices.Equal(react.Provenance.SourceIDs, []string{"repo-scan", "spdx"}) {
		t.Fatalf("react source ids = %#v", react.Provenance.SourceIDs)
	}
	if react.Homepage != "https://react.dev/" {
		t.Fatalf("react homepage = %q", react.Homepage)
	}
	if react.Provenance.FieldOrigins["homepage"] != "spdx" {
		t.Fatalf("homepage origin = %q", react.Provenance.FieldOrigins["homepage"])
	}
	if react.Repository != "" {
		t.Fatalf("react repository = %q", react.Repository)
	}
	if !slices.Contains(react.Provenance.ConflictFields, "project") {
		t.Fatalf("react conflict fields = %#v", react.Provenance.ConflictFields)
	}
	if len(result.Document.Conflicts) == 0 {
		t.Fatal("expected hybrid conflicts")
	}
}

func TestLoadUsesGeneratedSourceIDAndDisplayLocation(t *testing.T) {
	t.Parallel()

	cat, err := catalog.Load(filepath.Join("..", "..", "configs", "licenses.json"))
	if err != nil {
		t.Fatalf("load catalog: %v", err)
	}

	result, err := Load(LoadConfig{
		Sources: []SourceSpec{{
			Kind:            "  " + InputKindCycloneDXJSON + "  ",
			Location:        filepath.Join("..", "sbom", "testdata", "cyclonedx", "app.json"),
			DisplayLocation: "  fixture://cyclonedx-app  ",
		}},
		Catalog: cat,
	})
	if err != nil {
		t.Fatalf("load input: %v", err)
	}

	if result.Root != "fixture://cyclonedx-app" {
		t.Fatalf("root = %q", result.Root)
	}
	if got := result.Document.Sources[0].ID; got != InputKindCycloneDXJSON+"-1" {
		t.Fatalf("source id = %q", got)
	}
	if got := result.Document.Sources[0].DisplayLocation; got != "fixture://cyclonedx-app" {
		t.Fatalf("display location = %q", got)
	}
}

func TestSourceDisplayLocationFallsBackToLocation(t *testing.T) {
	t.Parallel()

	got := sourceDisplayLocation(SourceSpec{
		Location:        "  /tmp/report.json  ",
		DisplayLocation: "   ",
	})
	if got != "/tmp/report.json" {
		t.Fatalf("display location = %q", got)
	}
}

func TestLoadSourceErrorBranches(t *testing.T) {
	t.Parallel()

	if _, _, err := loadSource(LoadConfig{}, SourceSpec{
		Kind:     InputKindRepositoryScan,
		Location: filepath.Join("..", "..", "missing-root"),
	}, 0); err == nil {
		t.Fatal("expected repository scan error")
	}

	dir := t.TempDir()
	cdxPath := filepath.Join(dir, "broken.cdx.json")
	if err := os.WriteFile(cdxPath, []byte("{"), 0o644); err != nil {
		t.Fatalf("write broken cdx: %v", err)
	}
	if _, _, err := loadSource(LoadConfig{}, SourceSpec{
		Kind:     InputKindCycloneDXJSON,
		Location: cdxPath,
	}, 1); err == nil {
		t.Fatal("expected CycloneDX parse error")
	}

	spdxPath := filepath.Join(dir, "broken.spdx.json")
	if err := os.WriteFile(spdxPath, []byte("{"), 0o644); err != nil {
		t.Fatalf("write broken spdx: %v", err)
	}
	if _, _, err := loadSource(LoadConfig{}, SourceSpec{
		Kind:     InputKindSPDXJSON,
		Location: spdxPath,
	}, 2); err == nil {
		t.Fatal("expected SPDX parse error")
	}
}

func TestLoadSourceRepositoryScanGeneratesSourceID(t *testing.T) {
	t.Parallel()

	document, display, err := loadSource(LoadConfig{}, SourceSpec{
		Kind:            " " + InputKindRepositoryScan + " ",
		Location:        repoScanFixtureRoot(),
		DisplayLocation: " repo://fixture ",
	}, 1)
	if err != nil {
		t.Fatalf("loadSource repository-scan: %v", err)
	}
	if display != "repo://fixture" {
		t.Fatalf("display = %q", display)
	}
	if len(document.Sources) != 1 || document.Sources[0].ID != InputKindRepositoryScan+"-2" {
		t.Fatalf("sources = %#v", document.Sources)
	}
}

func TestLoadRejectsMergedDocumentWithDuplicateSourceIDs(t *testing.T) {
	t.Parallel()

	cat, err := catalog.Load(filepath.Join("..", "..", "configs", "licenses.json"))
	if err != nil {
		t.Fatalf("load catalog: %v", err)
	}

	_, err = Load(LoadConfig{
		Sources: []SourceSpec{
			{ID: "shared", Kind: InputKindCycloneDXJSON, Location: filepath.Join("..", "sbom", "testdata", "cyclonedx", "app.json")},
			{ID: "shared", Kind: InputKindSPDXJSON, Location: filepath.Join("..", "sbom", "testdata", "spdx", "app.json")},
		},
		Catalog: cat,
	})
	if err == nil {
		t.Fatal("expected duplicate source id validation error")
	}
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
