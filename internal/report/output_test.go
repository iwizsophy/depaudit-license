package report

import (
	"encoding/json"
	"testing"

	"depaudit-license/internal/catalog"
	"depaudit-license/internal/inventory"
)

func TestBuildOutputWrapsViewWithSchemaAndProvenance(t *testing.T) {
	t.Parallel()

	view := View{
		GeneratedAt: "2026-04-02T00:00:00Z",
		Root:        ".",
		Packages: []inventory.Package{{
			Provenance: inventory.PackageProvenance{
				SourceIDs:      []string{"repo-scan", "cyclonedx"},
				FieldOrigins:   map[string]string{"repository": "repo-scan", "embeddedLicenseText": "cyclonedx"},
				ConflictFields: []string{"homepage"},
			},
			Ecosystem:           "node",
			Project:             "web",
			Name:                "react",
			Version:             "19.2.4",
			PURL:                "pkg:npm/react@19.2.4",
			DependencyType:      "dependency",
			RawLicense:          "MIT",
			LicenseKey:          "MIT",
			EmbeddedLicenseText: "MIT License",
		}},
	}
	output := BuildOutput(view, OutputConfig{
		InputKind: "repository-scan",
		CatalogSources: []catalog.SourceMetadata{
			{Kind: "file", Location: "D:\\repo\\configs\\licenses.json", DisplayLocation: "configs\\licenses.json", PinningMode: "implicit", ContentSHA256: "abc"},
			{Kind: "remote", Location: "https://example.test/licenses.json#sha256=deadbeef", DisplayLocation: "https://example.test/licenses.json#sha256=deadbeef", ResolvedURL: "https://example.test/licenses.json", PinningMode: "pinned", RequestedSHA256: "deadbeef", ContentSHA256: "beef", RetrievedAt: "2026-04-02T00:00:00Z"},
		},
		SelectedLocale:   "ja",
		EffectiveCatalog: json.RawMessage(`{"fallback":"Unknown","licenses":[]}`),
	})

	if output.SchemaVersion != JSONSchemaVersion {
		t.Fatalf("schema version = %q", output.SchemaVersion)
	}
	if output.Provenance.InputKind != "repository-scan" {
		t.Fatalf("input kind = %q", output.Provenance.InputKind)
	}
	if output.Provenance.SelectedLocale != "ja" {
		t.Fatalf("selected locale = %q", output.Provenance.SelectedLocale)
	}
	if len(output.Provenance.CatalogSources) != 2 {
		t.Fatalf("catalog source count = %d", len(output.Provenance.CatalogSources))
	}
	if output.Provenance.CatalogSources[0].Kind != "file" {
		t.Fatalf("first catalog source kind = %q", output.Provenance.CatalogSources[0].Kind)
	}
	if output.Provenance.CatalogSources[0].Location != "configs\\licenses.json" {
		t.Fatalf("first catalog source location = %q", output.Provenance.CatalogSources[0].Location)
	}
	if output.Provenance.CatalogSources[1].Kind != "remote" {
		t.Fatalf("second catalog source kind = %q", output.Provenance.CatalogSources[1].Kind)
	}
	if output.Provenance.CatalogSources[1].PinningMode != "pinned" {
		t.Fatalf("pinning mode = %q", output.Provenance.CatalogSources[1].PinningMode)
	}
	if string(output.Provenance.EffectiveCatalog) == "" {
		t.Fatal("expected effective catalog snapshot")
	}
	if output.Report.Root != view.Root {
		t.Fatalf("report root = %q", output.Report.Root)
	}
	if len(output.Report.Packages) != 1 {
		t.Fatalf("package count = %d", len(output.Report.Packages))
	}
	if output.Report.Packages[0].Provenance.FieldOrigins["repository"] != "repo-scan" {
		t.Fatalf("repository origin = %q", output.Report.Packages[0].Provenance.FieldOrigins["repository"])
	}
}

func TestBuildOutputNormalizesBlankInputKindAndCatalogDisplayLocation(t *testing.T) {
	t.Parallel()

	output := BuildOutput(View{}, OutputConfig{
		InputKind: "   ",
		CatalogSources: []catalog.SourceMetadata{
			{Kind: "file", Location: "D:\\repo\\configs\\licenses.json", DisplayLocation: "   "},
		},
		SelectedLocale: "  en  ",
	})

	if output.Provenance.InputKind != "repository-scan" {
		t.Fatalf("input kind = %q", output.Provenance.InputKind)
	}
	if output.Provenance.SelectedLocale != "en" {
		t.Fatalf("selected locale = %q", output.Provenance.SelectedLocale)
	}
	if len(output.Provenance.CatalogSources) != 1 {
		t.Fatalf("catalog source count = %d", len(output.Provenance.CatalogSources))
	}
	if output.Provenance.CatalogSources[0].Location != "D:\\repo\\configs\\licenses.json" {
		t.Fatalf("catalog source location = %q", output.Provenance.CatalogSources[0].Location)
	}
}

func TestBuildOutputReturnsNilCatalogSourcesWhenUnset(t *testing.T) {
	t.Parallel()

	output := BuildOutput(View{}, OutputConfig{})

	if output.Provenance.CatalogSources != nil {
		t.Fatalf("catalog sources = %#v", output.Provenance.CatalogSources)
	}
}

func TestFirstNonEmptyReturnsTrimmedValueOrBlank(t *testing.T) {
	t.Parallel()

	if got := firstNonEmpty("   ", "\tvalue\t", "later"); got != "value" {
		t.Fatalf("firstNonEmpty picked %q", got)
	}
	if got := firstNonEmpty("", "   ", "\t"); got != "" {
		t.Fatalf("firstNonEmpty blank = %q", got)
	}
}

func TestBuildOutputPreservesExcludedPackageDiagnostics(t *testing.T) {
	t.Parallel()

	view := View{
		Packages: []inventory.Package{{
			Ecosystem: "node",
			Project:   "web",
			Name:      "react",
			Version:   "19.2.4",
		}},
		ExcludedPackages: []ExcludedPackage{{
			RuleID:    "omit-helper",
			Reason:    "exclude helper from final output",
			SourceIDs: []string{"repo-scan"},
			Package: inventory.Package{
				Ecosystem: "node",
				Project:   "web",
				Name:      "internal-helper",
				Version:   "1.0.0",
			},
		}},
	}

	output := BuildOutput(view, OutputConfig{})
	if len(output.Report.ExcludedPackages) != 1 {
		t.Fatalf("excluded package count = %d", len(output.Report.ExcludedPackages))
	}
	if output.Report.ExcludedPackages[0].RuleID != "omit-helper" || output.Report.ExcludedPackages[0].Package.Name != "internal-helper" {
		t.Fatalf("unexpected excluded package diagnostic = %#v", output.Report.ExcludedPackages[0])
	}
}

func TestBuildOutputPreservesDiagnostics(t *testing.T) {
	t.Parallel()

	view := View{
		Diagnostics: []inventory.Diagnostic{{
			SourceID:          "repo-scan",
			RuleID:            "omit-analyzer-subgraph",
			Code:              "subgraph-exclude-applied",
			Severity:          "info",
			Message:           "subgraph exclude applied",
			ProjectPath:       "src/server/App.csproj",
			MatchedRoots:      []string{"Analyzer.Core/1.0.0"},
			RemovedPackages:   []string{"Analyzer.Core/1.0.0", "Build.Helper/1.0.0"},
			PreservedPackages: []string{"Runtime.Core/2.0.0", "Shared.Lib/1.0.0"},
		}},
	}

	output := BuildOutput(view, OutputConfig{})
	if len(output.Report.Diagnostics) != 1 {
		t.Fatalf("diagnostics = %#v", output.Report.Diagnostics)
	}
	if output.Report.Diagnostics[0].RuleID != "omit-analyzer-subgraph" || output.Report.Diagnostics[0].ProjectPath != "src/server/App.csproj" {
		t.Fatalf("unexpected diagnostic = %#v", output.Report.Diagnostics[0])
	}
}
