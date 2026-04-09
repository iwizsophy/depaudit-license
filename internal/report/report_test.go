package report

import (
	"testing"
	"time"

	"depaudit-license/internal/catalog"
	"depaudit-license/internal/inventory"
	"depaudit-license/internal/policy"
)

func setTestNow(t *testing.T, instant time.Time) {
	t.Helper()
	previous := now
	now = func() time.Time { return instant }
	t.Cleanup(func() {
		now = previous
	})
}

func TestBuildFiltersProductionAndRendersNotice(t *testing.T) {
	t.Parallel()
	setTestNow(t, time.Date(2026, time.April, 4, 11, 0, 0, 0, time.UTC))

	cat := &catalog.Catalog{
		Fallback: "Unknown",
		Definitions: map[string]catalog.Definition{
			"MIT": {
				Key:            "MIT",
				Name:           "MIT License",
				RiskLevel:      "low",
				Color:          "#000000",
				NoticeTemplate: "copyright {{.Year}} {{.Holders}} / {{.PackageCount}}",
			},
			"Unknown": {
				Key:       "Unknown",
				Name:      "Unknown",
				RiskLevel: "unknown",
				Color:     "#999999",
			},
		},
	}

	packages := []inventory.Package{
		{
			Ecosystem:           "node",
			Project:             "web",
			Name:                "left-pad",
			Version:             "1.0.0",
			DependencyType:      "dependency",
			LicenseKey:          "MIT",
			CopyrightHolder:     "Alice",
			CopyrightYear:       2020,
			EmbeddedLicensePath: "LICENSE.txt",
			EmbeddedLicenseText: "custom license body",
		},
		{
			Ecosystem:      "node",
			Project:        "web",
			Name:           "jest",
			Version:        "29.0.0",
			DependencyType: "devDependency",
			LicenseKey:     "MIT",
		},
		{
			Ecosystem:      "generic",
			Project:        "sbom",
			Name:           "build-helper",
			Version:        "1.0.0",
			DependencyType: "devTransitiveDependency",
			LicenseKey:     "Unknown",
		},
		{
			Ecosystem:      "dotnet",
			Project:        "api",
			Name:           "internal.package",
			Version:        "1.2.3",
			DependencyType: "dependency",
			LicenseKey:     "MIT",
		},
	}

	view := BuildDocument(Config{
		Root:            ".",
		ExcludePatterns: []string{"internal."},
		ShallowRules: []policy.Rule{{
			ID:     "legacy-exclude-patterns",
			Reason: "synthesized from -exclude-patterns",
			Match: policy.Selector{
				NameGlobs: []string{"*internal.*"},
			},
		}},
	}, inventory.Document{Packages: packages}, cat)

	if view.TotalPackages != 3 {
		t.Fatalf("expected 3 visible packages, got %d", view.TotalPackages)
	}
	if view.GeneratedAt != "2026-04-04T11:00:00Z" {
		t.Fatalf("generated at = %q", view.GeneratedAt)
	}
	if view.ProductionPackages != 1 {
		t.Fatalf("expected 1 production package, got %d", view.ProductionPackages)
	}
	if len(view.Ecosystems) != 2 {
		t.Fatalf("expected 2 ecosystems, got %d", len(view.Ecosystems))
	}
	if len(view.DependencyTypes) != 3 {
		t.Fatalf("expected 3 dependency types, got %d", len(view.DependencyTypes))
	}
	if len(view.Groups) != 2 {
		t.Fatalf("expected 2 groups, got %d", len(view.Groups))
	}
	if len(view.ExcludedPackages) != 1 {
		t.Fatalf("expected 1 excluded package, got %d", len(view.ExcludedPackages))
	}
	if view.ExcludedPackages[0].RuleID != "legacy-exclude-patterns" || view.ExcludedPackages[0].Package.Name != "internal.package" {
		t.Fatalf("unexpected excluded package diagnostic: %#v", view.ExcludedPackages[0])
	}
	mitGroup := view.Groups[0]
	if mitGroup.Key != "MIT" {
		t.Fatalf("expected first group to be MIT, got %q", mitGroup.Key)
	}
	if mitGroup.NoticeText == "" {
		t.Fatal("expected notice text to be rendered")
	}
	if len(mitGroup.ProductionPackages) != 1 {
		t.Fatalf("expected 1 production package in group, got %d", len(mitGroup.ProductionPackages))
	}
	if len(view.LegalNoticeEvidence) != 2 {
		t.Fatalf("expected 2 legal notice evidence entries, got %d", len(view.LegalNoticeEvidence))
	}
	if view.LegalNoticeEvidence[0].Kind != "embedded-license-text" {
		t.Fatalf("unexpected first evidence kind %q", view.LegalNoticeEvidence[0].Kind)
	}
	if view.LegalNoticeEvidence[0].Text != "custom license body" {
		t.Fatalf("unexpected embedded evidence text %q", view.LegalNoticeEvidence[0].Text)
	}
	if view.LegalNoticeEvidence[1].Kind != "license-notice" {
		t.Fatalf("unexpected second evidence kind %q", view.LegalNoticeEvidence[1].Kind)
	}
}

func TestBuildDocumentPolicyShallowExcludeMatchesLegacyPatterns(t *testing.T) {
	t.Parallel()

	cat := &catalog.Catalog{
		Fallback: "Unknown",
		Definitions: map[string]catalog.Definition{
			"MIT":     {Key: "MIT", Name: "MIT License", RiskLevel: "low", Color: "#000000"},
			"Unknown": {Key: "Unknown", Name: "Unknown", RiskLevel: "unknown", Color: "#999999"},
		},
	}
	doc := inventory.Document{Packages: []inventory.Package{
		{Ecosystem: "node", Project: "web", Name: "react", Version: "19.2.4", DependencyType: "dependency", LicenseKey: "MIT"},
		{Ecosystem: "node", Project: "web", Name: "internal-helper", Version: "1.0.0", DependencyType: "dependency", LicenseKey: "MIT", Provenance: inventory.PackageProvenance{SourceIDs: []string{"repo-scan"}}},
	}}

	legacyView := BuildDocument(Config{
		Root:            ".",
		ExcludePatterns: []string{"internal-helper"},
		ShallowRules: []policy.Rule{{
			ID:     "legacy-exclude-patterns",
			Reason: "synthesized from -exclude-patterns",
			Match: policy.Selector{
				NameGlobs: []string{"*internal-helper*"},
			},
		}},
	}, doc, cat)
	policyView := BuildDocument(Config{
		Root: ".",
		ShallowRules: []policy.Rule{{
			ID:     "omit-helper",
			Reason: "test",
			Match: policy.Selector{
				Names: []string{"internal-helper"},
			},
		}},
	}, doc, cat)

	if len(legacyView.Packages) != len(policyView.Packages) || legacyView.Packages[0].Name != policyView.Packages[0].Name {
		t.Fatalf("visible packages differ: legacy=%#v policy=%#v", legacyView.Packages, policyView.Packages)
	}
	if len(legacyView.ExcludedPackages) != 1 || len(policyView.ExcludedPackages) != 1 {
		t.Fatalf("excluded diagnostics differ: legacy=%#v policy=%#v", legacyView.ExcludedPackages, policyView.ExcludedPackages)
	}
	if policyView.ExcludedPackages[0].Package.Name != "internal-helper" {
		t.Fatalf("unexpected excluded package = %#v", policyView.ExcludedPackages[0])
	}
}

func TestMinYearFallsBackToPackageClockYear(t *testing.T) {
	t.Parallel()
	setTestNow(t, time.Date(2032, time.January, 2, 0, 0, 0, 0, time.UTC))

	if got := minYear([]inventory.Package{{Name: "pkg"}}); got != 2032 {
		t.Fatalf("minYear fallback = %d", got)
	}
}

func TestApplyShallowExcludesKeepsPackagesWhenNoRuleMatches(t *testing.T) {
	t.Parallel()

	packages := []inventory.Package{
		{Ecosystem: "node", Project: "web", Name: "react", Version: "19.2.4", DependencyType: "dependency"},
		{Ecosystem: "dotnet", Project: "api", Name: "Newtonsoft.Json", Version: "13.0.3", DependencyType: "dependency"},
	}

	visible, excluded := applyShallowExcludes(packages, []policy.Rule{{
		ID: "omit-dev",
		Match: policy.Selector{
			DependencyTypes: []string{"devDependency"},
		},
	}})

	if len(visible) != 2 || len(excluded) != 0 {
		t.Fatalf("visible=%#v excluded=%#v", visible, excluded)
	}
}

func TestApplyShallowExcludesMatchesCompositeSelector(t *testing.T) {
	t.Parallel()

	withRuntime := true
	packages := []inventory.Package{
		{
			Provenance:       inventory.PackageProvenance{SourceIDs: []string{"repo-scan"}},
			Ecosystem:        "dotnet",
			Project:          "Api",
			Name:             "Newtonsoft.Json",
			Version:          "13.0.3",
			PURL:             "pkg:nuget/Newtonsoft.Json@13.0.3",
			DependencyType:   "dependency",
			HasRuntimeAssets: true,
		},
		{
			Ecosystem:        "dotnet",
			Project:          "Api",
			Name:             "Serilog",
			Version:          "3.1.0",
			PURL:             "pkg:nuget/Serilog@3.1.0",
			DependencyType:   "dependency",
			HasRuntimeAssets: true,
		},
	}

	visible, excluded := applyShallowExcludes(packages, []policy.Rule{{
		ID:     "omit-newtonsoft",
		Reason: "test composite selector",
		Match: policy.Selector{
			Ecosystems:       []string{"DOTNET"},
			Names:            []string{"Newtonsoft.Json"},
			Versions:         []string{"13.0.3"},
			Projects:         []string{"Api"},
			DependencyTypes:  []string{"DEPENDENCY"},
			HasRuntimeAssets: &withRuntime,
			PURLs:            []string{"pkg:nuget/Newtonsoft.Json@13.0.3"},
		},
	}})

	if len(visible) != 1 || visible[0].Name != "Serilog" {
		t.Fatalf("visible=%#v", visible)
	}
	if len(excluded) != 1 || excluded[0].Package.Name != "Newtonsoft.Json" || excluded[0].RuleID != "omit-newtonsoft" {
		t.Fatalf("excluded=%#v", excluded)
	}
}

func TestProductionGroupsAndLegalNoticeEvidenceHelpers(t *testing.T) {
	t.Parallel()

	groups := []LicenseGroup{
		{Key: "MIT", ProductionPackages: []inventory.Package{{Name: "react"}}, NoticeText: "notice"},
		{Key: "Unknown"},
	}
	if got := productionGroups(groups); len(got) != 1 || got[0].Key != "MIT" {
		t.Fatalf("productionGroups = %#v", got)
	}

	evidence := buildLegalNoticeEvidence([]LicenseGroup{
		{Key: "MIT", Name: "MIT License", ProductionPackages: []inventory.Package{{Ecosystem: "node", Project: "web", Name: "react", Version: "19.2.4"}}, NoticeText: "notice"},
	}, []inventory.Package{
		{Ecosystem: "node", Project: "web", Name: "react", Version: "19.2.4", EmbeddedLicenseText: "embedded", EmbeddedLicensePath: "LICENSE"},
	})
	if len(evidence) != 2 {
		t.Fatalf("evidence = %#v", evidence)
	}
	if evidence[0].Kind != "embedded-license-text" || evidence[1].Kind != "license-notice" {
		t.Fatalf("unexpected evidence ordering = %#v", evidence)
	}
}
