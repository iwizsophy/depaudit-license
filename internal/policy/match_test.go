package policy

import (
	"testing"

	"depaudit-license/internal/inventory"
)

func TestSelectorMatchesPackageSupportsAliasesAndProjectCandidates(t *testing.T) {
	t.Parallel()

	hasRuntimeAssets := false
	pkg := inventory.Package{
		Ecosystem:        "dotnet",
		Project:          "App",
		Name:             "Analyzer.Core",
		Version:          "1.0.0",
		PURL:             "pkg:nuget/Analyzer.Core@1.0.0",
		DependencyType:   "dependency",
		HasRuntimeAssets: hasRuntimeAssets,
	}

	if !SelectorMatchesPackage(Selector{
		Ecosystems:       []string{"nuget"},
		Names:            []string{"analyzer.core"},
		NameGlobs:        []string{"analyzer*"},
		Versions:         []string{"1.0.0"},
		Projects:         []string{"src/server/App.csproj"},
		DependencyTypes:  []string{"dependency"},
		HasRuntimeAssets: &hasRuntimeAssets,
		PURLs:            []string{"pkg:nuget/Analyzer.Core@1.0.0"},
	}, pkg, "src/server/App.csproj") {
		t.Fatalf("expected selector to match package %+v", pkg)
	}

	if SelectorMatchesPackage(Selector{
		Ecosystems:       []string{"npm"},
		Names:            []string{"Analyzer.Core"},
		HasRuntimeAssets: boolPtr(true),
	}, pkg, "src/server/App.csproj") {
		t.Fatalf("expected selector mismatch for ecosystem/runtime assets %+v", pkg)
	}
}

func TestPolicyMatchHelpersCoverAliasAndFallbackBranches(t *testing.T) {
	t.Parallel()

	if !containsEcosystem([]string{"npm"}, "node") {
		t.Fatal("expected npm to match node alias")
	}
	if !containsEcosystem([]string{"dotnet"}, "nuget") {
		t.Fatal("expected dotnet to match nuget alias")
	}
	if containsEcosystem([]string{"python"}, "dotnet") {
		t.Fatal("did not expect unrelated ecosystem match")
	}

	if !matchesProject([]string{"src/server/App.csproj"}, "App", "", "src/server/App.csproj") {
		t.Fatal("expected project candidates to match")
	}
	if matchesProject([]string{"src/server/Other.csproj"}, "App", "src/server/App.csproj") {
		t.Fatal("did not expect mismatched project match")
	}

	if !containsNormalized([]string{"Analyzer.Core"}, " analyzer.core ") {
		t.Fatal("expected normalized name match")
	}
	if containsNormalized([]string{"Analyzer.Core"}, "Runtime.Core") {
		t.Fatal("did not expect normalized mismatch")
	}

	if !containsTrimmed([]string{" 1.0.0 "}, "1.0.0") {
		t.Fatal("expected trimmed version match")
	}
	if containsTrimmed([]string{"1.0.0"}, "2.0.0") {
		t.Fatal("did not expect trimmed mismatch")
	}

	if !matchesAnyGlob([]string{"analyzer*"}, "Analyzer.Core") {
		t.Fatal("expected glob match")
	}
	if !matchesAnyGlob([]string{"*pkg*"}, "@scope/pkg") {
		t.Fatal("expected scoped package glob match")
	}
	if matchesAnyGlob([]string{"["}, "Analyzer.Core") {
		t.Fatal("expected escaped glob to not match")
	}
}

func boolPtr(value bool) *bool {
	return &value
}
