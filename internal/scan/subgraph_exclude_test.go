package scan

import (
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"depaudit-license/internal/inventory"
	"depaudit-license/internal/policy"
)

func TestApplySubgraphExcludesRemovesOnlySourceLocalExclusiveNodes(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	result := Result{
		Packages: []Package{
			{Ecosystem: "dotnet", Project: "App", ProjectPath: filepath.Join(root, "src", "server", "App.csproj"), Name: "Analyzer.Core", Version: "1.0.0", DependencyType: "dependency", HasRuntimeAssets: false},
			{Ecosystem: "dotnet", Project: "App", ProjectPath: filepath.Join(root, "src", "server", "App.csproj"), Name: "Build.Helper", Version: "1.0.0", DependencyType: "transitiveDependency", HasRuntimeAssets: false},
			{Ecosystem: "dotnet", Project: "App", ProjectPath: filepath.Join(root, "src", "server", "App.csproj"), Name: "Runtime.Core", Version: "2.0.0", DependencyType: "dependency", HasRuntimeAssets: true},
			{Ecosystem: "dotnet", Project: "App", ProjectPath: filepath.Join(root, "src", "server", "App.csproj"), Name: "Shared.Lib", Version: "1.0.0", DependencyType: "transitiveDependency", HasRuntimeAssets: true},
			{Ecosystem: "node", Project: "web", Name: "react", Version: "19.2.4", DependencyType: "dependency"},
		},
		Graphs: []DependencyGraph{{
			Ecosystem:   "dotnet",
			Project:     "App",
			ProjectPath: filepath.Join(root, "src", "server", "App.csproj"),
			Roots:       []string{"Analyzer.Core/1.0.0", "Runtime.Core/2.0.0"},
			Nodes: []DependencyGraphNode{
				{ID: "Analyzer.Core/1.0.0", Package: Package{Ecosystem: "dotnet", Project: "App", ProjectPath: filepath.Join(root, "src", "server", "App.csproj"), Name: "Analyzer.Core", Version: "1.0.0", DependencyType: "dependency", HasRuntimeAssets: false}},
				{ID: "Build.Helper/1.0.0", Package: Package{Ecosystem: "dotnet", Project: "App", ProjectPath: filepath.Join(root, "src", "server", "App.csproj"), Name: "Build.Helper", Version: "1.0.0", DependencyType: "transitiveDependency", HasRuntimeAssets: false}},
				{ID: "Runtime.Core/2.0.0", Package: Package{Ecosystem: "dotnet", Project: "App", ProjectPath: filepath.Join(root, "src", "server", "App.csproj"), Name: "Runtime.Core", Version: "2.0.0", DependencyType: "dependency", HasRuntimeAssets: true}},
				{ID: "Shared.Lib/1.0.0", Package: Package{Ecosystem: "dotnet", Project: "App", ProjectPath: filepath.Join(root, "src", "server", "App.csproj"), Name: "Shared.Lib", Version: "1.0.0", DependencyType: "transitiveDependency", HasRuntimeAssets: true}},
			},
			Edges: []DependencyGraphEdge{
				{From: "Analyzer.Core/1.0.0", To: "Build.Helper/1.0.0"},
				{From: "Analyzer.Core/1.0.0", To: "Shared.Lib/1.0.0"},
				{From: "Runtime.Core/2.0.0", To: "Shared.Lib/1.0.0"},
			},
		}},
	}

	updated, err := ApplySubgraphExcludes(SubgraphExcludeConfig{
		Root:     root,
		SourceID: "repo-scan",
		Rules: []policy.Rule{{
			ID: "omit-analyzer-subgraph",
			Match: policy.Selector{
				Ecosystems:       []string{"nuget"},
				Projects:         []string{"src/server/App.csproj"},
				Names:            []string{"Analyzer.Core"},
				HasRuntimeAssets: boolPtr(false),
			},
		}},
	}, result)
	if err != nil {
		t.Fatalf("ApplySubgraphExcludes: %v", err)
	}

	gotNames := packageNames(updated.Packages)
	if !slices.Equal(gotNames, []string{"Runtime.Core", "Shared.Lib", "react"}) {
		t.Fatalf("packages = %#v", updated.Packages)
	}
	if len(updated.Diagnostics) != 1 {
		t.Fatalf("diagnostics = %#v", updated.Diagnostics)
	}
	diagnostic := updated.Diagnostics[0]
	if diagnostic.Code != DiagnosticCodeSubgraphApplied || diagnostic.RuleID != "omit-analyzer-subgraph" {
		t.Fatalf("diagnostic = %#v", diagnostic)
	}
	if !slices.Equal(diagnostic.MatchedRoots, []string{"Analyzer.Core/1.0.0"}) {
		t.Fatalf("matched roots = %#v", diagnostic.MatchedRoots)
	}
	if !slices.Equal(diagnostic.RemovedPackages, []string{"Analyzer.Core/1.0.0", "Build.Helper/1.0.0"}) {
		t.Fatalf("removed packages = %#v", diagnostic.RemovedPackages)
	}
	if !slices.Equal(diagnostic.PreservedPackages, []string{"Runtime.Core/2.0.0", "Shared.Lib/1.0.0"}) {
		t.Fatalf("preserved packages = %#v", diagnostic.PreservedPackages)
	}
}

func TestApplySubgraphExcludesKeepsDuplicateProjectNamesWithDifferentPaths(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	managedPath := filepath.Join(root, "src", "server", "App.csproj")
	fallbackPath := filepath.Join(root, "src", "tools", "App.csproj")
	result := Result{
		Packages: []Package{
			{Ecosystem: "dotnet", Project: "App", ProjectPath: managedPath, Name: "Analyzer.Core", Version: "1.0.0", DependencyType: "dependency", HasRuntimeAssets: false},
			{Ecosystem: "dotnet", Project: "App", ProjectPath: managedPath, Name: "Build.Helper", Version: "1.0.0", DependencyType: "transitiveDependency", HasRuntimeAssets: false},
			{Ecosystem: "dotnet", Project: "App", ProjectPath: managedPath, Name: "Runtime.Core", Version: "2.0.0", DependencyType: "dependency", HasRuntimeAssets: true},
			{Ecosystem: "dotnet", Project: "App", ProjectPath: fallbackPath, Name: "Tooling.Only", Version: "4.0.0", DependencyType: "dependency", HasRuntimeAssets: true},
		},
		Graphs: []DependencyGraph{{
			Ecosystem:   "dotnet",
			Project:     "App",
			ProjectPath: managedPath,
			Roots:       []string{"Analyzer.Core/1.0.0", "Runtime.Core/2.0.0"},
			Nodes: []DependencyGraphNode{
				{ID: "Analyzer.Core/1.0.0", Package: Package{Ecosystem: "dotnet", Project: "App", ProjectPath: managedPath, Name: "Analyzer.Core", Version: "1.0.0", DependencyType: "dependency", HasRuntimeAssets: false}},
				{ID: "Build.Helper/1.0.0", Package: Package{Ecosystem: "dotnet", Project: "App", ProjectPath: managedPath, Name: "Build.Helper", Version: "1.0.0", DependencyType: "transitiveDependency", HasRuntimeAssets: false}},
				{ID: "Runtime.Core/2.0.0", Package: Package{Ecosystem: "dotnet", Project: "App", ProjectPath: managedPath, Name: "Runtime.Core", Version: "2.0.0", DependencyType: "dependency", HasRuntimeAssets: true}},
			},
			Edges: []DependencyGraphEdge{
				{From: "Analyzer.Core/1.0.0", To: "Build.Helper/1.0.0"},
			},
		}},
	}

	updated, err := ApplySubgraphExcludes(SubgraphExcludeConfig{
		Root:     root,
		SourceID: "repo-scan",
		Rules: []policy.Rule{{
			ID: "omit-analyzer-subgraph",
			Match: policy.Selector{
				Ecosystems: []string{"nuget"},
				Projects:   []string{"src/server/App.csproj"},
				Names:      []string{"Analyzer.Core"},
			},
		}},
	}, result)
	if err != nil {
		t.Fatalf("ApplySubgraphExcludes duplicate project names: %v", err)
	}

	gotNames := packageNames(updated.Packages)
	if !slices.Equal(gotNames, []string{"Runtime.Core", "Tooling.Only"}) {
		t.Fatalf("packages = %#v", updated.Packages)
	}
}

func TestApplySubgraphExcludesWarnsWhenGraphUnavailable(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	result := Result{
		Packages: []Package{
			{Ecosystem: "dotnet", Project: "App", ProjectPath: filepath.Join(root, "src", "server", "App.csproj"), Name: "Analyzer.Core", Version: "1.0.0", DependencyType: "dependency", HasRuntimeAssets: false},
		},
		Diagnostics: []inventory.Diagnostic{{
			Code:        DiagnosticCodeGraphUnavailable,
			Severity:    DiagnosticSeverityWarning,
			Message:     "project.assets.json not found",
			Ecosystem:   "dotnet",
			Project:     "App",
			ProjectPath: filepath.Join(root, "src", "server", "App.csproj"),
		}},
	}

	updated, err := ApplySubgraphExcludes(SubgraphExcludeConfig{
		Root:     root,
		SourceID: "repo-scan",
		Rules: []policy.Rule{{
			ID:            "omit-analyzer-subgraph",
			OnUnsupported: policy.OnUnsupportedWarn,
			Match: policy.Selector{
				Ecosystems: []string{"nuget"},
				Projects:   []string{"src/server/App.csproj"},
				Names:      []string{"Analyzer.Core"},
			},
		}},
	}, result)
	if err != nil {
		t.Fatalf("ApplySubgraphExcludes: %v", err)
	}

	if len(updated.Packages) != 1 || updated.Packages[0].Name != "Analyzer.Core" {
		t.Fatalf("packages = %#v", updated.Packages)
	}
	if len(updated.Diagnostics) != 2 {
		t.Fatalf("diagnostics = %#v", updated.Diagnostics)
	}
	warn := updated.Diagnostics[1]
	if warn.Code != DiagnosticCodeSubgraphUnsupported || warn.RuleID != "omit-analyzer-subgraph" || warn.Severity != DiagnosticSeverityWarning {
		t.Fatalf("warn diagnostic = %#v", warn)
	}
	if !slices.Equal(warn.MatchedRoots, []string{"Analyzer.Core/1.0.0"}) {
		t.Fatalf("warn matched roots = %#v", warn.MatchedRoots)
	}
}

func TestApplySubgraphExcludesWarnsOnlyForMatchingGraphUnavailableProjectPath(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	serverPath := filepath.Join(root, "src", "server", "App.csproj")
	toolsPath := filepath.Join(root, "src", "tools", "App.csproj")
	result := Result{
		Packages: []Package{
			{Ecosystem: "dotnet", Project: "App", ProjectPath: serverPath, Name: "Analyzer.Core", Version: "1.0.0", DependencyType: "dependency", HasRuntimeAssets: false},
			{Ecosystem: "dotnet", Project: "App", ProjectPath: toolsPath, Name: "Tool.Helper", Version: "1.0.0", DependencyType: "dependency", HasRuntimeAssets: false},
		},
		Diagnostics: []inventory.Diagnostic{{
			Code:        DiagnosticCodeGraphUnavailable,
			Severity:    DiagnosticSeverityWarning,
			Message:     "project.assets.json not found",
			Ecosystem:   "dotnet",
			Project:     "App",
			ProjectPath: serverPath,
		}},
	}

	updated, err := ApplySubgraphExcludes(SubgraphExcludeConfig{
		Root:     root,
		SourceID: "repo-scan",
		Rules: []policy.Rule{{
			ID:            "omit-analyzer-subgraph",
			OnUnsupported: policy.OnUnsupportedWarn,
			Match: policy.Selector{
				Ecosystems:       []string{"nuget"},
				Projects:         []string{"src/server/App.csproj"},
				HasRuntimeAssets: boolPtr(false),
			},
		}},
	}, result)
	if err != nil {
		t.Fatalf("ApplySubgraphExcludes duplicate graph unavailable names: %v", err)
	}

	if len(updated.Diagnostics) != 2 {
		t.Fatalf("diagnostics = %#v", updated.Diagnostics)
	}
	warn := updated.Diagnostics[1]
	if !slices.Equal(warn.MatchedRoots, []string{"Analyzer.Core/1.0.0"}) {
		t.Fatalf("warn matched roots = %#v", warn.MatchedRoots)
	}
}

func TestApplySubgraphExcludesErrorsWhenConfigured(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	result := Result{
		Packages: []Package{
			{Ecosystem: "dotnet", Project: "App", Name: "Analyzer.Core", Version: "1.0.0", DependencyType: "dependency"},
		},
	}

	_, err := ApplySubgraphExcludes(SubgraphExcludeConfig{
		Root: root,
		Rules: []policy.Rule{{
			ID:            "omit-analyzer-subgraph",
			OnUnsupported: policy.OnUnsupportedError,
			Match: policy.Selector{
				Names: []string{"Analyzer.Core"},
			},
		}},
	}, result)
	if err == nil || !strings.Contains(err.Error(), "omit-analyzer-subgraph") {
		t.Fatalf("expected unsupported error, got %v", err)
	}
}

func packageNames(packages []Package) []string {
	result := make([]string, 0, len(packages))
	for _, pkg := range packages {
		result = append(result, pkg.Name)
	}
	return result
}

func boolPtr(value bool) *bool {
	return &value
}
