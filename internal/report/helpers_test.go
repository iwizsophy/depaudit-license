package report

import (
	"html/template"
	"os"
	"path/filepath"
	"testing"

	"depaudit-license/internal/catalog"
	"depaudit-license/internal/inventory"
)

func TestBuildDelegatesToBuildDocument(t *testing.T) {
	t.Parallel()

	cat := &catalog.Catalog{
		Fallback: "Unknown",
		Definitions: map[string]catalog.Definition{
			"Unknown": {Key: "Unknown", Name: "Unknown", RiskLevel: "unknown"},
		},
	}
	view := Build(Config{Root: "."}, []inventory.Package{{
		Ecosystem:      "generic",
		Project:        "tool",
		Name:           "x",
		Version:        "1",
		DependencyType: "dependency",
		LicenseKey:     "Unknown",
	}}, cat)
	if view.TotalPackages != 1 {
		t.Fatalf("total packages = %d", view.TotalPackages)
	}
}

func TestRenderTemplateErrorBranchesAndLabels(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	missingCSS := filepath.Join(dir, "missing.css")
	templatePath := filepath.Join(dir, "broken.html.tmpl")
	if err := os.WriteFile(templatePath, []byte(`{{`), 0o644); err != nil {
		t.Fatalf("write template: %v", err)
	}

	if _, err := renderTemplate(View{}, templatePath, missingCSS, func(theme template.CSS) any { return nil }); err == nil {
		t.Fatal("expected css read error")
	}

	cssPath := filepath.Join(dir, "theme.css")
	if err := os.WriteFile(cssPath, []byte(`body{}`), 0o644); err != nil {
		t.Fatalf("write css: %v", err)
	}
	if _, err := renderTemplate(View{}, templatePath, cssPath, func(theme template.CSS) any { return nil }); err == nil {
		t.Fatal("expected parse error")
	}

	executeTemplatePath := filepath.Join(dir, "execute.html.tmpl")
	if err := os.WriteFile(executeTemplatePath, []byte(`{{.ThemeCSS.Missing}}`), 0o644); err != nil {
		t.Fatalf("write execute template: %v", err)
	}
	if _, err := renderTemplate(View{}, executeTemplatePath, cssPath, func(theme template.CSS) any {
		return struct {
			ThemeCSS template.CSS
		}{ThemeCSS: theme}
	}); err == nil {
		t.Fatal("expected execute error")
	}

	if got := riskOrder("high"); got != "0" {
		t.Fatalf("riskOrder(high) = %q", got)
	}
	if got := riskOrder("medium"); got != "1" {
		t.Fatalf("riskOrder(medium) = %q", got)
	}
	if got := ecosystemLabel(""); got != "Unknown" {
		t.Fatalf("ecosystemLabel empty = %q", got)
	}
	if got := ecosystemLabel("dotnet"); got != ".NET / NuGet" {
		t.Fatalf("ecosystemLabel dotnet = %q", got)
	}
	if got := ecosystemLabel("generic"); got != "Generic" {
		t.Fatalf("ecosystemLabel generic = %q", got)
	}
	if got := ecosystemLabel("custom"); got != "custom" {
		t.Fatalf("ecosystemLabel custom = %q", got)
	}
	if got := dependencyTypeLabel("dependency"); got != "Runtime dependency" {
		t.Fatalf("dependencyTypeLabel dependency = %q", got)
	}
	if got := dependencyTypeLabel("transitiveDependency"); got != "Transitive runtime dependency" {
		t.Fatalf("dependencyTypeLabel transitive = %q", got)
	}
	if got := dependencyTypeLabel(""); got != "Unknown" {
		t.Fatalf("dependencyTypeLabel empty = %q", got)
	}
	if got := dependencyTypeLabel("devTransitiveDependency"); got != "Transitive development dependency" {
		t.Fatalf("dependencyTypeLabel devTransitive = %q", got)
	}
	if got := dependencyTypeLabel("peerDependency"); got != "Peer dependency" {
		t.Fatalf("dependencyTypeLabel peer = %q", got)
	}
	if got := dependencyTypeLabel("custom"); got != "custom" {
		t.Fatalf("dependencyTypeLabel custom = %q", got)
	}
}
