package report

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"depaudit-license/internal/catalog"
	"depaudit-license/internal/inventory"
)

func TestRenderHTMLAndLegalNoticeUseTemplateHelpers(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	htmlTemplate := filepath.Join(dir, "report.html.tmpl")
	legalTemplate := filepath.Join(dir, "legal.html.tmpl")
	cssPath := filepath.Join(dir, "theme.css")

	if err := os.WriteFile(htmlTemplate, []byte(`<!doctype html><style>{{.ThemeCSS}}</style><div>{{slug .Root}}</div><div>{{ecosystemLabel "node"}}</div><div>{{dependencyTypeLabel "devDependency"}}</div>`), 0o644); err != nil {
		t.Fatalf("write html template: %v", err)
	}
	if err := os.WriteFile(legalTemplate, []byte(`<!doctype html><style>{{.ThemeCSS}}</style><div>{{(index .LegalNoticeEvidence 0).Kind}}</div>`), 0o644); err != nil {
		t.Fatalf("write legal template: %v", err)
	}
	if err := os.WriteFile(cssPath, []byte(`body{color:red;}`), 0o644); err != nil {
		t.Fatalf("write css: %v", err)
	}

	cat := &catalog.Catalog{
		Fallback: "Unknown",
		Definitions: map[string]catalog.Definition{
			"MIT":     {Key: "MIT", Name: "MIT License", Color: "#000", RiskLevel: "low", NoticeTemplate: "notice"},
			"Unknown": {Key: "Unknown", Name: "Unknown", Color: "#999", RiskLevel: "unknown"},
		},
	}
	view := BuildDocument(Config{Root: "D:\\Repo Root"}, inventory.Document{Packages: []inventory.Package{{
		Ecosystem:           "node",
		Project:             "web",
		Name:                "react",
		Version:             "19.2.4",
		DependencyType:      "dependency",
		LicenseKey:          "MIT",
		EmbeddedLicenseText: "MIT text",
	}}}, cat)

	html, err := RenderHTML(view, htmlTemplate, cssPath)
	if err != nil {
		t.Fatalf("render html: %v", err)
	}
	if !strings.Contains(string(html), "d-repo-root") || !strings.Contains(string(html), "Node.js / npm") || !strings.Contains(string(html), "Development dependency") || !strings.Contains(string(html), "color:red") {
		t.Fatalf("unexpected html: %s", string(html))
	}

	legal, err := RenderLegalNoticeHTML(view, legalTemplate, cssPath)
	if err != nil {
		t.Fatalf("render legal html: %v", err)
	}
	if !strings.Contains(string(legal), "embedded-license-text") {
		t.Fatalf("unexpected legal html: %s", string(legal))
	}
}

func TestRenderNoticeTemplateFallbacksToSourceOnTemplateError(t *testing.T) {
	t.Parallel()

	got := renderNoticeTemplate("{{ .Missing", []inventory.Package{{Name: "react"}}, "MIT")
	if got != "{{ .Missing" {
		t.Fatalf("unexpected template fallback: %q", got)
	}
}

func TestReadRenderAssetsReturnsHelpfulErrors(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	cssPath := filepath.Join(dir, "theme.css")
	if err := os.WriteFile(cssPath, []byte("body{}"), 0o644); err != nil {
		t.Fatalf("write css: %v", err)
	}

	if _, _, err := readRenderAssets(filepath.Join(dir, "missing.tmpl"), cssPath); err == nil || !strings.Contains(err.Error(), "read template") {
		t.Fatalf("expected template read error, got %v", err)
	}
	if _, _, err := readRenderAssets(filepath.Join(dir, "missing.tmpl"), filepath.Join(dir, "missing.css")); err == nil || !strings.Contains(err.Error(), "read CSS") {
		t.Fatalf("expected css read error, got %v", err)
	}
}

func TestParseRenderTemplateHandlesParseErrors(t *testing.T) {
	t.Parallel()

	if _, err := parseRenderTemplate("broken.tmpl", []byte("{{")); err == nil || !strings.Contains(err.Error(), "parse template") {
		t.Fatalf("expected parse template error, got %v", err)
	}
}

func TestRenderTemplatesSupportPrettyJSONHelper(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	htmlTemplate := filepath.Join(dir, "report.html.tmpl")
	legalTemplate := filepath.Join(dir, "legal.html.tmpl")
	cssPath := filepath.Join(dir, "theme.css")

	if err := os.WriteFile(htmlTemplate, []byte(`<pre>{{prettyJSON .RiskSummary}}</pre>`), 0o644); err != nil {
		t.Fatalf("write html template: %v", err)
	}
	if err := os.WriteFile(legalTemplate, []byte(`<pre>{{prettyJSON .LegalNoticeEvidence}}</pre>`), 0o644); err != nil {
		t.Fatalf("write legal template: %v", err)
	}
	if err := os.WriteFile(cssPath, []byte(`body{color:red;}`), 0o644); err != nil {
		t.Fatalf("write css: %v", err)
	}

	cat := &catalog.Catalog{
		Fallback: "Unknown",
		Definitions: map[string]catalog.Definition{
			"MIT":     {Key: "MIT", Name: "MIT License", Color: "#000", RiskLevel: "low", NoticeTemplate: "notice"},
			"Unknown": {Key: "Unknown", Name: "Unknown", Color: "#999", RiskLevel: "unknown"},
		},
	}
	view := BuildDocument(Config{Root: "D:\\Repo Root"}, inventory.Document{Packages: []inventory.Package{{
		Ecosystem:           "node",
		Project:             "web",
		Name:                "react",
		Version:             "19.2.4",
		DependencyType:      "dependency",
		LicenseKey:          "MIT",
		EmbeddedLicenseText: "MIT text",
	}}}, cat)

	html, err := RenderHTML(view, htmlTemplate, cssPath)
	if err != nil {
		t.Fatalf("render html: %v", err)
	}
	if !strings.Contains(string(html), "&#34;level&#34;") || !strings.Contains(string(html), "&#34;low&#34;") {
		t.Fatalf("prettyJSON html output = %q", string(html))
	}

	legal, err := RenderLegalNoticeHTML(view, legalTemplate, cssPath)
	if err != nil {
		t.Fatalf("render legal html: %v", err)
	}
	if !strings.Contains(string(legal), "&#34;kind&#34;") || !strings.Contains(string(legal), "embedded-license-text") {
		t.Fatalf("prettyJSON legal output = %q", string(legal))
	}
}

func TestBuildNoticeTemplateDataShapesTemplateFields(t *testing.T) {
	t.Parallel()

	data := buildNoticeTemplateData([]inventory.Package{
		{Name: "react", CopyrightHolder: "Meta", CopyrightYear: 2024},
		{Name: "scheduler", CopyrightHolder: "Meta", CopyrightYear: 2025},
	}, "MIT")

	if data.Year != 2024 {
		t.Fatalf("year = %d", data.Year)
	}
	if data.Holders != "Meta" {
		t.Fatalf("holders = %q", data.Holders)
	}
	if data.PackageName != "react" {
		t.Fatalf("package name = %q", data.PackageName)
	}
	if data.PackageList != "react, scheduler" {
		t.Fatalf("package list = %q", data.PackageList)
	}
	if data.PackageCount != 2 || data.LicenseName != "MIT" {
		t.Fatalf("data = %#v", data)
	}
}
