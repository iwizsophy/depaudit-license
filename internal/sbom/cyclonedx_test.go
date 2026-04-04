package sbom

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"depaudit-license/internal/catalog"
	"depaudit-license/internal/inventory"
)

func TestLoadCycloneDXJSONMapsComponentsToInventory(t *testing.T) {
	t.Parallel()

	cat, err := catalog.Load(filepath.Join("..", "..", "configs", "licenses.json"))
	if err != nil {
		t.Fatalf("load catalog: %v", err)
	}

	packages, err := LoadCycloneDXJSON(filepath.Join("testdata", "cyclonedx", "app.json"), cat)
	if err != nil {
		t.Fatalf("load cyclonedx: %v", err)
	}
	if len(packages) != 3 {
		t.Fatalf("expected 3 packages, got %d", len(packages))
	}

	react := findPackage(t, packages, "react")
	if react.Ecosystem != "node" {
		t.Fatalf("react ecosystem = %q", react.Ecosystem)
	}
	if react.DependencyType != "dependency" {
		t.Fatalf("react dependency type = %q", react.DependencyType)
	}
	if react.LicenseKey != "MIT" {
		t.Fatalf("react license key = %q", react.LicenseKey)
	}
	if react.EmbeddedLicenseText != "MIT License" {
		t.Fatalf("react embedded license = %q", react.EmbeddedLicenseText)
	}
	if react.Repository == "" || react.Homepage == "" {
		t.Fatalf("react URLs not populated: %#v", react)
	}
	if react.CopyrightHolder != "Meta" || react.CopyrightYear != 2024 {
		t.Fatalf("react copyright = %d %q", react.CopyrightYear, react.CopyrightHolder)
	}

	scheduler := findPackage(t, packages, "scheduler")
	if scheduler.DependencyType != "transitiveDependency" {
		t.Fatalf("scheduler dependency type = %q", scheduler.DependencyType)
	}
	if scheduler.RawLicense != "MIT OR Apache-2.0" {
		t.Fatalf("scheduler raw license = %q", scheduler.RawLicense)
	}
	if scheduler.LicenseKey != "Unknown" {
		t.Fatalf("scheduler license key = %q", scheduler.LicenseKey)
	}

	vite := findPackage(t, packages, "vite")
	if vite.DependencyType != "devDependency" {
		t.Fatalf("vite dependency type = %q", vite.DependencyType)
	}
	if vite.RawLicense != "MIT" {
		t.Fatalf("vite raw license = %q", vite.RawLicense)
	}
}

func TestLoadCycloneDXJSONFallsBackToUnknownLicense(t *testing.T) {
	t.Parallel()

	cat, err := catalog.Load(filepath.Join("..", "..", "configs", "licenses.json"))
	if err != nil {
		t.Fatalf("load catalog: %v", err)
	}

	packages, err := LoadCycloneDXJSON(filepath.Join("testdata", "cyclonedx", "missing-license.json"), cat)
	if err != nil {
		t.Fatalf("load cyclonedx: %v", err)
	}
	if len(packages) != 1 {
		t.Fatalf("expected 1 package, got %d", len(packages))
	}
	if packages[0].LicenseKey != "Unknown" {
		t.Fatalf("license key = %q", packages[0].LicenseKey)
	}
	if packages[0].DependencyType != "dependency" {
		t.Fatalf("dependency type = %q", packages[0].DependencyType)
	}
}

func TestLoadCycloneDXJSONCoversFallbackPURLAndEmbeddedTextContracts(t *testing.T) {
	t.Parallel()

	cat, err := catalog.Load(filepath.Join("..", "..", "configs", "licenses.json"))
	if err != nil {
		t.Fatalf("load catalog: %v", err)
	}

	packages, err := LoadCycloneDXJSON(filepath.Join("testdata", "cyclonedx", "edge-cases.json"), cat)
	if err != nil {
		t.Fatalf("load cyclonedx edge cases: %v", err)
	}
	if len(packages) != 1 {
		t.Fatalf("expected 1 package, got %d", len(packages))
	}

	pkg := packages[0]
	if pkg.Name != "acme/widget" {
		t.Fatalf("name = %q", pkg.Name)
	}
	if pkg.Ecosystem != "library" {
		t.Fatalf("ecosystem = %q", pkg.Ecosystem)
	}
	if pkg.PURL != "pkg:library/acme/widget@1.2.3" {
		t.Fatalf("purl = %q", pkg.PURL)
	}
	if pkg.DependencyType != "devDependency" {
		t.Fatalf("dependency type = %q", pkg.DependencyType)
	}
	if pkg.RawLicense != "Custom Notice" || pkg.EmbeddedLicenseText != "Custom license body" {
		t.Fatalf("license payload = %#v", pkg)
	}
	if pkg.EmbeddedLicensePath != "cyclonedx:widget-ref:license[0]" {
		t.Fatalf("embedded path = %q", pkg.EmbeddedLicensePath)
	}
	if pkg.Homepage != "https://docs.example.com/widget" || pkg.Repository != "" {
		t.Fatalf("urls = %#v", pkg)
	}
	if pkg.CopyrightHolder != "Acme Corp" || pkg.CopyrightYear != 0 {
		t.Fatalf("copyright = %#v", pkg)
	}
}

func TestLoadCycloneDXJSONRejectsEmptyComponentList(t *testing.T) {
	t.Parallel()

	cat, err := catalog.Load(filepath.Join("..", "..", "configs", "licenses.json"))
	if err != nil {
		t.Fatalf("load catalog: %v", err)
	}

	path := filepath.Join(t.TempDir(), "empty.json")
	if err := os.WriteFile(path, []byte(`{"bomFormat":"CycloneDX","specVersion":"1.5","version":1,"components":[]}`), 0o644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	if _, err := LoadCycloneDXJSON(path, cat); err == nil {
		t.Fatal("expected empty component error")
	}
}

func TestCycloneDXHelperFunctions(t *testing.T) {
	t.Parallel()

	if got := resolveCycloneDXEcosystem(cycloneDXComponent{PURL: "pkg:npm/react@18.2.0"}); got != "node" {
		t.Fatalf("resolveCycloneDXEcosystem npm = %q", got)
	}
	if got := resolveCycloneDXEcosystem(cycloneDXComponent{PURL: "pkg:nuget/Newtonsoft.Json@13.0.3"}); got != "dotnet" {
		t.Fatalf("resolveCycloneDXEcosystem nuget = %q", got)
	}
	if got := resolveCycloneDXEcosystem(cycloneDXComponent{Type: "library"}); got != "library" {
		t.Fatalf("resolveCycloneDXEcosystem type = %q", got)
	}
	if got := resolveCycloneDXEcosystem(cycloneDXComponent{}); got != "generic" {
		t.Fatalf("resolveCycloneDXEcosystem empty = %q", got)
	}

	if got := purlType("pkg:npm/%40scope/react@18.2.0?x=1"); got != "npm" {
		t.Fatalf("purlType = %q", got)
	}
	if got := purlType("not-a-purl"); got != "" {
		t.Fatalf("purlType invalid = %q", got)
	}

	cat := &catalog.Catalog{Fallback: "Unknown"}
	if got := canonicalCycloneDXPURL(cycloneDXComponent{Name: "react", Version: "18.2.0"}); got != "pkg:generic/react@18.2.0" {
		t.Fatalf("canonicalCycloneDXPURL fallback = %q", got)
	}
	if got := normalizeCycloneDXLicenseKey("MIT OR Apache-2.0", cat); got != "Unknown" {
		t.Fatalf("normalizeCycloneDXLicenseKey compound = %q", got)
	}
	if !isCompoundLicenseExpression("MIT OR Apache-2.0") {
		t.Fatal("expected compound expression")
	}
	if isCompoundLicenseExpression("MIT") {
		t.Fatal("did not expect simple expression to be compound")
	}
}

func TestCycloneDXGraphAndLicenseFallbacks(t *testing.T) {
	t.Parallel()

	graph := buildCycloneDXGraph(cycloneDXDocument{
		Dependencies: []cycloneDXDependency{
			{Ref: "root", DependsOn: []string{"direct", "optional"}},
			{Ref: "direct", DependsOn: []string{"transitive"}},
		},
	}, "root")
	if !graph.hasGraph {
		t.Fatal("expected graph to be present")
	}
	if got := classifyCycloneDXDependency("", "direct", graph); got != "dependency" {
		t.Fatalf("direct dependency = %q", got)
	}
	if got := classifyCycloneDXDependency("optional", "optional", graph); got != "devDependency" {
		t.Fatalf("optional direct dependency = %q", got)
	}
	if got := classifyCycloneDXDependency("optional", "transitive", graph); got != "devTransitiveDependency" {
		t.Fatalf("optional transitive dependency = %q", got)
	}

	rootless := buildCycloneDXGraph(cycloneDXDocument{
		Dependencies: []cycloneDXDependency{
			{Ref: "app", DependsOn: []string{"react"}},
			{Ref: "react", DependsOn: []string{"scheduler"}},
		},
	}, "")
	if got := classifyCycloneDXDependency("", "react", rootless); got != "dependency" {
		t.Fatalf("rootless direct dependency = %q", got)
	}
	if got := classifyCycloneDXDependency("", "scheduler", rootless); got != "transitiveDependency" {
		t.Fatalf("rootless transitive dependency = %q", got)
	}

	raw, path, text := resolveCycloneDXLicense(cycloneDXComponent{
		BOMRef: "pkg:npm/react@18.2.0",
		Evidence: cycloneDXEvidence{
			Licenses: []cycloneDXLicenseChoice{{
				License: &cycloneDXLicense{
					Name: "MIT",
					Text: &cycloneDXTextBlock{Content: "ZXZpZGVuY2UtbGljZW5zZQ==", Encoding: "base64"},
				},
			}},
		},
	})
	if raw != "MIT" || path == "" || text != "evidence-license" {
		t.Fatalf("resolveCycloneDXLicense evidence fallback = %q %q %q", raw, path, text)
	}

	if got, _, _ := selectCycloneDXLicense([]cycloneDXLicenseChoice{
		{License: &cycloneDXLicense{Name: "MIT"}},
		{License: &cycloneDXLicense{Name: "Apache-2.0"}},
	}, "pkg:npm/react@18.2.0"); got != "MIT OR Apache-2.0" {
		t.Fatalf("selectCycloneDXLicense names = %q", got)
	}
	if got, path, text := selectCycloneDXLicense([]cycloneDXLicenseChoice{
		{},
		{License: nil},
	}, "pkg:npm/react@18.2.0"); got != "" || path != "" || text != "" {
		t.Fatalf("selectCycloneDXLicense empty choices = %q %q %q", got, path, text)
	}

	if got := decodeCycloneDXText(&cycloneDXTextBlock{Content: "%%%invalid%%%", Encoding: "base64"}); got != "" {
		t.Fatalf("decodeCycloneDXText invalid base64 = %q", got)
	}
	if got := decodeCycloneDXText(&cycloneDXTextBlock{Content: "   ", Encoding: "base64"}); got != "" {
		t.Fatalf("decodeCycloneDXText blank content = %q", got)
	}
}

func TestCycloneDXHelperEdgeBranches(t *testing.T) {
	t.Parallel()

	if got := componentDisplayName(cycloneDXComponent{Group: "@scope", Name: "pkg", PURL: "pkg:npm/%40scope/pkg@1.0.0"}); got != "@scope/pkg" {
		t.Fatalf("componentDisplayName scoped npm = %q", got)
	}
	if got := componentDisplayName(cycloneDXComponent{Group: "scope", Name: "pkg", PURL: "pkg:npm/pkg@1.0.0"}); got != "@scope/pkg" {
		t.Fatalf("componentDisplayName implicit scoped npm = %q", got)
	}
	if got := componentDisplayName(cycloneDXComponent{Group: "org.example", Name: "pkg", PURL: "pkg:maven/org.example/pkg@1.0.0"}); got != "org.example/pkg" {
		t.Fatalf("componentDisplayName non-npm group = %q", got)
	}
	if got := componentRef(cycloneDXComponent{BOMRef: " bom-ref "}); got != "bom-ref" {
		t.Fatalf("componentRef bom-ref = %q", got)
	}
	if got := componentRef(cycloneDXComponent{PURL: " pkg:npm/react@18.2.0 "}); got != "pkg:npm/react@18.2.0" {
		t.Fatalf("componentRef purl = %q", got)
	}
	if got := componentRef(cycloneDXComponent{Name: "pkg", Group: "scope", PURL: "not-a-purl"}); got != "not-a-purl" {
		t.Fatalf("componentRef trimmed purl fallback = %q", got)
	}
	if got := componentRef(cycloneDXComponent{}); got != "" {
		t.Fatalf("componentRef empty = %q", got)
	}
	if got := buildCycloneDXLicensePath("", 0); got != "" {
		t.Fatalf("buildCycloneDXLicensePath blank ref = %q", got)
	}
	if got := decodeCycloneDXText(nil); got != "" {
		t.Fatalf("decodeCycloneDXText nil = %q", got)
	}
	if got := decodeCycloneDXText(&cycloneDXTextBlock{Content: "plain text"}); got != "plain text" {
		t.Fatalf("decodeCycloneDXText plain = %q", got)
	}
	repo, home := resolveCycloneDXURLs([]cycloneDXExternalRef{
		{Type: "documentation", URL: "https://docs.example/pkg"},
		{Type: "website", URL: "https://site.example/pkg"},
		{Type: "vcs", URL: "https://github.com/example/pkg"},
	})
	if repo != "https://github.com/example/pkg" || home != "https://docs.example/pkg" {
		t.Fatalf("resolveCycloneDXURLs = %q %q", repo, home)
	}
	repo, home = resolveCycloneDXURLs([]cycloneDXExternalRef{
		{Type: "website", URL: "https://site.example/pkg"},
		{Type: "vcs", URL: "https://github.com/example/pkg"},
	})
	if repo != "https://github.com/example/pkg" || home != "https://site.example/pkg" {
		t.Fatalf("resolveCycloneDXURLs website fallback = %q %q", repo, home)
	}
	if got := uniqueStrings([]string{"b", "", "a", "b"}); len(got) != 2 || got[0] != "b" || got[1] != "a" {
		t.Fatalf("uniqueStrings = %#v", got)
	}
}

func findPackage(t *testing.T, packages []inventory.Package, name string) inventory.Package {
	t.Helper()

	for _, pkg := range packages {
		if pkg.Name == name || strings.HasSuffix(pkg.Name, "/"+name) {
			return pkg
		}
	}
	t.Fatalf("package %q not found", name)
	return inventory.Package{}
}
