package sbom

import (
	"os"
	"path/filepath"
	"testing"

	"depaudit-license/internal/catalog"
	"depaudit-license/internal/inventory"
)

func TestLoadSPDXJSONMapsPackagesToInventory(t *testing.T) {
	t.Parallel()

	cat, err := catalog.Load(filepath.Join("..", "..", "configs", "licenses.json"))
	if err != nil {
		t.Fatalf("load catalog: %v", err)
	}

	packages, err := LoadSPDXJSON(filepath.Join("testdata", "spdx", "app.json"), cat)
	if err != nil {
		t.Fatalf("load SPDX: %v", err)
	}
	if len(packages) != 3 {
		t.Fatalf("expected 3 packages, got %d", len(packages))
	}

	react := findPackageByName(t, packages, "react")
	if react.DependencyType != "dependency" {
		t.Fatalf("react dependency type = %q", react.DependencyType)
	}
	if react.LicenseKey != "MIT" {
		t.Fatalf("react license key = %q", react.LicenseKey)
	}
	if react.Project != "sample-app" {
		t.Fatalf("react project = %q", react.Project)
	}

	scheduler := findPackageByName(t, packages, "scheduler")
	if scheduler.DependencyType != "transitiveDependency" {
		t.Fatalf("scheduler dependency type = %q", scheduler.DependencyType)
	}
	if scheduler.RawLicense != "MIT OR Apache-2.0" {
		t.Fatalf("scheduler raw license = %q", scheduler.RawLicense)
	}
	if scheduler.LicenseKey != "Unknown" {
		t.Fatalf("scheduler license key = %q", scheduler.LicenseKey)
	}

	custom := findPackageByName(t, packages, "custom-lib")
	if custom.LicenseKey != "OTHER" {
		t.Fatalf("custom license key = %q", custom.LicenseKey)
	}
	if custom.EmbeddedLicensePath != "spdx:LicenseRef-Custom" {
		t.Fatalf("custom embedded path = %q", custom.EmbeddedLicensePath)
	}
	if custom.EmbeddedLicenseText != "Custom internal license text" {
		t.Fatalf("custom embedded text = %q", custom.EmbeddedLicenseText)
	}
}

func TestLoadSPDXJSONRejectsEmptyPackageList(t *testing.T) {
	t.Parallel()

	cat, err := catalog.Load(filepath.Join("..", "..", "configs", "licenses.json"))
	if err != nil {
		t.Fatalf("load catalog: %v", err)
	}

	path := filepath.Join(t.TempDir(), "empty.json")
	if err := os.WriteFile(path, []byte(`{"spdxVersion":"SPDX-2.3","SPDXID":"SPDXRef-DOCUMENT","packages":[]}`), 0o644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	if _, err := LoadSPDXJSON(path, cat); err == nil {
		t.Fatal("expected empty package error")
	}
}

func TestLoadSPDXJSONCoversDependencyOfAndLicenseFileFallback(t *testing.T) {
	t.Parallel()

	cat, err := catalog.Load(filepath.Join("..", "..", "configs", "licenses.json"))
	if err != nil {
		t.Fatalf("load catalog: %v", err)
	}

	packages, err := LoadSPDXJSON(filepath.Join("testdata", "spdx", "edge-cases.json"), cat)
	if err != nil {
		t.Fatalf("load SPDX edge cases: %v", err)
	}
	if len(packages) != 2 {
		t.Fatalf("expected 2 packages, got %d", len(packages))
	}

	app := findPackageByName(t, packages, "edge-app")
	if app.DependencyType != "transitiveDependency" {
		t.Fatalf("app dependency type = %q", app.DependencyType)
	}
	if app.Project != "edge-cases" {
		t.Fatalf("project = %q", app.Project)
	}

	tool := findPackageByName(t, packages, "example.com/tool")
	if tool.DependencyType != "dependency" {
		t.Fatalf("tool dependency type = %q", tool.DependencyType)
	}
	if tool.RawLicense != "Apache-2.0 OR MIT" || tool.LicenseKey != "Unknown" {
		t.Fatalf("license = %#v", tool)
	}
	if tool.Ecosystem != "golang" {
		t.Fatalf("ecosystem = %q", tool.Ecosystem)
	}
	if tool.PURL != "pkg:golang/example.com/tool@v1.2.3" {
		t.Fatalf("purl = %q", tool.PURL)
	}
	if tool.Repository != "https://github.com/example/tool" || tool.Homepage != "https://pkg.go.dev/example.com/tool" {
		t.Fatalf("urls = %#v", tool)
	}
	if tool.CopyrightHolder != "Example Tool Authors" || tool.CopyrightYear != 0 {
		t.Fatalf("copyright = %#v", tool)
	}
}

func TestSPDXHelperFunctions(t *testing.T) {
	t.Parallel()

	document := spdxDocument{
		DocumentDescribes: []string{"SPDXRef-Project"},
		Packages: []spdxPackage{{
			SPDXID: "SPDXRef-Project",
			Name:   "sample-app",
		}},
	}
	if got := resolveSPDXProject(document, filepath.Join("fixtures", "app.spdx.json")); got != "sample-app" {
		t.Fatalf("resolveSPDXProject described = %q", got)
	}
	if got := resolveSPDXProject(spdxDocument{Name: "named-doc"}, "x.spdx.json"); got != "named-doc" {
		t.Fatalf("resolveSPDXProject named = %q", got)
	}
	if got := resolveSPDXProject(spdxDocument{}, filepath.Join("fixtures", "fallback.spdx.json")); got != "fallback.spdx" {
		t.Fatalf("resolveSPDXProject fallback = %q", got)
	}

	pkg := spdxPackage{
		LicenseConcluded: " NOASSERTION ",
		LicenseDeclared:  "LicenseRef-Custom",
		LicenseInfoFromFiles: []string{
			"MIT",
			"NONE",
			"Apache-2.0",
		},
		ExternalRefs: []spdxExternalRef{
			{ReferenceCategory: "PACKAGE-MANAGER", ReferenceType: "purl", ReferenceLocator: "pkg:npm/react@18.2.0"},
			{ReferenceCategory: "PACKAGE-MANAGER", ReferenceType: "vcs", ReferenceLocator: "https://github.com/facebook/react"},
		},
		Name:        "react",
		VersionInfo: "18.2.0",
	}
	raw, path, text := resolveSPDXLicense(pkg, map[string]spdxExtractedLicense{
		"LicenseRef-Custom": {LicenseID: "LicenseRef-Custom", ExtractedText: "custom license text"},
	})
	if raw != "LicenseRef-Custom" || path != "spdx:LicenseRef-Custom" || text != "custom license text" {
		t.Fatalf("resolveSPDXLicense extracted = %q %q %q", raw, path, text)
	}

	repo, packageURL := resolveSPDXRepositoryAndPURL(pkg.ExternalRefs)
	if repo != "https://github.com/facebook/react" || packageURL != "pkg:npm/react@18.2.0" {
		t.Fatalf("resolveSPDXRepositoryAndPURL = %q %q", repo, packageURL)
	}
	if got := resolveSPDZEcosystem(packageURL); got != "node" {
		t.Fatalf("resolveSPDZEcosystem = %q", got)
	}
	if got := canonicalSPDXPURL(spdxPackage{Name: "Newtonsoft.Json", VersionInfo: "13.0.3"}, ""); got != "pkg:generic/Newtonsoft.Json@13.0.3" {
		t.Fatalf("canonicalSPDXPURL fallback = %q", got)
	}
	if got := cleanSPDXLicenseField(" NONE "); got != "" {
		t.Fatalf("cleanSPDXLicenseField = %q", got)
	}
	if got := classifySPDXDependency("pkg", spdxGraph{}); got != "dependency" {
		t.Fatalf("classifySPDXDependency no graph = %q", got)
	}
	if got := classifySPDXDependency("transitive", spdxGraph{hasGraph: true, direct: map[string]struct{}{"direct": struct{}{}}}); got != "transitiveDependency" {
		t.Fatalf("classifySPDXDependency transitive = %q", got)
	}
}

func TestSPDXRelationshipAndLicenseFallbacks(t *testing.T) {
	t.Parallel()

	if left, right, ok := normalizeSPDXRelationship(spdxRelationship{
		SPDXElementID:    "A",
		RelationshipType: "DEPENDS_ON",
		RelatedElementID: "B",
	}); !ok || left != "A" || right != "B" {
		t.Fatalf("DEPENDS_ON normalize = %q %q %v", left, right, ok)
	}
	if left, right, ok := normalizeSPDXRelationship(spdxRelationship{
		SPDXElementID:    "B",
		RelationshipType: "DEPENDENCY_OF",
		RelatedElementID: "A",
	}); !ok || left != "A" || right != "B" {
		t.Fatalf("DEPENDENCY_OF normalize = %q %q %v", left, right, ok)
	}
	if _, _, ok := normalizeSPDXRelationship(spdxRelationship{RelationshipType: "OTHER"}); ok {
		t.Fatal("expected unsupported relationship to be ignored")
	}
	if _, _, ok := normalizeSPDXRelationship(spdxRelationship{
		SPDXElementID:    " ",
		RelationshipType: "DEPENDS_ON",
		RelatedElementID: "B",
	}); ok {
		t.Fatal("expected blank DEPENDS_ON source to be ignored")
	}
	if _, _, ok := normalizeSPDXRelationship(spdxRelationship{
		SPDXElementID:    "B",
		RelationshipType: "DEPENDENCY_OF",
		RelatedElementID: " ",
	}); ok {
		t.Fatal("expected blank DEPENDENCY_OF target to be ignored")
	}

	graph := buildSPDXGraph(spdxDocument{
		Packages: []spdxPackage{
			{SPDXID: "SPDXRef-App"},
			{SPDXID: "SPDXRef-React"},
			{SPDXID: "SPDXRef-Scheduler"},
		},
		Relationships: []spdxRelationship{
			{SPDXElementID: "SPDXRef-App", RelationshipType: "DEPENDS_ON", RelatedElementID: "SPDXRef-React"},
			{SPDXElementID: "SPDXRef-React", RelationshipType: "DEPENDS_ON", RelatedElementID: "SPDXRef-Scheduler"},
		},
	})
	if got := classifySPDXDependency("SPDXRef-React", graph); got != "dependency" {
		t.Fatalf("graph direct dependency = %q", got)
	}
	if got := classifySPDXDependency("SPDXRef-Scheduler", graph); got != "transitiveDependency" {
		t.Fatalf("graph transitive dependency = %q", got)
	}

	raw, path, text := resolveSPDXLicense(spdxPackage{
		LicenseInfoFromFiles: []string{"NONE", "MIT", "Apache-2.0", "MIT"},
	}, nil)
	if raw != "MIT OR Apache-2.0" || path != "" || text != "" {
		t.Fatalf("resolveSPDXLicense files fallback = %q %q %q", raw, path, text)
	}

	repo, purl := resolveSPDXRepositoryAndPURL([]spdxExternalRef{
		{ReferenceCategory: "OTHER", ReferenceType: "vcs", ReferenceLocator: "https://ignored.example/repo"},
		{ReferenceCategory: "PACKAGE-MANAGER", ReferenceType: "pkg:npm", ReferenceLocator: ""},
	})
	if repo != "" || purl != "" {
		t.Fatalf("resolveSPDXRepositoryAndPURL ignored = %q %q", repo, purl)
	}
	if got := resolveSPDZEcosystem(""); got != "generic" {
		t.Fatalf("resolveSPDZEcosystem empty = %q", got)
	}
	if got := resolveSPDZEcosystem("pkg:golang/github.com/example/mod@v1.0.0"); got != "golang" {
		t.Fatalf("resolveSPDZEcosystem golang = %q", got)
	}
	if got := resolveSPDZEcosystem("pkg:nuget/Newtonsoft.Json@13.0.3"); got != "dotnet" {
		t.Fatalf("resolveSPDZEcosystem nuget = %q", got)
	}
}

func findPackageByName(t *testing.T, packages []inventory.Package, name string) inventory.Package {
	t.Helper()

	for _, pkg := range packages {
		if pkg.Name == name {
			return pkg
		}
	}
	t.Fatalf("package %q not found", name)
	return inventory.Package{}
}
