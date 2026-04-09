package scan

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"depaudit-license/internal/catalog"
	"depaudit-license/internal/inventory"
)

func TestMetadataLookupServiceEnrichPackageUsesInstalledNodeMetadata(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	packageDir := filepath.Join(root, "web", "node_modules", "react")
	if err := os.MkdirAll(packageDir, 0o755); err != nil {
		t.Fatalf("mkdir package dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(packageDir, "package.json"), []byte(`{
  "name": "react",
  "version": "19.2.4",
  "license": "MIT",
  "homepage": "https://react.dev",
  "repository": { "url": "https://github.com/facebook/react" },
  "author": { "name": "Meta" }
}`), 0o644); err != nil {
		t.Fatalf("write package.json: %v", err)
	}

	cat, err := catalog.Load(filepath.Join("..", "..", "configs", "licenses.json"))
	if err != nil {
		t.Fatalf("load catalog: %v", err)
	}

	service := NewMetadataLookupService(MetadataLookupConfig{
		Catalog:         cat,
		RepositoryRoots: []string{filepath.Join(root, "web"), filepath.Join(root, "web")},
	})
	pkg, source, changed := service.EnrichPackage(inventory.Package{
		Ecosystem:  "node",
		Project:    "web",
		Name:       "react",
		Version:    "19.2.4",
		RawLicense: "",
		LicenseKey: cat.Fallback,
		Provenance: inventory.PackageProvenance{SourceIDs: []string{"repo-scan"}},
	})
	if !changed {
		t.Fatal("expected package to be enriched")
	}
	if source == nil || source.Kind != MetadataEnrichmentSourceKind {
		t.Fatalf("unexpected source: %#v", source)
	}
	if pkg.RawLicense != "MIT" {
		t.Fatalf("raw license = %q", pkg.RawLicense)
	}
	if pkg.LicenseKey != "MIT" {
		t.Fatalf("license key = %q", pkg.LicenseKey)
	}
	if pkg.Repository != "https://github.com/facebook/react" {
		t.Fatalf("repository = %q", pkg.Repository)
	}
	if pkg.MetadataSource != "node-modules" {
		t.Fatalf("metadata source = %q", pkg.MetadataSource)
	}
	if pkg.Provenance.FieldOrigins["licenseKey"] == "" {
		t.Fatalf("field origins = %#v", pkg.Provenance.FieldOrigins)
	}
}

func TestMetadataLookupServiceNodeProjectDirsDeduplicatesRoots(t *testing.T) {
	t.Parallel()

	service := NewMetadataLookupService(MetadataLookupConfig{
		RepositoryRoots: []string{"/repo", "/repo", "/repo-alt"},
	})
	dirs := service.nodeProjectDirs(inventory.Package{Project: "web"})
	expected := []string{filepath.Clean("/repo"), filepath.Clean("/repo-alt"), filepath.Join("/repo", "web"), filepath.Join("/repo-alt", "web")}
	if len(dirs) != len(expected) {
		t.Fatalf("dirs = %#v", dirs)
	}
	for _, want := range expected {
		found := false
		for _, got := range dirs {
			if filepath.Clean(got) == filepath.Clean(want) {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("missing dir %q from %#v", want, dirs)
		}
	}
}

func TestApplyMetadataDoesNotOverwriteExistingFields(t *testing.T) {
	t.Parallel()

	cat, err := catalog.Load(filepath.Join("..", "..", "configs", "licenses.json"))
	if err != nil {
		t.Fatalf("load catalog: %v", err)
	}

	pkg, changed := applyMetadata(inventory.Package{
		RawLicense:     "Apache-2.0",
		LicenseKey:     "Apache-2.0",
		Repository:     "https://example.test/repo",
		Homepage:       "https://example.test",
		MetadataSource: "spdx",
		Provenance: inventory.PackageProvenance{
			FieldOrigins: map[string]string{"repository": "spdx"},
			SourceIDs:    []string{"spdx"},
		},
	}, metadata{
		RawLicense: "MIT",
		Repository: "https://github.com/example/repo",
		Homepage:   "https://react.dev",
		Source:     "node-modules",
	}, cat, "enrich:node-modules")

	if changed {
		t.Fatal("expected no changes")
	}
	if pkg.Repository != "https://example.test/repo" {
		t.Fatalf("repository = %q", pkg.Repository)
	}
	if pkg.MetadataSource != "spdx" {
		t.Fatalf("metadata source = %q", pkg.MetadataSource)
	}
}

func TestMetadataLookupServiceFallbacks(t *testing.T) {
	t.Parallel()

	cat, err := catalog.Load(filepath.Join("..", "..", "configs", "licenses.json"))
	if err != nil {
		t.Fatalf("load catalog: %v", err)
	}

	service := NewMetadataLookupService(MetadataLookupConfig{
		Catalog:         cat,
		RepositoryRoots: []string{"", " /repo ", "/repo"},
	})
	if _, _, changed := service.EnrichPackage(inventory.Package{
		Ecosystem: "generic",
		Name:      "custom",
		Version:   "1.0.0",
	}); changed {
		t.Fatal("expected unsupported ecosystem to skip enrichment")
	}

	pkg, source, changed := service.EnrichPackage(inventory.Package{
		Ecosystem:  "node",
		Project:    "web",
		Name:       "missing-package",
		Version:    "1.0.0",
		LicenseKey: cat.Fallback,
	})
	if changed || source != nil || pkg.Name != "missing-package" {
		t.Fatalf("unexpected fallback enrichment result: %#v %#v %v", pkg, source, changed)
	}

	roots := normalizeRoots([]string{"", " /repo ", "/repo", "/repo-alt"})
	if len(roots) != 2 || roots[0] != "/repo" || roots[1] != "/repo-alt" {
		t.Fatalf("normalizeRoots = %#v", roots)
	}
	if !isMissingLicense("Unknown") || !isMissingLicense("") || isMissingLicense("MIT") {
		t.Fatal("unexpected isMissingLicense result")
	}
	if !isMissingLicenseKey("", cat) || !isMissingLicenseKey(cat.Fallback, cat) || isMissingLicenseKey("MIT", cat) {
		t.Fatal("unexpected isMissingLicenseKey result")
	}
	if isMissingLicenseKey("Unknown", nil) {
		t.Fatal("expected nil catalog to preserve non-empty license key")
	}
}

func TestMetadataLookupServiceEnrichPackageReturnsNoSourceWhenNoChangesApply(t *testing.T) {
	t.Parallel()
	setTestNow(t, time.Date(2031, time.March, 1, 0, 0, 0, 0, time.UTC))

	root := t.TempDir()
	packageDir := filepath.Join(root, "web", "node_modules", "react")
	if err := os.MkdirAll(packageDir, 0o755); err != nil {
		t.Fatalf("mkdir package dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(packageDir, "package.json"), []byte(`{
  "name": "react",
  "version": "19.2.4",
  "license": "MIT",
  "homepage": "https://react.dev",
  "repository": { "url": "https://github.com/facebook/react" },
  "author": { "name": "Meta" }
}`), 0o644); err != nil {
		t.Fatalf("write package.json: %v", err)
	}

	cat, err := catalog.Load(filepath.Join("..", "..", "configs", "licenses.json"))
	if err != nil {
		t.Fatalf("load catalog: %v", err)
	}

	service := NewMetadataLookupService(MetadataLookupConfig{
		Catalog:         cat,
		RepositoryRoots: []string{filepath.Join(root, "web")},
	})
	original := inventory.Package{
		Ecosystem:       "node",
		Project:         "web",
		Name:            "react",
		Version:         "19.2.4",
		RawLicense:      "MIT",
		LicenseKey:      "MIT",
		Repository:      "https://github.com/facebook/react",
		Homepage:        "https://react.dev",
		CopyrightHolder: "Meta",
		CopyrightYear:   2031,
		MetadataSource:  "node-modules",
		Provenance: inventory.PackageProvenance{
			FieldOrigins: map[string]string{
				"repository": "repo-scan",
			},
			SourceIDs: []string{"repo-scan"},
		},
	}

	pkg, source, changed := service.EnrichPackage(original)
	if changed || source != nil {
		t.Fatalf("expected no-op enrichment, got %#v %#v %v", pkg, source, changed)
	}
	if pkg.RawLicense != original.RawLicense ||
		pkg.LicenseKey != original.LicenseKey ||
		pkg.Repository != original.Repository ||
		pkg.Homepage != original.Homepage ||
		pkg.CopyrightHolder != original.CopyrightHolder ||
		pkg.MetadataSource != original.MetadataSource ||
		!slices.Equal(pkg.Provenance.SourceIDs, original.Provenance.SourceIDs) {
		t.Fatalf("package should remain unchanged: %#v", pkg)
	}
}

func TestMetadataLookupServiceLookupBranches(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/react/19.2.4":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{
  "license": "MIT",
  "homepage": "https://react.dev",
  "repository": { "url": "https://github.com/facebook/react" },
  "author": { "name": "Meta" }
}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	cat, err := catalog.Load(filepath.Join("..", "..", "configs", "licenses.json"))
	if err != nil {
		t.Fatalf("load catalog: %v", err)
	}

	service := NewMetadataLookupService(MetadataLookupConfig{
		Client:              server.Client(),
		Catalog:             cat,
		NodeRegistryBaseURL: server.URL,
	})

	meta, ok := service.lookupMetadata(inventory.Package{
		Ecosystem: "node",
		Name:      "react",
		Version:   "19.2.4",
	})
	if !ok || meta.Source != "npm-registry-version" {
		t.Fatalf("node lookup = %#v %v", meta, ok)
	}

	meta, ok = service.lookupMetadata(inventory.Package{
		Ecosystem: "node",
		Name:      "react",
		Version:   "^19.0.0",
	})
	if ok || meta.Source != "fallback" {
		t.Fatalf("node fallback lookup = %#v %v", meta, ok)
	}

	root := t.TempDir()
	packageDir := filepath.Join(root, "newtonsoft.json", "13.0.3")
	if err := os.MkdirAll(packageDir, 0o755); err != nil {
		t.Fatalf("mkdir nuget dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(packageDir, "newtonsoft.json.nuspec"), []byte(`<?xml version="1.0" encoding="utf-8"?>
<package><metadata><authors>James Newton-King</authors><license type="expression">MIT</license></metadata></package>`), 0o644); err != nil {
		t.Fatalf("write nuspec: %v", err)
	}
	service = NewMetadataLookupService(MetadataLookupConfig{
		Catalog:                 cat,
		NuGetGlobalPackagesRoot: root,
	})
	meta, ok = service.lookupMetadata(inventory.Package{
		Ecosystem: "dotnet",
		Name:      "Newtonsoft.Json",
		Version:   "13.0.3",
	})
	if !ok || meta.Source != "nuget-global-packages" {
		t.Fatalf("dotnet lookup = %#v %v", meta, ok)
	}
}

func TestMetadataLookupServiceEnrichPackageUsesDotNetMetadata(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	packageDir := filepath.Join(root, "newtonsoft.json", "13.0.3")
	if err := os.MkdirAll(packageDir, 0o755); err != nil {
		t.Fatalf("mkdir nuget dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(packageDir, "newtonsoft.json.nuspec"), []byte(`<?xml version="1.0" encoding="utf-8"?>
<package>
  <metadata>
    <authors>James Newton-King</authors>
    <projectUrl>https://www.newtonsoft.com/json</projectUrl>
    <repository url="https://github.com/JamesNK/Newtonsoft.Json" />
    <license type="expression">MIT</license>
  </metadata>
</package>`), 0o644); err != nil {
		t.Fatalf("write nuspec: %v", err)
	}

	cat, err := catalog.Load(filepath.Join("..", "..", "configs", "licenses.json"))
	if err != nil {
		t.Fatalf("load catalog: %v", err)
	}

	service := NewMetadataLookupService(MetadataLookupConfig{
		Catalog:                 cat,
		NuGetGlobalPackagesRoot: root,
	})
	pkg, source, changed := service.EnrichPackage(inventory.Package{
		Ecosystem:  "dotnet",
		Name:       "Newtonsoft.Json",
		Version:    "13.0.3",
		RawLicense: "",
		LicenseKey: cat.Fallback,
		Provenance: inventory.PackageProvenance{
			SourceIDs: []string{"repo-scan"},
		},
	})
	if !changed || source == nil || source.Kind != MetadataEnrichmentSourceKind {
		t.Fatalf("dotnet enrich result = %#v %#v %v", pkg, source, changed)
	}
	if pkg.RawLicense != "MIT" || pkg.LicenseKey != "MIT" {
		t.Fatalf("license enrichment = %#v", pkg)
	}
	if pkg.Repository != "https://github.com/JamesNK/Newtonsoft.Json" || pkg.Homepage != "https://www.newtonsoft.com/json" {
		t.Fatalf("url enrichment = %#v", pkg)
	}
	if pkg.MetadataSource != "nuget-global-packages" {
		t.Fatalf("metadata source = %q", pkg.MetadataSource)
	}
	if !slices.Equal(pkg.Provenance.SourceIDs, []string{"enrich:nuget-global-packages", "repo-scan"}) {
		t.Fatalf("source ids = %#v", pkg.Provenance.SourceIDs)
	}
}

func TestApplyMetadataHelperBranches(t *testing.T) {
	t.Parallel()

	cat, err := catalog.Load(filepath.Join("..", "..", "configs", "licenses.json"))
	if err != nil {
		t.Fatalf("load catalog: %v", err)
	}

	pkg, changed := applyMetadata(inventory.Package{
		RawLicense: "MIT",
		LicenseKey: "MIT",
		Provenance: inventory.PackageProvenance{
			SourceIDs: []string{"sbom"},
		},
	}, metadata{
		RawLicense: "",
		Source:     "node-modules",
	}, cat, "enrich:node-modules")
	if changed {
		t.Fatalf("expected empty metadata to be ignored: %#v", pkg)
	}

	pkg, changed = applyMetadata(inventory.Package{
		RawLicense: "Unknown",
		LicenseKey: cat.Fallback,
		Provenance: inventory.PackageProvenance{
			SourceIDs: []string{"sbom"},
		},
	}, metadata{
		RawLicense: "Unknown",
		Source:     "node-modules",
	}, cat, "enrich:node-modules")
	if !changed || pkg.LicenseKey != "Unknown" || pkg.MetadataSource != "node-modules" {
		t.Fatalf("expected unknown license metadata to seed fallback values: %#v %v", pkg, changed)
	}

	pkg, changed = applyMetadata(inventory.Package{
		RawLicense:     "MIT",
		LicenseKey:     "MIT",
		MetadataSource: "node-modules",
		Provenance: inventory.PackageProvenance{
			FieldOrigins: map[string]string{},
			SourceIDs:    []string{"repo-scan"},
		},
	}, metadata{
		Homepage: "https://react.dev",
		Source:   "node-modules",
	}, cat, "enrich:node-modules")
	if !changed || pkg.MetadataSource != "node-modules" || pkg.Homepage != "https://react.dev" {
		t.Fatalf("same-source metadata apply = %#v %v", pkg, changed)
	}

	pkg, changed = applyMetadata(inventory.Package{
		RawLicense:     "MIT",
		LicenseKey:     "MIT",
		MetadataSource: "spdx-json",
		Provenance: inventory.PackageProvenance{
			FieldOrigins: map[string]string{},
			SourceIDs:    []string{"sbom"},
		},
	}, metadata{
		Repository: "https://github.com/facebook/react",
		Source:     "node-modules",
	}, cat, "enrich:node-modules")
	if !changed || pkg.MetadataSource != "merged" {
		t.Fatalf("merged metadata source = %#v %v", pkg, changed)
	}

	pkg, changed = applyMetadata(inventory.Package{
		RawLicense:     "MIT",
		LicenseKey:     "MIT",
		Provenance:     inventory.PackageProvenance{},
		Project:        "web",
		Name:           "react",
		Version:        "19.2.4",
		Repository:     "",
		Homepage:       "",
		MetadataSource: "",
	}, metadata{
		Repository:          "https://github.com/facebook/react",
		Homepage:            "https://react.dev",
		Holder:              "Meta",
		Year:                2024,
		EmbeddedLicensePath: "LICENSE.txt",
		EmbeddedLicenseText: "license text",
		Source:              "node-modules",
	}, cat, "enrich:node-modules")
	if !changed {
		t.Fatal("expected metadata fields to be applied")
	}
	if pkg.CopyrightHolder != "Meta" || pkg.CopyrightYear != 2024 {
		t.Fatalf("copyright metadata = %#v", pkg)
	}
	if pkg.EmbeddedLicensePath != "LICENSE.txt" || pkg.EmbeddedLicenseText != "license text" {
		t.Fatalf("embedded license metadata = %#v", pkg)
	}
	if pkg.MetadataSource != "node-modules" {
		t.Fatalf("metadata source = %q", pkg.MetadataSource)
	}
	for _, field := range []string{"repository", "homepage", "copyrightHolder", "copyrightYear", "embeddedLicensePath", "embeddedLicenseText", "metadataSource"} {
		if pkg.Provenance.FieldOrigins[field] != "enrich:node-modules" {
			t.Fatalf("field origin %s = %#v", field, pkg.Provenance.FieldOrigins)
		}
	}
	if !slices.Equal(pkg.Provenance.SourceIDs, []string{"enrich:node-modules"}) {
		t.Fatalf("source ids = %#v", pkg.Provenance.SourceIDs)
	}
}

func TestUniqueNonEmptyTrimsSortsAndDedupes(t *testing.T) {
	t.Parallel()

	got := uniqueNonEmpty([]string{" /repo-b ", "", "/repo-a", "/repo-b"})
	if !slices.Equal(got, []string{"/repo-a", "/repo-b"}) {
		t.Fatalf("uniqueNonEmpty = %#v", got)
	}
}

func TestMetadataLookupServiceNodeProjectDirsOmitsBlankProjectPaths(t *testing.T) {
	t.Parallel()

	service := NewMetadataLookupService(MetadataLookupConfig{
		RepositoryRoots: []string{"/repo-b", "/repo-a", "/repo-a"},
	})
	dirs := service.nodeProjectDirs(inventory.Package{})
	if !slices.Equal(dirs, []string{"/repo-a", "/repo-b"}) {
		t.Fatalf("dirs = %#v", dirs)
	}
}

func TestMetadataLookupServiceDotNetFallbackLookupReturnsNotFound(t *testing.T) {
	t.Parallel()

	service := NewMetadataLookupService(MetadataLookupConfig{})
	meta, ok := service.lookupMetadata(inventory.Package{
		Ecosystem: "dotnet",
		Name:      "Missing.Package",
		Version:   "1.0.0",
	})
	if ok || meta.Source != "fallback" {
		t.Fatalf("dotnet fallback lookup = %#v %v", meta, ok)
	}
}
