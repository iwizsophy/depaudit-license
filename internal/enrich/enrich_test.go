package enrich

import (
	"archive/zip"
	"bytes"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"depaudit-license/internal/catalog"
	"depaudit-license/internal/inventory"
)

func applyAll(cfg Config, doc inventory.Document) (inventory.Document, error) {
	result, err := ApplyLocal(cfg, doc)
	if err != nil {
		return inventory.Document{}, err
	}
	return ApplyRemote(cfg, result)
}

func TestApplyFillsMissingNodeMetadataWithoutOverwritingSBOMValues(t *testing.T) {
	t.Parallel()

	cat, err := catalog.Load(filepath.Join("..", "..", "configs", "licenses.json"))
	if err != nil {
		t.Fatalf("load catalog: %v", err)
	}

	root := t.TempDir()
	packageDir := filepath.Join(root, "client", "node_modules", "react")
	if err := os.MkdirAll(packageDir, 0o755); err != nil {
		t.Fatalf("mkdir package dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(packageDir, "package.json"), []byte(`{
  "name": "react",
  "version": "18.2.0",
  "license": "MIT",
  "homepage": "https://react.dev/",
  "repository": { "url": "https://github.com/facebook/react" },
  "author": { "name": "Meta" }
}`), 0o644); err != nil {
		t.Fatalf("write package.json: %v", err)
	}

	doc := inventory.Document{
		Sources: []inventory.Source{{
			ID:       "spdx",
			Kind:     "spdx-json",
			Location: "/tmp/app.spdx.json",
		}},
		Packages: []inventory.Package{{
			Provenance: inventory.PackageProvenance{
				SourceIDs: []string{"spdx"},
				FieldOrigins: map[string]string{
					"ecosystem":      "spdx",
					"project":        "spdx",
					"name":           "spdx",
					"version":        "spdx",
					"homepage":       "spdx",
					"metadataSource": "spdx",
				},
			},
			Ecosystem:      "node",
			Project:        "client",
			Name:           "react",
			Version:        "18.2.0",
			Homepage:       "https://sbom.example/react",
			MetadataSource: "spdx-json",
		}},
	}

	enriched, err := applyAll(Config{
		Catalog:         cat,
		RepositoryRoots: []string{root},
	}, doc)
	if err != nil {
		t.Fatalf("apply enrichment: %v", err)
	}

	pkg := enriched.Packages[0]
	if pkg.Repository != "https://github.com/facebook/react" {
		t.Fatalf("repository = %q", pkg.Repository)
	}
	if pkg.Homepage != "https://sbom.example/react" {
		t.Fatalf("homepage = %q", pkg.Homepage)
	}
	if pkg.RawLicense != "MIT" || pkg.LicenseKey != "MIT" {
		t.Fatalf("license = %q / %q", pkg.RawLicense, pkg.LicenseKey)
	}
	if pkg.MetadataSource != "merged" {
		t.Fatalf("metadata source = %q", pkg.MetadataSource)
	}
	if pkg.Provenance.FieldOrigins["repository"] != "enrich:node-modules" {
		t.Fatalf("repository origin = %q", pkg.Provenance.FieldOrigins["repository"])
	}
	if pkg.Provenance.FieldOrigins["homepage"] != "spdx" {
		t.Fatalf("homepage origin = %q", pkg.Provenance.FieldOrigins["homepage"])
	}
	if len(enriched.Sources) != 2 {
		t.Fatalf("sources = %#v", enriched.Sources)
	}
	if pkg.Provenance.ArtifactResolution == nil || pkg.Provenance.ArtifactResolution.Kind != "local-package-manager" || pkg.Provenance.ArtifactResolution.Detail != "node-modules" {
		t.Fatalf("artifact resolution = %#v", pkg.Provenance.ArtifactResolution)
	}
}

func TestApplyUsesRegistryAndGlobalPackagesForMissingMetadata(t *testing.T) {
	t.Parallel()

	cat, err := catalog.Load(filepath.Join("..", "..", "configs", "licenses.json"))
	if err != nil {
		t.Fatalf("load catalog: %v", err)
	}

	root := t.TempDir()
	packageDir := filepath.Join(root, "newtonsoft.json", "13.0.3")
	if err := os.MkdirAll(packageDir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	nuspec := `<?xml version="1.0" encoding="utf-8"?>
<package>
  <metadata>
    <id>Newtonsoft.Json</id>
    <version>13.0.3</version>
    <authors>James Newton-King</authors>
    <projectUrl>https://www.newtonsoft.com/json</projectUrl>
    <license type="expression">MIT</license>
    <repository url="https://github.com/JamesNK/Newtonsoft.Json" />
  </metadata>
</package>`
	if err := os.WriteFile(filepath.Join(packageDir, "newtonsoft.json.nuspec"), []byte(nuspec), 0o644); err != nil {
		t.Fatalf("write nuspec: %v", err)
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/react/18.2.0" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
  "license": "MIT",
  "homepage": "https://react.dev",
  "repository": { "url": "https://github.com/facebook/react" },
  "author": { "name": "Meta" }
}`))
	}))
	defer server.Close()

	doc := inventory.Document{
		Sources: []inventory.Source{{
			ID:       "sbom",
			Kind:     "cyclonedx-json",
			Location: "/tmp/app.cdx.json",
		}},
		Packages: []inventory.Package{
			{
				Provenance: inventory.PackageProvenance{
					SourceIDs: []string{"sbom"},
				},
				Ecosystem: "node",
				Name:      "react",
				Version:   "18.2.0",
			},
			{
				Provenance: inventory.PackageProvenance{
					SourceIDs: []string{"sbom"},
				},
				Ecosystem: "dotnet",
				Name:      "Newtonsoft.Json",
				Version:   "13.0.3",
			},
		},
	}

	enriched, err := applyAll(Config{
		Client:                  server.Client(),
		Catalog:                 cat,
		NodeRegistryBaseURL:     server.URL,
		NuGetGlobalPackagesRoot: root,
	}, doc)
	if err != nil {
		t.Fatalf("apply enrichment: %v", err)
	}

	nodePkg := enriched.Packages[0]
	if nodePkg.Repository != "https://github.com/facebook/react" {
		t.Fatalf("node repository = %q", nodePkg.Repository)
	}
	if nodePkg.MetadataSource != "npm-registry-version" {
		t.Fatalf("node metadata source = %q", nodePkg.MetadataSource)
	}

	nugetPkg := enriched.Packages[1]
	if nugetPkg.Repository != "https://github.com/JamesNK/Newtonsoft.Json" {
		t.Fatalf("nuget repository = %q", nugetPkg.Repository)
	}
	if nugetPkg.MetadataSource != "nuget-global-packages" {
		t.Fatalf("nuget metadata source = %q", nugetPkg.MetadataSource)
	}
	if nugetPkg.Provenance.ArtifactResolution == nil || nugetPkg.Provenance.ArtifactResolution.Kind != "local-package-manager" || nugetPkg.Provenance.ArtifactResolution.Detail != "nuget-global-packages" {
		t.Fatalf("nuget artifact resolution = %#v", nugetPkg.Provenance.ArtifactResolution)
	}
}

func TestApplyMarksRemoteNuGetArtifactFallbackForReview(t *testing.T) {
	t.Parallel()

	cat, err := catalog.Load(filepath.Join("..", "..", "configs", "licenses.json"))
	if err != nil {
		t.Fatalf("load catalog: %v", err)
	}

	var archive bytes.Buffer
	writer := zip.NewWriter(&archive)
	nuspec, err := writer.Create("Sample.Package.nuspec")
	if err != nil {
		t.Fatalf("create nuspec: %v", err)
	}
	if _, err := nuspec.Write([]byte(`<?xml version="1.0" encoding="utf-8"?>
<package>
  <metadata>
    <id>Sample.Package</id>
    <version>1.2.3</version>
    <authors>Sample Author</authors>
    <license type="file">LICENSE.txt</license>
  </metadata>
</package>`)); err != nil {
		t.Fatalf("write nuspec: %v", err)
	}
	licenseFile, err := writer.Create("LICENSE.txt")
	if err != nil {
		t.Fatalf("create license: %v", err)
	}
	if _, err := licenseFile.Write([]byte("MIT License\n\nCopyright (c) 2024 Example")); err != nil {
		t.Fatalf("write license: %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("close archive: %v", err)
	}

	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/sample.package/1.2.3.json":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"catalogEntry":"` + server.URL + `/catalog/sample.package.1.2.3.json","packageContent":"` + server.URL + `/package/sample.package.1.2.3.nupkg"}`))
		case "/catalog/sample.package.1.2.3.json":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"authors":"Sample Author","projectUrl":"https://example.test/sample","published":"2024-02-03T00:00:00Z"}`))
		case "/package/sample.package.1.2.3.nupkg":
			w.Header().Set("Content-Type", "application/octet-stream")
			_, _ = w.Write(archive.Bytes())
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	doc := inventory.Document{
		Sources: []inventory.Source{{
			ID:       "sbom",
			Kind:     "spdx-json",
			Location: "/tmp/app.spdx.json",
		}},
		Packages: []inventory.Package{{
			Provenance: inventory.PackageProvenance{
				SourceIDs: []string{"sbom"},
			},
			Ecosystem:  "dotnet",
			Name:       "Sample.Package",
			Version:    "1.2.3",
			LicenseKey: cat.Fallback,
		}},
	}

	enriched, err := applyAll(Config{
		Client:                   server.Client(),
		Catalog:                  cat,
		NuGetGlobalPackagesRoot:  filepath.Join(t.TempDir(), "missing"),
		NuGetRegistrationBaseURL: server.URL,
	}, doc)
	if err != nil {
		t.Fatalf("apply enrichment: %v", err)
	}

	pkg := enriched.Packages[0]
	if pkg.Provenance.ArtifactResolution == nil {
		t.Fatal("expected artifact resolution")
	}
	if pkg.Provenance.ArtifactResolution.Kind != "remote-package-content" || !pkg.Provenance.ArtifactResolution.ReviewRequired {
		t.Fatalf("artifact resolution = %#v", pkg.Provenance.ArtifactResolution)
	}
	if len(enriched.Diagnostics) != 1 || enriched.Diagnostics[0].Code != "remote_resolution_fallback_used" || enriched.Diagnostics[0].Severity != "warning" {
		t.Fatalf("diagnostics = %#v", enriched.Diagnostics)
	}
	if !strings.Contains(enriched.Diagnostics[0].Message, "manual review required") {
		t.Fatalf("diagnostic message = %#v", enriched.Diagnostics[0])
	}
}

func TestApplyMarksRemoteMetadataFallbackForReviewWithoutMetadataOverwrite(t *testing.T) {
	t.Parallel()

	cat, err := catalog.Load(filepath.Join("..", "..", "configs", "licenses.json"))
	if err != nil {
		t.Fatalf("load catalog: %v", err)
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/react/18.2.0" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
  "license": "MIT",
  "homepage": "https://react.dev",
  "repository": { "url": "https://github.com/facebook/react" },
  "author": { "name": "Meta" }
}`))
	}))
	defer server.Close()

	doc := inventory.Document{
		Sources: []inventory.Source{{
			ID:       "sbom",
			Kind:     "cyclonedx-json",
			Location: "/tmp/app.cdx.json",
		}},
		Packages: []inventory.Package{{
			Provenance: inventory.PackageProvenance{
				SourceIDs: []string{"sbom"},
			},
			Ecosystem:       "node",
			Name:            "react",
			Version:         "18.2.0",
			RawLicense:      "MIT",
			LicenseKey:      "MIT",
			Repository:      "https://github.com/facebook/react",
			Homepage:        "https://react.dev",
			CopyrightHolder: "Meta",
			CopyrightYear:   2026,
			MetadataSource:  "cyclonedx-json",
		}},
	}

	enriched, err := applyAll(Config{
		Client:              server.Client(),
		Catalog:             cat,
		NodeRegistryBaseURL: server.URL,
	}, doc)
	if err != nil {
		t.Fatalf("apply enrichment: %v", err)
	}

	if len(enriched.Sources) != 1 {
		t.Fatalf("sources = %#v", enriched.Sources)
	}
	pkg := enriched.Packages[0]
	if pkg.MetadataSource != "cyclonedx-json" || !slices.Equal(pkg.Provenance.SourceIDs, []string{"sbom"}) {
		t.Fatalf("package should keep source provenance = %#v", pkg)
	}
	if pkg.Provenance.ArtifactResolution == nil || pkg.Provenance.ArtifactResolution.Kind != "remote-metadata" || !pkg.Provenance.ArtifactResolution.ReviewRequired {
		t.Fatalf("artifact resolution = %#v", pkg.Provenance.ArtifactResolution)
	}
	if len(enriched.Diagnostics) != 1 || enriched.Diagnostics[0].Code != "remote_resolution_fallback_used" {
		t.Fatalf("diagnostics = %#v", enriched.Diagnostics)
	}
}

func TestApplyKeepsExistingEnrichmentSourceAndSortsSources(t *testing.T) {
	t.Parallel()

	cat, err := catalog.Load(filepath.Join("..", "..", "configs", "licenses.json"))
	if err != nil {
		t.Fatalf("load catalog: %v", err)
	}

	root := t.TempDir()
	packageDir := filepath.Join(root, "client", "node_modules", "react")
	if err := os.MkdirAll(packageDir, 0o755); err != nil {
		t.Fatalf("mkdir package dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(packageDir, "package.json"), []byte(`{
  "name": "react",
  "version": "18.2.0",
  "license": "MIT",
  "homepage": "https://react.dev/",
  "repository": { "url": "https://github.com/facebook/react" },
  "author": { "name": "Meta" }
}`), 0o644); err != nil {
		t.Fatalf("write package.json: %v", err)
	}

	doc := inventory.Document{
		Sources: []inventory.Source{
			{ID: "z-source", Kind: "manual", Location: "/tmp/z"},
			{ID: "enrich:node-modules", Kind: "metadata-enrichment", Location: "node-modules"},
			{ID: "a-source", Kind: "manual", Location: "/tmp/a"},
		},
		Packages: []inventory.Package{{
			Provenance: inventory.PackageProvenance{
				SourceIDs: []string{"sbom"},
			},
			Ecosystem: "node",
			Project:   "client",
			Name:      "react",
			Version:   "18.2.0",
		}},
	}

	enriched, err := applyAll(Config{
		Catalog:         cat,
		RepositoryRoots: []string{root},
	}, doc)
	if err != nil {
		t.Fatalf("apply enrichment: %v", err)
	}

	if len(enriched.Sources) != 3 {
		t.Fatalf("sources = %#v", enriched.Sources)
	}
	if got := []string{enriched.Sources[0].ID, enriched.Sources[1].ID, enriched.Sources[2].ID}; !slices.Equal(got, []string{"a-source", "enrich:node-modules", "z-source"}) {
		t.Fatalf("sorted source ids = %#v", got)
	}
}

func TestApplyClonesDocumentBeforeMutatingEnrichedPackages(t *testing.T) {
	t.Parallel()

	cat, err := catalog.Load(filepath.Join("..", "..", "configs", "licenses.json"))
	if err != nil {
		t.Fatalf("load catalog: %v", err)
	}

	root := t.TempDir()
	packageDir := filepath.Join(root, "client", "node_modules", "react")
	if err := os.MkdirAll(packageDir, 0o755); err != nil {
		t.Fatalf("mkdir package dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(packageDir, "package.json"), []byte(`{
  "name": "react",
  "version": "18.2.0",
  "license": "MIT",
  "repository": { "url": "https://github.com/facebook/react" }
}`), 0o644); err != nil {
		t.Fatalf("write package.json: %v", err)
	}

	doc := inventory.Document{
		Sources: []inventory.Source{{ID: "sbom", Kind: "spdx-json", Location: "/tmp/app.spdx.json"}},
		Packages: []inventory.Package{{
			Provenance: inventory.PackageProvenance{
				SourceIDs:      []string{"sbom"},
				FieldOrigins:   map[string]string{"repository": "sbom"},
				ConflictFields: []string{"license"},
			},
			Ecosystem:      "node",
			Project:        "client",
			Name:           "react",
			Version:        "18.2.0",
			Repository:     "https://sbom.example/react",
			MetadataSource: "spdx-json",
		}},
		Conflicts: []inventory.Conflict{{
			Identity: "node:react@18.2.0",
			Field:    "repository",
			Values: []inventory.ConflictValue{{
				SourceID: "sbom",
				Value:    "https://sbom.example/react",
			}},
		}},
	}

	originalPackage := doc.Packages[0]
	originalConflicts := append([]inventory.ConflictValue(nil), doc.Conflicts[0].Values...)

	enriched, err := applyAll(Config{
		Catalog:         cat,
		RepositoryRoots: []string{root},
	}, doc)
	if err != nil {
		t.Fatalf("apply enrichment: %v", err)
	}

	if doc.Packages[0].Repository != originalPackage.Repository || doc.Packages[0].MetadataSource != originalPackage.MetadataSource {
		t.Fatalf("original package mutated = %#v", doc.Packages[0])
	}
	if !slices.Equal(doc.Packages[0].Provenance.SourceIDs, originalPackage.Provenance.SourceIDs) {
		t.Fatalf("original source ids mutated = %#v", doc.Packages[0].Provenance.SourceIDs)
	}
	if doc.Packages[0].Provenance.FieldOrigins["repository"] != "sbom" {
		t.Fatalf("original field origins mutated = %#v", doc.Packages[0].Provenance.FieldOrigins)
	}
	if !slices.Equal(doc.Packages[0].Provenance.ConflictFields, originalPackage.Provenance.ConflictFields) {
		t.Fatalf("original conflict fields mutated = %#v", doc.Packages[0].Provenance.ConflictFields)
	}
	if !slices.Equal(doc.Conflicts[0].Values, originalConflicts) {
		t.Fatalf("original conflicts mutated = %#v", doc.Conflicts)
	}

	if enriched.Packages[0].Repository != "https://sbom.example/react" {
		t.Fatalf("enriched repository = %q", enriched.Packages[0].Repository)
	}
	if enriched.Packages[0].MetadataSource != "merged" {
		t.Fatalf("enriched metadata source = %q", enriched.Packages[0].MetadataSource)
	}
	if !slices.Equal(enriched.Packages[0].Provenance.SourceIDs, []string{"enrich:node-modules", "sbom"}) {
		t.Fatalf("enriched source ids = %#v", enriched.Packages[0].Provenance.SourceIDs)
	}
	if enriched.Packages[0].Provenance.FieldOrigins["metadataSource"] != "enrich:node-modules" {
		t.Fatalf("enriched field origins = %#v", enriched.Packages[0].Provenance.FieldOrigins)
	}
}

func TestApplyRegistersSharedEnrichmentSourceOnce(t *testing.T) {
	t.Parallel()

	cat, err := catalog.Load(filepath.Join("..", "..", "configs", "licenses.json"))
	if err != nil {
		t.Fatalf("load catalog: %v", err)
	}

	root := t.TempDir()
	for _, packageName := range []string{"react", "react-dom"} {
		packageDir := filepath.Join(root, "client", "node_modules", packageName)
		if err := os.MkdirAll(packageDir, 0o755); err != nil {
			t.Fatalf("mkdir package dir: %v", err)
		}
		if err := os.WriteFile(filepath.Join(packageDir, "package.json"), []byte(`{
  "name": "`+packageName+`",
  "version": "18.2.0",
  "license": "MIT"
}`), 0o644); err != nil {
			t.Fatalf("write package.json: %v", err)
		}
	}

	doc := inventory.Document{
		Sources: []inventory.Source{{ID: "sbom", Kind: "cyclonedx-json", Location: "/tmp/app.cdx.json"}},
		Packages: []inventory.Package{
			{
				Provenance: inventory.PackageProvenance{SourceIDs: []string{"sbom"}},
				Ecosystem:  "node",
				Project:    "client",
				Name:       "react",
				Version:    "18.2.0",
			},
			{
				Provenance: inventory.PackageProvenance{SourceIDs: []string{"sbom"}},
				Ecosystem:  "node",
				Project:    "client",
				Name:       "react-dom",
				Version:    "18.2.0",
			},
		},
	}

	enriched, err := applyAll(Config{
		Catalog:         cat,
		RepositoryRoots: []string{root},
	}, doc)
	if err != nil {
		t.Fatalf("apply enrichment: %v", err)
	}

	if len(enriched.Sources) != 2 {
		t.Fatalf("sources = %#v", enriched.Sources)
	}
	if got := []string{enriched.Sources[0].ID, enriched.Sources[1].ID}; !slices.Equal(got, []string{"enrich:node-modules", "sbom"}) {
		t.Fatalf("source ids = %#v", got)
	}
	for _, pkg := range enriched.Packages {
		if !slices.Equal(pkg.Provenance.SourceIDs, []string{"enrich:node-modules", "sbom"}) {
			t.Fatalf("package source ids for %s = %#v", pkg.Name, pkg.Provenance.SourceIDs)
		}
	}
}

func TestApplyWithoutMetadataChangePreservesDocument(t *testing.T) {
	t.Parallel()

	doc := inventory.Document{
		Sources: []inventory.Source{
			{ID: "z-source", Kind: "manual", Location: "/tmp/z"},
			{ID: "a-source", Kind: "manual", Location: "/tmp/a"},
		},
		Packages: []inventory.Package{{
			Ecosystem: "python",
			Name:      "requests",
			Version:   "2.31.0",
		}},
		Conflicts: []inventory.Conflict{{
			Identity: "python:requests@2.31.0",
			Field:    "license",
		}},
	}

	enriched, err := applyAll(Config{}, doc)
	if err != nil {
		t.Fatalf("apply enrichment: %v", err)
	}

	if got := []string{enriched.Sources[0].ID, enriched.Sources[1].ID}; !slices.Equal(got, []string{"a-source", "z-source"}) {
		t.Fatalf("sorted source ids = %#v", got)
	}
	if len(enriched.Packages) != 1 || enriched.Packages[0].Name != "requests" {
		t.Fatalf("packages = %#v", enriched.Packages)
	}
	if len(enriched.Conflicts) != 1 || enriched.Conflicts[0].Identity != "python:requests@2.31.0" {
		t.Fatalf("conflicts = %#v", enriched.Conflicts)
	}
}

func TestClonePackagesClonesSlicesWhilePreservingNilOrigins(t *testing.T) {
	t.Parallel()

	var nilOrigins map[string]string
	source := []inventory.Package{
		{
			Name: "react",
			Provenance: inventory.PackageProvenance{
				SourceIDs:      []string{"sbom"},
				ConflictFields: []string{"license"},
				FieldOrigins:   nilOrigins,
			},
		},
	}

	cloned := clonePackages(source)
	if len(cloned) != 1 {
		t.Fatalf("cloned = %#v", cloned)
	}
	if cloned[0].Provenance.FieldOrigins != nil {
		t.Fatalf("expected nil field origins, got %#v", cloned[0].Provenance.FieldOrigins)
	}
	cloned[0].Provenance.SourceIDs[0] = "mutated"
	cloned[0].Provenance.ConflictFields[0] = "mutated"
	if source[0].Provenance.SourceIDs[0] != "sbom" {
		t.Fatalf("source ids mutated = %#v", source[0].Provenance.SourceIDs)
	}
	if source[0].Provenance.ConflictFields[0] != "license" {
		t.Fatalf("conflict fields mutated = %#v", source[0].Provenance.ConflictFields)
	}
}

func TestCloneDocumentClonesDiagnostics(t *testing.T) {
	t.Parallel()

	doc := inventory.Document{
		Sources: []inventory.Source{{ID: "repo"}},
		Diagnostics: []inventory.Diagnostic{{
			SourceID:          "repo",
			RuleID:            "omit-analyzer-subgraph",
			Code:              "subgraph-exclude-applied",
			Severity:          "info",
			Message:           "applied",
			MatchedRoots:      []string{"Analyzer.Core/1.0.0"},
			RemovedPackages:   []string{"Analyzer.Core/1.0.0"},
			PreservedPackages: []string{"Shared.Lib/1.0.0"},
		}},
	}

	cloned := cloneDocument(doc)
	if len(cloned.Diagnostics) != 1 {
		t.Fatalf("diagnostics = %#v", cloned.Diagnostics)
	}
	cloned.Diagnostics[0].MatchedRoots[0] = "mutated"
	cloned.Diagnostics[0].RemovedPackages[0] = "mutated"
	cloned.Diagnostics[0].PreservedPackages[0] = "mutated"
	if doc.Diagnostics[0].MatchedRoots[0] != "Analyzer.Core/1.0.0" || doc.Diagnostics[0].RemovedPackages[0] != "Analyzer.Core/1.0.0" || doc.Diagnostics[0].PreservedPackages[0] != "Shared.Lib/1.0.0" {
		t.Fatalf("source diagnostics mutated = %#v", doc.Diagnostics)
	}

	if got := cloneDiagnostics(nil); got != nil {
		t.Fatalf("cloneDiagnostics nil = %#v", got)
	}
}
