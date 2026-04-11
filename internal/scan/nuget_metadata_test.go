package scan

import (
	"archive/zip"
	"bytes"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func setTestNow(t *testing.T, instant time.Time) {
	t.Helper()
	previous := now
	now = func() time.Time { return instant }
	t.Cleanup(func() {
		now = previous
	})
}

func TestNugetResolverUsesGlobalPackagesNuspec(t *testing.T) {
	setTestNow(t, time.Date(2031, time.March, 1, 0, 0, 0, 0, time.UTC))

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
    <copyright>Copyright © James Newton-King 2008</copyright>
  </metadata>
</package>`
	if err := os.WriteFile(filepath.Join(packageDir, "newtonsoft.json.nuspec"), []byte(nuspec), 0o644); err != nil {
		t.Fatalf("write nuspec: %v", err)
	}

	resolver := &nugetResolver{
		cache:              map[string]metadata{},
		globalPackagesRoot: root,
	}

	meta := resolver.resolve("Newtonsoft.Json", "13.0.3")
	if meta.RawLicense != "MIT" {
		t.Fatalf("license = %q, want MIT", meta.RawLicense)
	}
	if meta.Repository != "https://github.com/JamesNK/Newtonsoft.Json" {
		t.Fatalf("repository = %q", meta.Repository)
	}
	if meta.Holder != "James Newton-King" {
		t.Fatalf("holder = %q", meta.Holder)
	}
	if meta.Source != "nuget-global-packages" {
		t.Fatalf("source = %q", meta.Source)
	}
	if meta.ArtifactResolution == nil || meta.ArtifactResolution.Kind != "local-package-manager" || meta.ArtifactResolution.Detail != "nuget-global-packages" || meta.ArtifactResolution.ReviewRequired {
		t.Fatalf("artifact resolution = %#v", meta.ArtifactResolution)
	}
}

func TestNugetResolverReadsEmbeddedLicenseFileFromGlobalPackages(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	packageDir := filepath.Join(root, "sample.package", "1.2.3")
	if err := os.MkdirAll(packageDir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	nuspec := `<?xml version="1.0" encoding="utf-8"?>
<package>
  <metadata>
    <id>Sample.Package</id>
    <version>1.2.3</version>
    <authors>Sample Author</authors>
    <license type="file">LICENSE.txt</license>
  </metadata>
</package>`
	if err := os.WriteFile(filepath.Join(packageDir, "sample.package.nuspec"), []byte(nuspec), 0o644); err != nil {
		t.Fatalf("write nuspec: %v", err)
	}
	if err := os.WriteFile(filepath.Join(packageDir, "LICENSE.txt"), []byte("embedded license body"), 0o644); err != nil {
		t.Fatalf("write license file: %v", err)
	}

	resolver := &nugetResolver{
		cache:              map[string]metadata{},
		globalPackagesRoot: root,
	}

	meta := resolver.resolve("Sample.Package", "1.2.3")
	if meta.EmbeddedLicensePath != "LICENSE.txt" {
		t.Fatalf("license path = %q", meta.EmbeddedLicensePath)
	}
	if meta.EmbeddedLicenseText != "embedded license body" {
		t.Fatalf("license text = %q", meta.EmbeddedLicenseText)
	}
}

func TestNugetResolverGlobalPackagesFieldFallbacks(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	packageDir := filepath.Join(root, "fallback.package", "1.0.0")
	if err := os.MkdirAll(packageDir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	nuspec := `<?xml version="1.0" encoding="utf-8"?>
<package>
  <metadata>
    <id>Fallback.Package</id>
    <version>1.0.0</version>
    <owners>Fallback Owner</owners>
  </metadata>
</package>`
	if err := os.WriteFile(filepath.Join(packageDir, "fallback.package.nuspec"), []byte(nuspec), 0o644); err != nil {
		t.Fatalf("write nuspec: %v", err)
	}

	meta, ok, err := (&nugetResolver{globalPackagesRoot: root}).resolveFromGlobalPackages("Fallback.Package", "1.0.0")
	if err != nil {
		t.Fatalf("resolveFromGlobalPackages: %v", err)
	}
	if !ok {
		t.Fatal("expected global packages lookup to succeed")
	}
	if meta.Holder != "Fallback Owner" || meta.RawLicense != "Unknown" {
		t.Fatalf("global fallback metadata = %#v", meta)
	}
}

func TestNugetResolverFallsBackToRegistration(t *testing.T) {
	t.Parallel()

	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/sample.package/1.2.3.json":
			_, _ = w.Write([]byte(`{"catalogEntry":"` + server.URL + `/catalog/sample.package.1.2.3.json"}`))
		case "/catalog/sample.package.1.2.3.json":
			_, _ = w.Write([]byte(`{
  "authors":"Sample Author",
  "copyright":"Copyright 2024 Sample",
  "licenseExpression":"Apache-2.0",
  "licenseUrl":"https://licenses.nuget.org/Apache-2.0",
  "projectUrl":"https://example.test/sample",
  "repository":"https://github.com/example/sample",
  "published":"2024-02-03T00:00:00Z"
}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	resolver := &nugetResolver{
		client:              server.Client(),
		cache:               map[string]metadata{},
		globalPackagesRoot:  filepath.Join(t.TempDir(), "missing"),
		registrationBaseURL: server.URL,
	}

	meta := resolver.resolve("Sample.Package", "1.2.3")
	if meta.RawLicense != "Apache-2.0" {
		t.Fatalf("license = %q, want Apache-2.0", meta.RawLicense)
	}
	if meta.Repository != "https://github.com/example/sample" {
		t.Fatalf("repository = %q", meta.Repository)
	}
	if meta.Holder != "Sample Author" {
		t.Fatalf("holder = %q", meta.Holder)
	}
	if meta.Source != "nuget-registration" {
		t.Fatalf("source = %q", meta.Source)
	}
	if meta.ArtifactResolution == nil || meta.ArtifactResolution.Kind != "remote-metadata" || meta.ArtifactResolution.Detail != "nuget-registration" || !meta.ArtifactResolution.ReviewRequired {
		t.Fatalf("artifact resolution = %#v", meta.ArtifactResolution)
	}
}

func TestNugetResolverReadsEmbeddedLicenseFileFromPackageArchive(t *testing.T) {
	t.Parallel()

	archive := buildTestNugetArchive(t, map[string]string{
		"Sample.Package.nuspec": `<?xml version="1.0" encoding="utf-8"?>
<package>
  <metadata>
    <id>Sample.Package</id>
    <version>1.2.3</version>
    <authors>Sample Author</authors>
    <license type="file">LICENSE.txt</license>
  </metadata>
</package>`,
		"LICENSE.txt": "archive embedded license",
	})

	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/sample.package/1.2.3.json":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"catalogEntry":"` + server.URL + `/catalog/sample.package.1.2.3.json","packageContent":"` + server.URL + `/package/sample.package.1.2.3.nupkg"}`))
		case "/catalog/sample.package.1.2.3.json":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"authors":"Sample Author","projectUrl":"https://example.test/sample","repository":"","published":"2024-02-03T00:00:00Z"}`))
		case "/package/sample.package.1.2.3.nupkg":
			w.Header().Set("Content-Type", "application/octet-stream")
			_, _ = w.Write(archive)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	resolver := &nugetResolver{
		client:              server.Client(),
		cache:               map[string]metadata{},
		globalPackagesRoot:  filepath.Join(t.TempDir(), "missing"),
		registrationBaseURL: server.URL,
	}

	meta := resolver.resolve("Sample.Package", "1.2.3")
	if meta.EmbeddedLicensePath != "LICENSE.txt" {
		t.Fatalf("license path = %q", meta.EmbeddedLicensePath)
	}
	if meta.EmbeddedLicenseText != "archive embedded license" {
		t.Fatalf("license text = %q", meta.EmbeddedLicenseText)
	}
	if meta.ArtifactResolution == nil || meta.ArtifactResolution.Kind != "remote-package-content" || !meta.ArtifactResolution.ReviewRequired {
		t.Fatalf("artifact resolution = %#v", meta.ArtifactResolution)
	}
}

func TestNugetResolverPrefersEmbeddedLicenseFileOverRegistrationLicenseURL(t *testing.T) {
	t.Parallel()

	archive := buildTestNugetArchive(t, map[string]string{
		"Sample.Package.nuspec": `<?xml version="1.0" encoding="utf-8"?>
<package>
  <metadata>
    <id>Sample.Package</id>
    <version>2.0.0</version>
    <authors>Sample Author</authors>
    <license type="file">LICENSE.txt</license>
    <licenseUrl>https://aka.ms/deprecateLicenseUrl</licenseUrl>
  </metadata>
</package>`,
		"LICENSE.txt": "archive embedded license",
	})

	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/sample.package/2.0.0.json":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"catalogEntry":"` + server.URL + `/catalog/sample.package.2.0.0.json","packageContent":"` + server.URL + `/package/sample.package.2.0.0.nupkg"}`))
		case "/catalog/sample.package.2.0.0.json":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{
  "authors":"Sample Author",
  "licenseExpression":"",
  "licenseUrl":"https://www.nuget.org/packages/Sample.Package/2.0.0/license",
  "projectUrl":"https://example.test/sample",
  "published":"2024-02-03T00:00:00Z"
}`))
		case "/package/sample.package.2.0.0.nupkg":
			w.Header().Set("Content-Type", "application/octet-stream")
			_, _ = w.Write(archive)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	meta, ok, err := (&nugetResolver{
		client:              server.Client(),
		registrationBaseURL: server.URL,
	}).resolveFromRegistration("Sample.Package", "2.0.0")
	if err != nil {
		t.Fatalf("resolveFromRegistration: %v", err)
	}
	if !ok {
		t.Fatal("expected registration lookup to succeed")
	}
	if meta.RawLicense != "LICENSE.txt" {
		t.Fatalf("raw license = %q", meta.RawLicense)
	}
	if meta.EmbeddedLicensePath != "LICENSE.txt" || meta.EmbeddedLicenseText != "archive embedded license" {
		t.Fatalf("embedded license metadata = %#v", meta)
	}
	if meta.ArtifactResolution == nil || meta.ArtifactResolution.Kind != "remote-package-content" || !meta.ArtifactResolution.ReviewRequired {
		t.Fatalf("artifact resolution = %#v", meta.ArtifactResolution)
	}
}

func TestNugetResolverRegistrationFieldFallbacks(t *testing.T) {
	t.Parallel()

	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/fallback.package/2.0.0.json":
			_, _ = w.Write([]byte(`{"catalogEntry":"` + server.URL + `/catalog/fallback.package.2.0.0.json"}`))
		case "/catalog/fallback.package.2.0.0.json":
			_, _ = w.Write([]byte(`{
  "authors":"",
  "projectUrl":"https://example.test/fallback",
  "repository":"",
  "published":"2024-02-03T00:00:00Z"
}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	meta, ok, err := (&nugetResolver{
		client:              server.Client(),
		registrationBaseURL: server.URL,
	}).resolveFromRegistration("Fallback.Package", "2.0.0")
	if err != nil {
		t.Fatalf("resolveFromRegistration: %v", err)
	}
	if !ok {
		t.Fatal("expected registration lookup to succeed")
	}
	if meta.Holder != "Fallback.Package" || meta.Repository != "https://example.test/fallback" || meta.RawLicense != "Unknown" {
		t.Fatalf("registration fallback metadata = %#v", meta)
	}
	if meta.ArtifactResolution == nil || meta.ArtifactResolution.Kind != "remote-metadata" || !meta.ArtifactResolution.ReviewRequired {
		t.Fatalf("artifact resolution = %#v", meta.ArtifactResolution)
	}
}

func TestNugetResolverRegistrationUsesLicenseURLWhenExpressionMissing(t *testing.T) {
	t.Parallel()

	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/sample.package/2.0.0.json":
			_, _ = w.Write([]byte(`{"catalogEntry":"` + server.URL + `/catalog/sample.package.2.0.0.json"}`))
		case "/catalog/sample.package.2.0.0.json":
			_, _ = w.Write([]byte(`{
  "authors":"Sample Author",
  "licenseExpression":"",
  "licenseUrl":"https://licenses.nuget.org/MIT",
  "projectUrl":"https://example.test/sample",
  "published":"2024-02-03T00:00:00Z"
}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	meta, ok, err := (&nugetResolver{
		client:              server.Client(),
		registrationBaseURL: server.URL,
	}).resolveFromRegistration("Sample.Package", "2.0.0")
	if err != nil {
		t.Fatalf("resolveFromRegistration: %v", err)
	}
	if !ok {
		t.Fatal("expected registration lookup to succeed")
	}
	if meta.RawLicense != "https://licenses.nuget.org/MIT" {
		t.Fatalf("raw license = %q", meta.RawLicense)
	}
	if meta.ArtifactResolution == nil || meta.ArtifactResolution.Kind != "remote-metadata" || !meta.ArtifactResolution.ReviewRequired {
		t.Fatalf("artifact resolution = %#v", meta.ArtifactResolution)
	}
}

func buildTestNugetArchive(t *testing.T, files map[string]string) []byte {
	t.Helper()

	var buffer bytes.Buffer
	writer := zip.NewWriter(&buffer)
	for name, body := range files {
		entry, err := writer.Create(name)
		if err != nil {
			t.Fatalf("create zip entry: %v", err)
		}
		if _, err := entry.Write([]byte(body)); err != nil {
			t.Fatalf("write zip entry: %v", err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("close zip: %v", err)
	}
	return buffer.Bytes()
}

func TestNugetResolverMetadataHelpers(t *testing.T) {
	setTestNow(t, time.Date(2031, time.March, 1, 0, 0, 0, 0, time.UTC))

	resolver := &nugetResolver{}
	if got := resolver.resolveRegistrationBaseURL(); got != "https://api.nuget.org/v3/registration5-gz-semver2" {
		t.Fatalf("resolveRegistrationBaseURL default = %q", got)
	}
	resolver.registrationBaseURL = "https://registry.example.test"
	if got := resolver.resolveRegistrationBaseURL(); got != "https://registry.example.test" {
		t.Fatalf("resolveRegistrationBaseURL explicit = %q", got)
	}

	if got := parseMetadataYear("2024-02-03T00:00:00Z"); got != 2024 {
		t.Fatalf("parseMetadataYear valid = %d", got)
	}
	if got := parseMetadataYear("not-a-date"); got != 2031 {
		t.Fatalf("parseMetadataYear fallback = %d", got)
	}
}

func TestNugetMetadataFailureBranchesAndGlobalRootHelper(t *testing.T) {
	t.Parallel()

	tempHome := t.TempDir()
	oldUserProfile := os.Getenv("USERPROFILE")
	oldHome := os.Getenv("HOME")
	t.Cleanup(func() {
		_ = os.Setenv("USERPROFILE", oldUserProfile)
		_ = os.Setenv("HOME", oldHome)
	})
	_ = os.Setenv("USERPROFILE", tempHome)
	_ = os.Setenv("HOME", tempHome)

	if root, ok := nugetGlobalPackagesRoot(); !ok || root == "" {
		t.Fatalf("nugetGlobalPackagesRoot = %q %v", root, ok)
	}

	resolver := &nugetResolver{}
	if _, ok := resolver.resolveGlobalPackagesRoot(); !ok {
		t.Fatal("expected resolveGlobalPackagesRoot fallback")
	}

	dir := t.TempDir()
	if _, ok, err := (&nugetResolver{globalPackagesRoot: filepath.Join(dir, "missing")}).resolveFromGlobalPackages("Missing.Package", "1.0.0"); err != nil {
		t.Fatalf("resolveFromGlobalPackages: %v", err)
	} else if ok {
		t.Fatal("expected missing global package lookup to fail")
	}

	badDir := filepath.Join(dir, "broken.package", "1.0.0")
	if err := os.MkdirAll(badDir, 0o755); err != nil {
		t.Fatalf("mkdir bad dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(badDir, "broken.package.nuspec"), []byte(`<package>`), 0o644); err != nil {
		t.Fatalf("write broken nuspec: %v", err)
	}
	if _, ok, err := (&nugetResolver{globalPackagesRoot: dir}).resolveFromGlobalPackages("Broken.Package", "1.0.0"); err != nil {
		t.Fatalf("resolveFromGlobalPackages: %v", err)
	} else if ok {
		t.Fatal("expected broken nuspec lookup to fail")
	}

	if _, ok, err := (&nugetResolver{}).resolveFromRegistration("Sample.Package", "1.2.3"); err != nil {
		t.Fatalf("resolveFromRegistration: %v", err)
	} else if ok {
		t.Fatal("expected registration lookup without client to fail")
	}
	if _, ok, err := (&nugetResolver{client: http.DefaultClient}).resolveFromRegistration("Sample.Package", ""); err != nil {
		t.Fatalf("resolveFromRegistration: %v", err)
	} else if ok {
		t.Fatal("expected registration lookup without version to fail")
	}
}

func TestNugetEmbeddedLicenseFailureBranches(t *testing.T) {
	t.Parallel()

	if got, err := readEmbeddedLicenseFromDirectory(t.TempDir(), "missing.txt", DefaultMaxEmbeddedLicenseBytes); err != nil {
		t.Fatalf("readEmbeddedLicenseFromDirectory: %v", err)
	} else if got != "" {
		t.Fatalf("expected missing directory license to be empty, got %q", got)
	}

	archive := buildTestNugetArchive(t, map[string]string{
		"Package.nuspec": `<?xml version="1.0" encoding="utf-8"?>
<package><metadata><license type="file">LICENSE.txt</license></metadata></package>`,
	})
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/bad.zip":
			w.Header().Set("Content-Type", "application/octet-stream")
			_, _ = w.Write([]byte("not-a-zip"))
		case "/missing-license.zip":
			w.Header().Set("Content-Type", "application/octet-stream")
			_, _ = w.Write(archive)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	resolver := &nugetResolver{client: server.Client()}
	if _, _, err := resolver.resolveEmbeddedLicenseFromPackageContent("Sample.Package", "1.2.3", server.URL+"/bad.zip"); err == nil {
		t.Fatal("expected bad zip error")
	}
	if _, _, err := resolver.resolveEmbeddedLicenseFromPackageContent("Sample.Package", "1.2.3", server.URL+"/missing-license.zip"); err == nil {
		t.Fatal("expected missing embedded license error")
	}
}

func TestNugetEmbeddedLicenseArchiveErrorBranches(t *testing.T) {
	t.Parallel()

	archiveWithoutNuspec := buildTestNugetArchive(t, map[string]string{
		"LICENSE.txt": "archive embedded license",
	})

	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/status-error.zip":
			http.Error(w, "forbidden", http.StatusForbidden)
		case "/missing-nuspec.zip":
			w.Header().Set("Content-Type", "application/octet-stream")
			_, _ = w.Write(archiveWithoutNuspec)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	resolver := &nugetResolver{client: server.Client()}
	if _, _, err := resolver.resolveEmbeddedLicenseFromPackageContent("Sample.Package", "1.2.3", server.URL+"/status-error.zip"); err == nil {
		t.Fatal("expected non-2xx status error")
	}
	if _, _, err := resolver.resolveEmbeddedLicenseFromPackageContent("Sample.Package", "1.2.3", server.URL+"/missing-nuspec.zip"); err == nil {
		t.Fatal("expected missing nuspec error")
	}
}

func TestNugetEmbeddedLicenseRequestSetsUserAgent(t *testing.T) {
	t.Parallel()

	archive := buildTestNugetArchive(t, map[string]string{
		"Package.nuspec": `<?xml version="1.0" encoding="utf-8"?>
<package><metadata><license type="file">LICENSE.txt</license></metadata></package>`,
		"LICENSE.txt": "archive embedded license",
	})

	var gotUserAgent string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotUserAgent = r.Header.Get("User-Agent")
		w.Header().Set("Content-Type", "application/octet-stream")
		_, _ = w.Write(archive)
	}))
	defer server.Close()

	resolver := &nugetResolver{client: server.Client()}
	licensePath, licenseText, err := resolver.resolveEmbeddedLicenseFromPackageContent("Sample.Package", "1.2.3", server.URL)
	if err != nil {
		t.Fatalf("resolveEmbeddedLicenseFromPackageContent: %v", err)
	}
	if gotUserAgent != "depaudit-license" {
		t.Fatalf("user agent = %q", gotUserAgent)
	}
	if licensePath != "LICENSE.txt" || licenseText != "archive embedded license" {
		t.Fatalf("embedded license = %q %q", licensePath, licenseText)
	}
}

func TestResolveNuspecLicenseHelperBranches(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "LICENSE.txt"), []byte("directory license"), 0o644); err != nil {
		t.Fatalf("write directory license: %v", err)
	}

	location, path, text, err := resolveNuspecLicense("expression", " MIT ", "https://licenses.example/mit", dir, nil, ArtifactReadLimits{})
	if err != nil {
		t.Fatalf("resolveNuspecLicense expression: %v", err)
	}
	if location != "MIT" || path != "" || text != "" {
		t.Fatalf("expression license = %q %q %q", location, path, text)
	}

	location, path, text, err = resolveNuspecLicense("file", "LICENSE.txt", "", dir, nil, ArtifactReadLimits{})
	if err != nil {
		t.Fatalf("resolveNuspecLicense file: %v", err)
	}
	if location != "LICENSE.txt" || path != "LICENSE.txt" || text != "directory license" {
		t.Fatalf("directory file license = %q %q %q", location, path, text)
	}

	archive := buildTestNugetArchive(t, map[string]string{
		"LICENSE.txt": "zip license",
	})
	zipReader, err := zip.NewReader(bytes.NewReader(archive), int64(len(archive)))
	if err != nil {
		t.Fatalf("zip reader: %v", err)
	}

	location, path, text, err = resolveNuspecLicense("file", "LICENSE.txt", "https://licenses.example/file", "", zipReader, ArtifactReadLimits{})
	if err != nil {
		t.Fatalf("resolveNuspecLicense zip file: %v", err)
	}
	if location != "LICENSE.txt" || path != "LICENSE.txt" || text != "zip license" {
		t.Fatalf("zip file license = %q %q %q", location, path, text)
	}

	location, path, text, err = resolveNuspecLicense("custom", " custom-license ", " https://licenses.example/custom ", dir, nil, ArtifactReadLimits{})
	if err != nil {
		t.Fatalf("resolveNuspecLicense default: %v", err)
	}
	if location != "custom-license" || path != "" || text != "" {
		t.Fatalf("default license = %q %q %q", location, path, text)
	}
}

func TestNugetZipHelperBranches(t *testing.T) {
	t.Parallel()

	archive := buildTestNugetArchive(t, map[string]string{
		"docs/LICENSE.txt": "zip license",
	})
	zipReader, err := zip.NewReader(bytes.NewReader(archive), int64(len(archive)))
	if err != nil {
		t.Fatalf("zip reader: %v", err)
	}

	if got, err := readEmbeddedLicenseFromZip(zipReader, "/docs/LICENSE.txt", DefaultMaxEmbeddedLicenseBytes); err != nil {
		t.Fatalf("readEmbeddedLicenseFromZip: %v", err)
	} else if got != "zip license" {
		t.Fatalf("readEmbeddedLicenseFromZip = %q", got)
	}
	for _, licensePath := range []string{"../LICENSE.txt", "C:/LICENSE.txt", `\\server\share\LICENSE.txt`} {
		if got := normalizeEmbeddedLicensePath(licensePath); got != "" {
			t.Fatalf("normalizeEmbeddedLicensePath(%q) = %q", licensePath, got)
		}
	}
	if got, err := readEmbeddedLicenseFromZip(zipReader, "missing.txt", DefaultMaxEmbeddedLicenseBytes); err != nil {
		t.Fatalf("readEmbeddedLicenseFromZip: %v", err)
	} else if got != "" {
		t.Fatalf("expected missing zip license to be empty, got %q", got)
	}

	if payload, err := readZipFile(zipReader.File[0], DefaultMaxEmbeddedLicenseBytes); err != nil || string(payload) != "zip license" {
		t.Fatalf("readZipFile = %q %v", string(payload), err)
	}

	zipReader.File[0].Method = 99
	if _, err := readZipFile(zipReader.File[0], DefaultMaxEmbeddedLicenseBytes); err == nil {
		t.Fatal("expected unsupported compression method error")
	}
}

func TestNugetResolverResolveHelperBranches(t *testing.T) {
	t.Parallel()

	cached := metadata{RawLicense: "MIT", Source: "cache"}
	resolver := &nugetResolver{cache: map[string]metadata{"react/1.0.0": cached}}
	if got := resolver.resolve("React", "1.0.0"); got != cached {
		t.Fatalf("cached resolve = %#v", got)
	}

	client := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		switch req.URL.Path {
		case "/sample.package/1.2.3.json":
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(strings.NewReader(`{"catalogEntry":"https://registry.example.test/catalog.json","packageContent":"https://registry.example.test/package.zip"}`)),
				Header:     make(http.Header),
			}, nil
		case "/catalog.json":
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(strings.NewReader(`{"projectUrl":"https://example.test/sample","published":"2024-02-03T00:00:00Z"}`)),
				Header:     make(http.Header),
			}, nil
		case "/package.zip":
			archive := buildTestNugetArchive(t, map[string]string{
				"Sample.Package.nuspec": `<?xml version="1.0" encoding="utf-8"?>
<package><metadata><license type="file">LICENSE.txt</license></metadata></package>`,
				"LICENSE.txt": "embedded license",
			})
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(bytes.NewReader(archive)),
				Header:     make(http.Header),
			}, nil
		default:
			return &http.Response{
				StatusCode: http.StatusNotFound,
				Body:       io.NopCloser(strings.NewReader("not found")),
				Header:     make(http.Header),
			}, nil
		}
	})}
	resolver = &nugetResolver{
		client:              client,
		cache:               map[string]metadata{},
		registrationBaseURL: "https://registry.example.test",
	}
	got := resolver.resolve("Sample.Package", "1.2.3")
	if got.Source != "nuget-registration" || got.Repository != "https://example.test/sample" {
		t.Fatalf("registration fallback resolve = %#v", got)
	}
	if got.EmbeddedLicensePath != "LICENSE.txt" || got.EmbeddedLicenseText != "embedded license" {
		t.Fatalf("embedded license resolve = %#v", got)
	}
	if got.ArtifactResolution == nil || got.ArtifactResolution.Kind != "remote-package-content" || !got.ArtifactResolution.ReviewRequired {
		t.Fatalf("artifact resolution = %#v", got.ArtifactResolution)
	}
	if cached := resolver.cache["sample.package/1.2.3"]; cached.Source != "nuget-registration" {
		t.Fatalf("cache after resolve = %#v", cached)
	}
}

func TestNugetResolverResolveFallbackBranch(t *testing.T) {
	setTestNow(t, time.Date(2031, time.March, 1, 0, 0, 0, 0, time.UTC))

	resolver := &nugetResolver{
		cache:              map[string]metadata{},
		globalPackagesRoot: filepath.Join(t.TempDir(), "missing"),
	}

	got := resolver.resolve("Missing.Package", "9.9.9")
	if got.RawLicense != "Unknown" || got.Holder != "Missing.Package" || got.Source != "fallback" {
		t.Fatalf("fallback resolve = %#v", got)
	}
	cached, ok := resolver.cache["missing.package/9.9.9"]
	if !ok {
		t.Fatal("expected fallback result to be cached")
	}
	if cached.Source != "fallback" || cached.Holder != "Missing.Package" {
		t.Fatalf("fallback cache = %#v", cached)
	}
	if got.Year != 2031 || cached.Year != 2031 {
		t.Fatalf("fallback years = %#v %#v", got, cached)
	}
}

func TestNugetResolverResolvePrefersGlobalPackagesOverRegistration(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	packageDir := filepath.Join(root, "sample.package", "1.2.3")
	if err := os.MkdirAll(packageDir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	nuspec := `<?xml version="1.0" encoding="utf-8"?>
<package>
  <metadata>
    <authors>Local Author</authors>
    <license type="expression">MIT</license>
  </metadata>
</package>`
	if err := os.WriteFile(filepath.Join(packageDir, "sample.package.nuspec"), []byte(nuspec), 0o644); err != nil {
		t.Fatalf("write nuspec: %v", err)
	}

	client := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		t.Fatalf("unexpected registration request: %s", req.URL.String())
		return nil, nil
	})}
	resolver := &nugetResolver{
		client:              client,
		cache:               map[string]metadata{},
		globalPackagesRoot:  root,
		registrationBaseURL: "https://registry.example.test",
	}

	got := resolver.resolve("Sample.Package", "1.2.3")
	if got.Source != "nuget-global-packages" || got.Holder != "Local Author" {
		t.Fatalf("preferred source = %#v", got)
	}
	if got.ArtifactResolution == nil || got.ArtifactResolution.Kind != "local-package-manager" || got.ArtifactResolution.Detail != "nuget-global-packages" {
		t.Fatalf("artifact resolution = %#v", got.ArtifactResolution)
	}
}

func TestNugetResolverGlobalPackagesRejectsOversizedNuspec(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	packageDir := filepath.Join(root, "oversized.package", "1.0.0")
	if err := os.MkdirAll(packageDir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	nuspec := `<?xml version="1.0" encoding="utf-8"?>
<package><metadata><license type="expression">MIT</license></metadata></package>`
	if err := os.WriteFile(filepath.Join(packageDir, "oversized.package.nuspec"), []byte(nuspec), 0o644); err != nil {
		t.Fatalf("write nuspec: %v", err)
	}

	_, ok, err := (&nugetResolver{
		globalPackagesRoot: root,
		artifactReadLimits: ArtifactReadLimits{MaxPackageMetadataBytes: 8},
	}).resolveFromGlobalPackages("Oversized.Package", "1.0.0")
	if ok {
		t.Fatal("expected oversized nuspec lookup to fail")
	}
	var safetyErr *ArtifactSafetyError
	if !errors.As(err, &safetyErr) {
		t.Fatalf("expected ArtifactSafetyError, got %T: %v", err, err)
	}
}

func TestNugetResolverRegistrationRejectsOversizedPackageContentAndArchiveEntryCount(t *testing.T) {
	t.Parallel()

	archive := buildTestNugetArchive(t, map[string]string{
		"Sample.Package.nuspec": `<?xml version="1.0" encoding="utf-8"?>
<package><metadata><license type="file">LICENSE.txt</license></metadata></package>`,
		"LICENSE.txt": "archive embedded license",
		"extra.txt":   "x",
	})

	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/sample.package/1.0.0.json":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"catalogEntry":"` + server.URL + `/catalog/sample.package.1.0.0.json","packageContent":"` + server.URL + `/package/sample.package.1.0.0.nupkg"}`))
		case "/catalog/sample.package.1.0.0.json":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"authors":"Sample Author","published":"2024-02-03T00:00:00Z"}`))
		case "/package/sample.package.1.0.0.nupkg":
			w.Header().Set("Content-Type", "application/octet-stream")
			w.Header().Set("Content-Length", "999")
			_, _ = w.Write(archive)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	resolver := &nugetResolver{
		client:              server.Client(),
		registrationBaseURL: server.URL,
		artifactReadLimits:  ArtifactReadLimits{MaxPackageArtifactBytes: 32, MaxPackageArchiveEntries: 2},
	}

	_, ok, err := resolver.resolveFromRegistration("Sample.Package", "1.0.0")
	if ok {
		t.Fatal("expected oversized package artifact to fail")
	}
	var safetyErr *ArtifactSafetyError
	if !errors.As(err, &safetyErr) {
		t.Fatalf("expected ArtifactSafetyError, got %T: %v", err, err)
	}

	resolver.artifactReadLimits = ArtifactReadLimits{
		MaxPackageArtifactBytes:  int64(len(archive) + 16),
		MaxPackageArchiveEntries: 2,
	}
	_, ok, err = resolver.resolveFromRegistration("Sample.Package", "1.0.0")
	if ok {
		t.Fatal("expected excessive archive entry count to fail")
	}
	if !errors.As(err, &safetyErr) {
		t.Fatalf("expected ArtifactSafetyError, got %T: %v", err, err)
	}
}

func TestReadZipFileRejectsOversizedEntry(t *testing.T) {
	t.Parallel()

	archive := buildTestNugetArchive(t, map[string]string{
		"LICENSE.txt": "12345",
	})
	zipReader, err := zip.NewReader(bytes.NewReader(archive), int64(len(archive)))
	if err != nil {
		t.Fatalf("zip reader: %v", err)
	}
	if _, err := readZipFile(zipReader.File[0], 4); err == nil {
		t.Fatal("expected oversized zip entry error")
	}
}

func TestNugetResolverRegistrationRejectsOversizedMetadataResponses(t *testing.T) {
	t.Parallel()

	t.Run("registration-leaf", func(t *testing.T) {
		var server *httptest.Server
		server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/sample.package/1.0.0.json":
				w.Header().Set("Content-Type", "application/json")
				w.Header().Set("Content-Length", "512")
				_, _ = w.Write([]byte(`{"catalogEntry":"` + server.URL + `/catalog/sample.package.1.0.0.json"}`))
			default:
				http.NotFound(w, r)
			}
		}))
		defer server.Close()

		_, ok, err := (&nugetResolver{
			client:              server.Client(),
			registrationBaseURL: server.URL,
			artifactReadLimits: ArtifactReadLimits{
				MaxPackageArtifactBytes:  DefaultMaxPackageArtifactBytes,
				MaxPackageMetadataBytes:  16,
				MaxEmbeddedLicenseBytes:  DefaultMaxEmbeddedLicenseBytes,
				MaxPackageArchiveEntries: DefaultMaxPackageArchiveEntries,
			},
		}).resolveFromRegistration("Sample.Package", "1.0.0")
		if ok {
			t.Fatal("expected oversized registration leaf to fail")
		}
		var safetyErr *ArtifactSafetyError
		if !errors.As(err, &safetyErr) {
			t.Fatalf("expected ArtifactSafetyError, got %T: %v", err, err)
		}
	})

	t.Run("catalog-entry", func(t *testing.T) {
		var server *httptest.Server
		server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/sample.package/1.0.0.json":
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{"catalogEntry":"` + server.URL + `/catalog/sample.package.1.0.0.json"}`))
			case "/catalog/sample.package.1.0.0.json":
				w.Header().Set("Content-Type", "application/json")
				w.Header().Set("Content-Length", "512")
				_, _ = w.Write([]byte(`{"authors":"Sample Author","licenseExpression":"MIT"}`))
			default:
				http.NotFound(w, r)
			}
		}))
		defer server.Close()

		_, ok, err := (&nugetResolver{
			client:              server.Client(),
			registrationBaseURL: server.URL,
			artifactReadLimits: ArtifactReadLimits{
				MaxPackageArtifactBytes:  DefaultMaxPackageArtifactBytes,
				MaxPackageMetadataBytes:  16,
				MaxEmbeddedLicenseBytes:  DefaultMaxEmbeddedLicenseBytes,
				MaxPackageArchiveEntries: DefaultMaxPackageArchiveEntries,
			},
		}).resolveFromRegistration("Sample.Package", "1.0.0")
		if ok {
			t.Fatal("expected oversized catalog entry to fail")
		}
		var safetyErr *ArtifactSafetyError
		if !errors.As(err, &safetyErr) {
			t.Fatalf("expected ArtifactSafetyError, got %T: %v", err, err)
		}
	})
}
