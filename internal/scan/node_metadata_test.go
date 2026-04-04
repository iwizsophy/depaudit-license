package scan

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestNodeResolverUsesInstalledPackageMetadata(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	packageDir := filepath.Join(root, "node_modules", "react")
	if err := os.MkdirAll(packageDir, 0o755); err != nil {
		t.Fatalf("mkdir package dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(packageDir, "package.json"), []byte(`{
  "name": "react",
  "version": "18.2.0",
  "license": "MIT",
  "homepage": "https://react.dev",
  "repository": { "url": "https://github.com/facebook/react" },
  "author": { "name": "Meta" }
}`), 0o644); err != nil {
		t.Fatalf("write package.json: %v", err)
	}

	resolver := &nodeResolver{cache: map[string]metadata{}}
	meta := resolver.resolve("react", "^18.0.0", root)

	if meta.Source != "node-modules" {
		t.Fatalf("source = %q", meta.Source)
	}
	if meta.RawLicense != "MIT" {
		t.Fatalf("raw license = %q", meta.RawLicense)
	}
	if meta.Repository != "https://github.com/facebook/react" {
		t.Fatalf("repository = %q", meta.Repository)
	}
}

func TestNodeResolverFallsBackToExactRegistryVersion(t *testing.T) {
	t.Parallel()

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

	resolver := &nodeResolver{
		client:          server.Client(),
		cache:           map[string]metadata{},
		registryBaseURL: server.URL,
	}

	meta := resolver.resolve("react", "18.2.0", t.TempDir())
	if meta.Source != "npm-registry-version" {
		t.Fatalf("source = %q", meta.Source)
	}
	if meta.RawLicense != "MIT" {
		t.Fatalf("raw license = %q", meta.RawLicense)
	}
	if meta.Homepage != "https://react.dev" {
		t.Fatalf("homepage = %q", meta.Homepage)
	}
}

func TestNodeResolverDoesNotUseLatestForNonExactVersion(t *testing.T) {
	t.Parallel()

	resolver := &nodeResolver{cache: map[string]metadata{}}
	meta := resolver.resolve("react", "^18.0.0", t.TempDir())

	if meta.Source != "fallback" {
		t.Fatalf("source = %q", meta.Source)
	}
	if meta.RawLicense != "Unknown" {
		t.Fatalf("raw license = %q", meta.RawLicense)
	}
}

func TestNodeResolverUsesCacheAndFallbackBranches(t *testing.T) {
	t.Parallel()

	resolver := &nodeResolver{
		cache: map[string]metadata{
			"react@19.2.4": {RawLicense: "MIT", Source: "cached"},
		},
	}
	meta := resolver.resolve("react", "19.2.4", t.TempDir())
	if meta.Source != "cached" || meta.RawLicense != "MIT" {
		t.Fatalf("cached resolve = %#v", meta)
	}

	resolver = &nodeResolver{cache: map[string]metadata{}}
	meta = resolver.resolve("react", "19.2.4", t.TempDir())
	if meta.Source != "fallback" || meta.RawLicense != "Unknown" {
		t.Fatalf("nil client fallback = %#v", meta)
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{invalid`))
	}))
	defer server.Close()

	resolver = &nodeResolver{
		client:          server.Client(),
		cache:           map[string]metadata{},
		registryBaseURL: server.URL,
	}
	meta = resolver.resolve("react", "19.2.4", t.TempDir())
	if meta.Source != "fallback" || meta.RawLicense != "Unknown" {
		t.Fatalf("bad json fallback = %#v", meta)
	}
}

func TestNodeResolverInstalledPackageFallbacks(t *testing.T) {
	t.Parallel()

	resolver := &nodeResolver{cache: map[string]metadata{}}
	if _, ok := resolver.resolveFromInstalledPackage("react", "18.2.0", ""); ok {
		t.Fatal("expected empty project dir to fail")
	}

	root := t.TempDir()
	packageDir := filepath.Join(root, "node_modules", "react")
	if err := os.MkdirAll(packageDir, 0o755); err != nil {
		t.Fatalf("mkdir package dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(packageDir, "package.json"), []byte(`{
  "name": "react",
  "version": "18.2.1",
  "repository": { "url": "https://github.com/facebook/react" }
}`), 0o644); err != nil {
		t.Fatalf("write package.json: %v", err)
	}

	if _, ok := resolver.resolveFromInstalledPackage("react", "18.2.0", root); ok {
		t.Fatal("expected exact version mismatch to fail")
	}

	if err := os.WriteFile(filepath.Join(packageDir, "package.json"), []byte(`{
  "name": "react",
  "version": "18.2.0",
  "author": { "name": "Meta" }
}`), 0o644); err != nil {
		t.Fatalf("rewrite package.json: %v", err)
	}

	meta, ok := resolver.resolveFromInstalledPackage("react", "^18.0.0", root)
	if !ok {
		t.Fatal("expected range version to accept installed package metadata")
	}
	if meta.RawLicense != "Unknown" {
		t.Fatalf("raw license = %q", meta.RawLicense)
	}
	if meta.Holder != "Meta" {
		t.Fatalf("holder = %q", meta.Holder)
	}
}

func TestNodeResolverInstalledPackageHelperBranches(t *testing.T) {
	t.Parallel()

	resolver := &nodeResolver{cache: map[string]metadata{}}
	root := t.TempDir()
	packageDir := filepath.Join(root, "node_modules", "react")
	if err := os.MkdirAll(packageDir, 0o755); err != nil {
		t.Fatalf("mkdir package dir: %v", err)
	}

	if err := os.WriteFile(filepath.Join(packageDir, "package.json"), []byte(`{invalid`), 0o644); err != nil {
		t.Fatalf("write invalid package.json: %v", err)
	}
	if _, ok := resolver.resolveFromInstalledPackage("react", "19.2.4", root); ok {
		t.Fatal("expected invalid package.json to fail")
	}

	if err := os.WriteFile(filepath.Join(packageDir, "package.json"), []byte(`{
  "name": "react",
  "version": "19.2.4",
  "license": {"type":"MIT"},
  "maintainers": [{"name":"Maintainer"}],
  "contributors": [{"name":"Contributor"}]
}`), 0o644); err != nil {
		t.Fatalf("write package.json: %v", err)
	}

	meta, ok := resolver.resolveFromInstalledPackage("react", "19.2.4", root)
	if !ok {
		t.Fatal("expected exact version to accept installed package metadata")
	}
	if meta.RawLicense != "MIT" {
		t.Fatalf("raw license = %q", meta.RawLicense)
	}
	if meta.Holder != "Maintainer" {
		t.Fatalf("holder = %q", meta.Holder)
	}

	if err := os.WriteFile(filepath.Join(packageDir, "package.json"), []byte(`{
  "name": "react",
  "version": "19.2.4",
  "contributors": [{"name":"Contributor"}]
}`), 0o644); err != nil {
		t.Fatalf("rewrite package.json: %v", err)
	}
	meta, ok = resolver.resolveFromInstalledPackage("react", "19.2.4", root)
	if !ok || meta.Holder != "Contributor" {
		t.Fatalf("contributor fallback = %#v %v", meta, ok)
	}
}
