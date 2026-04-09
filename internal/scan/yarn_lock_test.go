package scan

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCollectYarnPackagesUsesResolvedVersionsAndTransitives(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "package.json"), []byte(`{
  "name": "web",
  "dependencies": {
    "react": "^18.2.0"
  },
  "devDependencies": {
    "vite": "^5.4.0"
  }
}`), 0o644); err != nil {
		t.Fatalf("write package.json: %v", err)
	}

	lockfile := filepath.Join(root, "yarn.lock")
	lock := `react@^18.2.0:
  version "18.2.0"
  dependencies:
    loose-envify "^1.4.0"

loose-envify@^1.4.0:
  version "1.4.0"

vite@^5.4.0:
  version "5.4.0"
  dependencies:
    esbuild "^0.21.0"

esbuild@^0.21.0:
  version "0.21.0"
`
	if err := os.WriteFile(lockfile, []byte(lock), 0o644); err != nil {
		t.Fatalf("write lockfile: %v", err)
	}

	packages, err := collectYarnPackages(lockfile)
	if err != nil {
		t.Fatalf("collect yarn packages: %v", err)
	}

	lookup := map[string]Package{}
	for _, pkg := range packages {
		lookup[pkg.Name] = pkg
	}

	if lookup["react"].Version != "18.2.0" {
		t.Fatalf("react version = %q", lookup["react"].Version)
	}
	if lookup["react"].DependencyType != "dependency" {
		t.Fatalf("react dependency type = %q", lookup["react"].DependencyType)
	}
	if lookup["loose-envify"].DependencyType != "dependency" {
		t.Fatalf("loose-envify dependency type = %q", lookup["loose-envify"].DependencyType)
	}
	if lookup["vite"].DependencyType != "devDependency" {
		t.Fatalf("vite dependency type = %q", lookup["vite"].DependencyType)
	}
	if lookup["esbuild"].DependencyType != "devDependency" {
		t.Fatalf("esbuild dependency type = %q", lookup["esbuild"].DependencyType)
	}
}

func TestCollectYarnPackagesSupportsWorkspaceImporters(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	appDir := filepath.Join(root, "apps", "web")
	pkgDir := filepath.Join(root, "packages", "shared")
	if err := os.MkdirAll(appDir, 0o755); err != nil {
		t.Fatalf("mkdir app dir: %v", err)
	}
	if err := os.MkdirAll(pkgDir, 0o755); err != nil {
		t.Fatalf("mkdir package dir: %v", err)
	}

	if err := os.WriteFile(filepath.Join(root, "package.json"), []byte(`{
  "name": "repo",
  "private": true,
  "workspaces": ["apps/*", "packages/*"]
}`), 0o644); err != nil {
		t.Fatalf("write root package.json: %v", err)
	}
	if err := os.WriteFile(filepath.Join(appDir, "package.json"), []byte(`{
  "name": "@repo/web",
  "dependencies": {
    "react": "^18.2.0"
  }
}`), 0o644); err != nil {
		t.Fatalf("write app package.json: %v", err)
	}
	if err := os.WriteFile(filepath.Join(pkgDir, "package.json"), []byte(`{
  "name": "@repo/shared",
  "dependencies": {
    "tslib": "^2.6.2"
  }
}`), 0o644); err != nil {
		t.Fatalf("write shared package.json: %v", err)
	}

	lock := `"react@^18.2.0":
  version: 18.2.0
"tslib@^2.6.2":
  version: 2.6.2
`
	lockfile := filepath.Join(root, "yarn.lock")
	if err := os.WriteFile(lockfile, []byte(lock), 0o644); err != nil {
		t.Fatalf("write lockfile: %v", err)
	}

	packages, err := collectYarnPackages(lockfile)
	if err != nil {
		t.Fatalf("collect yarn packages: %v", err)
	}

	projects := map[string]struct{}{}
	for _, pkg := range packages {
		projects[pkg.Project] = struct{}{}
	}
	if _, ok := projects["@repo/web"]; !ok {
		t.Fatalf("workspace project @repo/web not found: %#v", projects)
	}
	if _, ok := projects["@repo/shared"]; !ok {
		t.Fatalf("workspace project @repo/shared not found: %#v", projects)
	}
}

func TestYarnHelperFunctions(t *testing.T) {
	t.Parallel()

	if got := yarnResolvedVersion(" npm:1.2.3 "); got != "1.2.3" {
		t.Fatalf("yarnResolvedVersion npm = %q", got)
	}
	if got := yarnResolvedVersion("^1.2.3"); got != "" {
		t.Fatalf("yarnResolvedVersion range = %q", got)
	}
	if got := yarnResolvedVersion("workspace:*"); got != "" {
		t.Fatalf("yarnResolvedVersion workspace = %q", got)
	}

	if name, ref, ok := splitYarnDescriptor("@scope/pkg@npm:^1.0.0"); !ok || name != "@scope/pkg" || ref != "npm:^1.0.0" {
		t.Fatalf("splitYarnDescriptor = %q %q %v", name, ref, ok)
	}
	if _, _, ok := splitYarnDescriptor("invalid"); ok {
		t.Fatal("expected invalid descriptor to fail")
	}

	document := yarnLockDocument{
		Descriptors: map[string]string{
			"react@^18.2.0":      "react@18.2.0",
			"scheduler@npm:^0.1": "scheduler@0.1.0",
		},
		Packages: map[string]yarnLockPackage{
			"react@18.2.0":    {Name: "react", Version: "18.2.0"},
			"scheduler@0.1.0": {Name: "scheduler", Version: "0.1.0"},
			"left-pad@1.3.0":  {Name: "left-pad", Version: "1.3.0"},
		},
	}
	if key, ok := yarnResolvedPackageKey(document, "react", "^18.2.0"); !ok || key != "react@18.2.0" {
		t.Fatalf("yarnResolvedPackageKey react = %q %v", key, ok)
	}
	if key, ok := yarnResolvedPackageKey(document, "scheduler", "npm:^0.1"); !ok || key != "scheduler@0.1.0" {
		t.Fatalf("yarnResolvedPackageKey scheduler = %q %v", key, ok)
	}
	if key, ok := yarnResolvedPackageKey(document, "left-pad", "1.3.0"); !ok || key != "left-pad@1.3.0" {
		t.Fatalf("yarnResolvedPackageKey exact = %q %v", key, ok)
	}
	if _, ok := yarnResolvedPackageKey(document, "workspace-pkg", "workspace:*"); ok {
		t.Fatal("expected workspace reference to be skipped")
	}
}

func TestReadYarnLockfileAndImporterHelpers(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	lockfile := filepath.Join(root, "yarn.lock")
	if _, err := readYarnLockfile(filepath.Join(root, "missing-yarn.lock")); err == nil {
		t.Fatal("expected missing lockfile error")
	}
	if err := os.WriteFile(lockfile, []byte(``), 0o644); err != nil {
		t.Fatalf("write empty lockfile: %v", err)
	}
	if _, err := readYarnLockfile(lockfile); err == nil {
		t.Fatal("expected empty lockfile error")
	}

	if err := os.WriteFile(filepath.Join(root, "package.json"), []byte(`{
  "name": "repo",
  "workspaces": {
    "packages": ["packages/*"]
  }
}`), 0o644); err != nil {
		t.Fatalf("write root package.json: %v", err)
	}
	pkgDir := filepath.Join(root, "packages", "lib")
	if err := os.MkdirAll(pkgDir, 0o755); err != nil {
		t.Fatalf("mkdir package dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(pkgDir, "package.json"), []byte(`{"name":"@repo/lib"}`), 0o644); err != nil {
		t.Fatalf("write workspace package.json: %v", err)
	}

	importers, err := readYarnImporters(root)
	if err != nil {
		t.Fatalf("read yarn importers: %v", err)
	}
	if len(importers) != 2 {
		t.Fatalf("importer count = %d", len(importers))
	}

	srcDir := filepath.Join(pkgDir, "src")
	if err := os.MkdirAll(srcDir, 0o755); err != nil {
		t.Fatalf("mkdir src dir: %v", err)
	}
	if got := nearestYarnLockfile(filepath.Join(srcDir, "index.ts"), root); got != lockfile {
		t.Fatalf("nearestYarnLockfile = %q", got)
	}
	if got := nearestYarnLockfile(filepath.Join(root, "other", "index.ts"), filepath.Join(root, "other")); got != "" {
		t.Fatalf("expected no lockfile, got %q", got)
	}
}
