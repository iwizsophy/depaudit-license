package scan

import (
	"os"
	"path/filepath"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestCollectPnpmPackagesUsesResolvedVersionsAndTransitives(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	lockfile := filepath.Join(root, "pnpm-lock.yaml")
	if err := os.WriteFile(filepath.Join(root, "package.json"), []byte(`{
  "name": "web",
  "peerDependencies": {
    "scheduler": "^0.23.0"
  }
}`), 0o644); err != nil {
		t.Fatalf("write package.json: %v", err)
	}
	lock := `lockfileVersion: '9.0'
importers:
  .:
    dependencies:
      react:
        version: 18.2.0
    devDependencies:
      vite:
        version: 5.4.0
    optionalDependencies:
      scheduler:
        version: 0.23.0
snapshots:
  react@18.2.0:
    dependencies:
      loose-envify: 1.4.0
  loose-envify@1.4.0: {}
  vite@5.4.0:
    dependencies:
      esbuild: 0.21.0
  esbuild@0.21.0: {}
  scheduler@0.23.0: {}
`
	if err := os.WriteFile(lockfile, []byte(lock), 0o644); err != nil {
		t.Fatalf("write lockfile: %v", err)
	}

	packages, err := collectPnpmPackages(lockfile)
	if err != nil {
		t.Fatalf("collect pnpm packages: %v", err)
	}

	lookup := map[string]Package{}
	for _, pkg := range packages {
		lookup[pkg.Name] = pkg
	}

	if lookup["react"].Version != "18.2.0" {
		t.Fatalf("react version = %q", lookup["react"].Version)
	}
	if lookup["loose-envify"].DependencyType != "dependency" {
		t.Fatalf("loose-envify dependencyType = %q", lookup["loose-envify"].DependencyType)
	}
	if lookup["vite"].DependencyType != "devDependency" {
		t.Fatalf("vite dependencyType = %q", lookup["vite"].DependencyType)
	}
	if lookup["esbuild"].DependencyType != "devDependency" {
		t.Fatalf("esbuild dependencyType = %q", lookup["esbuild"].DependencyType)
	}
	if lookup["scheduler"].DependencyType != "peerDependency" {
		t.Fatalf("scheduler dependencyType = %q", lookup["scheduler"].DependencyType)
	}
}

func TestCollectPnpmPackagesSupportsWorkspaceImporters(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	appDir := filepath.Join(root, "apps", "web")
	pkgDir := filepath.Join(root, "packages", "shared")
	if err := os.MkdirAll(appDir, 0o755); err != nil {
		t.Fatalf("mkdir app dir: %v", err)
	}
	if err := os.MkdirAll(pkgDir, 0o755); err != nil {
		t.Fatalf("mkdir pkg dir: %v", err)
	}

	if err := os.WriteFile(filepath.Join(appDir, "package.json"), []byte(`{"name":"@repo/web"}`), 0o644); err != nil {
		t.Fatalf("write app package.json: %v", err)
	}
	if err := os.WriteFile(filepath.Join(pkgDir, "package.json"), []byte(`{"name":"@repo/shared"}`), 0o644); err != nil {
		t.Fatalf("write shared package.json: %v", err)
	}
	lock := `lockfileVersion: '9.0'
importers:
  apps/web:
    dependencies:
      react:
        version: 18.2.0
  packages/shared:
    dependencies:
      tslib:
        version: 2.6.2
snapshots:
  react@18.2.0: {}
  tslib@2.6.2: {}
`
	lockfile := filepath.Join(root, "pnpm-lock.yaml")
	if err := os.WriteFile(lockfile, []byte(lock), 0o644); err != nil {
		t.Fatalf("write lockfile: %v", err)
	}

	packages, err := collectPnpmPackages(lockfile)
	if err != nil {
		t.Fatalf("collect pnpm packages: %v", err)
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

func TestPnpmHelperFunctions(t *testing.T) {
	t.Parallel()

	if !assignPnpmCategory(map[string]string{}, "react@18.2.0", "dependency") {
		t.Fatal("expected initial category assignment")
	}
	categories := map[string]string{"react@18.2.0": "devDependency"}
	if !assignPnpmCategory(categories, "react@18.2.0", "dependency") {
		t.Fatal("expected stronger category to replace weaker one")
	}
	if categories["react@18.2.0"] != "dependency" {
		t.Fatalf("category = %q", categories["react@18.2.0"])
	}
	if assignPnpmCategory(categories, "react@18.2.0", "devDependency") {
		t.Fatal("expected weaker category to be ignored")
	}

	if got := pnpmCategoryPriority("dependency"); got != 3 {
		t.Fatalf("dependency priority = %d", got)
	}
	if got := pnpmCategoryPriority("peerDependency"); got != 2 {
		t.Fatalf("peerDependency priority = %d", got)
	}
	if got := pnpmCategoryPriority("devDependency"); got != 1 {
		t.Fatalf("devDependency priority = %d", got)
	}
	if got := pnpmCategoryPriority("unknown"); got != 0 {
		t.Fatalf("unknown priority = %d", got)
	}
	if got := pnpmCategoryPriority("transitiveDependency"); got != 0 {
		t.Fatalf("transitiveDependency priority = %d", got)
	}
}

func TestPnpmResolvedRefAndLockfileErrorBranches(t *testing.T) {
	t.Parallel()

	var scalar pnpmResolvedRef
	if err := yaml.Unmarshal([]byte("18.2.0\n"), &scalar); err != nil {
		t.Fatalf("unmarshal scalar ref: %v", err)
	}
	if scalar.Version != "18.2.0" {
		t.Fatalf("scalar version = %q", scalar.Version)
	}

	var mapping pnpmResolvedRef
	if err := yaml.Unmarshal([]byte("version: 5.4.0\n"), &mapping); err != nil {
		t.Fatalf("unmarshal mapping ref: %v", err)
	}
	if mapping.Version != "5.4.0" {
		t.Fatalf("mapping version = %q", mapping.Version)
	}

	var invalid pnpmResolvedRef
	if err := yaml.Unmarshal([]byte("- invalid\n"), &invalid); err == nil {
		t.Fatal("expected unsupported node kind error")
	}

	dir := t.TempDir()
	lockfile := filepath.Join(dir, "pnpm-lock.yaml")
	if _, err := readPnpmLockfile(filepath.Join(dir, "missing-lock.yaml")); err == nil {
		t.Fatal("expected missing lockfile error")
	}
	if err := os.WriteFile(lockfile, []byte("{invalid"), 0o644); err != nil {
		t.Fatalf("write invalid lockfile: %v", err)
	}
	if _, err := readPnpmLockfile(lockfile); err == nil {
		t.Fatal("expected parse error")
	}
	if err := os.WriteFile(lockfile, []byte("lockfileVersion: '9.0'\nimporters: {}\n"), 0o644); err != nil {
		t.Fatalf("write empty importer lockfile: %v", err)
	}
	if _, err := readPnpmLockfile(lockfile); err == nil {
		t.Fatal("expected no-importers error")
	}
}

func TestPnpmReferenceAndProjectMetadataHelpers(t *testing.T) {
	t.Parallel()

	if got := pnpmResolvedVersion(" 1.2.3(peer@1.0.0) "); got != "1.2.3" {
		t.Fatalf("pnpmResolvedVersion trimmed = %q", got)
	}
	if got := pnpmResolvedVersion("   "); got != "" {
		t.Fatalf("pnpmResolvedVersion blank = %q", got)
	}
	if got := pnpmResolvedVersion("workspace:*"); got != "" {
		t.Fatalf("pnpmResolvedVersion workspace = %q", got)
	}
	if got := pnpmResolvedVersion("link:../local"); got != "" {
		t.Fatalf("pnpmResolvedVersion link = %q", got)
	}
	if got := pnpmResolvedVersion("file:../pkg.tgz"); got != "" {
		t.Fatalf("pnpmResolvedVersion file = %q", got)
	}

	if key, ok := pnpmKeyFromReference("react", "18.2.0(peer@1.0.0)"); !ok || key != "react@18.2.0" {
		t.Fatalf("pnpmKeyFromReference = %q %v", key, ok)
	}
	if _, ok := pnpmKeyFromReference("react", "workspace:*"); ok {
		t.Fatal("expected unsupported reference to be skipped")
	}

	if got := canonicalPnpmSnapshotKey("/react@18.2.0(peer@1.0.0)"); got != "react@18.2.0" {
		t.Fatalf("canonicalPnpmSnapshotKey = %q", got)
	}
	if name, version, ok := splitPnpmSnapshotKey("@scope/pkg@1.0.0(peer@2.0.0)"); !ok || name != "@scope/pkg" || version != "1.0.0" {
		t.Fatalf("splitPnpmSnapshotKey = %q %q %v", name, version, ok)
	}
	if _, _, ok := splitPnpmSnapshotKey("react"); ok {
		t.Fatal("expected invalid snapshot key to be rejected")
	}

	document := pnpmLockFile{
		Packages: map[string]pnpmSnapshot{
			"/react@18.2.0(peer@1.0.0)": {Dependencies: map[string]string{"scheduler": "0.23.0"}},
		},
	}
	graph := pnpmSnapshots(document)
	if _, ok := graph["react@18.2.0"]; !ok {
		t.Fatalf("pnpmSnapshots = %#v", graph)
	}

	root := t.TempDir()
	appDir := filepath.Join(root, "apps", "web")
	if err := os.MkdirAll(appDir, 0o755); err != nil {
		t.Fatalf("mkdir app dir: %v", err)
	}
	project, peerDeps := readNodeProjectMetadata(appDir, "apps/web")
	if project != "apps/web" || len(peerDeps) != 0 {
		t.Fatalf("fallback project metadata = %q %#v", project, peerDeps)
	}

	if err := os.WriteFile(filepath.Join(appDir, "package.json"), []byte(`{invalid`), 0o644); err != nil {
		t.Fatalf("write invalid package.json: %v", err)
	}
	project, peerDeps = readNodeProjectMetadata(appDir, ".")
	if project != "web" || len(peerDeps) != 0 {
		t.Fatalf("root fallback project metadata = %q %#v", project, peerDeps)
	}
	project, peerDeps = readNodeProjectMetadata(appDir, "apps/web")
	if project != "apps/web" || len(peerDeps) != 0 {
		t.Fatalf("importer fallback project metadata = %q %#v", project, peerDeps)
	}

	if err := os.WriteFile(filepath.Join(appDir, "package.json"), []byte(`{
  "name":"@repo/web",
  "peerDependencies":{"react":"^18.2.0"}
}`), 0o644); err != nil {
		t.Fatalf("write package.json: %v", err)
	}
	project, peerDeps = readNodeProjectMetadata(appDir, "apps/web")
	if project != "@repo/web" {
		t.Fatalf("project name = %q", project)
	}
	if _, ok := peerDeps["react"]; !ok {
		t.Fatalf("peer deps = %#v", peerDeps)
	}

	lockfile := filepath.Join(root, "pnpm-lock.yaml")
	if err := os.WriteFile(lockfile, []byte("lockfileVersion: '9.0'\nimporters:\n  .: {}\n"), 0o644); err != nil {
		t.Fatalf("write root lockfile: %v", err)
	}
	nestedLockfile := filepath.Join(appDir, "pnpm-lock.yaml")
	if err := os.WriteFile(nestedLockfile, []byte("lockfileVersion: '9.0'\nimporters:\n  .: {}\n"), 0o644); err != nil {
		t.Fatalf("write nested lockfile: %v", err)
	}
	nested := filepath.Join(appDir, "src")
	if err := os.MkdirAll(nested, 0o755); err != nil {
		t.Fatalf("mkdir nested dir: %v", err)
	}
	if got := nearestPnpmLockfile(filepath.Join(nested, "index.ts"), root); got != nestedLockfile {
		t.Fatalf("nearestPnpmLockfile = %q", got)
	}
	if got := nearestPnpmLockfile(filepath.Join(root, "other", "index.ts"), filepath.Join(root, "other")); got != "" {
		t.Fatalf("expected no lockfile, got %q", got)
	}
}

func TestBuildPnpmImporterPackagesHelperBranches(t *testing.T) {
	t.Parallel()

	importer := pnpmImporter{
		Dependencies: map[string]pnpmResolvedRef{
			"react":   {Version: "18.2.0"},
			"missing": {Version: "1.0.0"},
		},
		OptionalDependencies: map[string]pnpmResolvedRef{
			"scheduler": {Version: "0.23.0"},
		},
		DevDependencies: map[string]pnpmResolvedRef{
			"vite": {Version: "5.4.0"},
		},
	}
	graph := map[string]pnpmSnapshot{
		"react@18.2.0": {
			Dependencies:         map[string]string{"loose-envify": "1.4.0", "local": "workspace:*"},
			OptionalDependencies: map[string]string{"optional-child": "2.0.0"},
		},
		"loose-envify@1.4.0":   {},
		"optional-child@2.0.0": {},
		"scheduler@0.23.0":     {},
		"vite@5.4.0":           {},
	}

	packages := buildPnpmImporterPackages("web", importer, map[string]struct{}{"scheduler": {}}, graph)
	lookup := map[string]Package{}
	for _, pkg := range packages {
		lookup[pkg.Name] = pkg
	}

	if lookup["missing"].DependencyType != "dependency" {
		t.Fatalf("missing dependency type = %q", lookup["missing"].DependencyType)
	}
	if _, ok := lookup["missing-child"]; ok {
		t.Fatalf("missing snapshot should not expand transitive packages: %#v", lookup["missing-child"])
	}
	if lookup["react"].DependencyType != "dependency" {
		t.Fatalf("react dependency type = %q", lookup["react"].DependencyType)
	}
	if lookup["scheduler"].DependencyType != "peerDependency" {
		t.Fatalf("scheduler dependency type = %q", lookup["scheduler"].DependencyType)
	}
	if lookup["vite"].DependencyType != "devDependency" {
		t.Fatalf("vite dependency type = %q", lookup["vite"].DependencyType)
	}
	if lookup["loose-envify"].DependencyType != "dependency" {
		t.Fatalf("loose-envify dependency type = %q", lookup["loose-envify"].DependencyType)
	}
	if lookup["optional-child"].DependencyType != "dependency" {
		t.Fatalf("optional-child dependency type = %q", lookup["optional-child"].DependencyType)
	}
	if _, ok := lookup["local"]; ok {
		t.Fatalf("workspace child should be skipped: %#v", lookup["local"])
	}
}

func TestBuildPnpmImporterPackagesPrefersDependencyOverPeerAndDevPropagation(t *testing.T) {
	t.Parallel()

	importer := pnpmImporter{
		Dependencies: map[string]pnpmResolvedRef{
			"react": {Version: "18.2.0"},
		},
		DevDependencies: map[string]pnpmResolvedRef{
			"react-dom": {Version: "18.2.0"},
		},
	}
	graph := map[string]pnpmSnapshot{
		"react@18.2.0": {
			Dependencies: map[string]string{"scheduler": "0.23.0"},
		},
		"react-dom@18.2.0": {
			Dependencies: map[string]string{"scheduler": "0.23.0"},
		},
		"scheduler@0.23.0": {},
	}

	packages := buildPnpmImporterPackages("web", importer, nil, graph)
	lookup := map[string]Package{}
	for _, pkg := range packages {
		lookup[pkg.Name] = pkg
	}

	if lookup["react"].DependencyType != "dependency" {
		t.Fatalf("react dependency type = %q", lookup["react"].DependencyType)
	}
	if lookup["react-dom"].DependencyType != "devDependency" {
		t.Fatalf("react-dom dependency type = %q", lookup["react-dom"].DependencyType)
	}
	if lookup["scheduler"].DependencyType != "dependency" {
		t.Fatalf("scheduler dependency type = %q", lookup["scheduler"].DependencyType)
	}
}
