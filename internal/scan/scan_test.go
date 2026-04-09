package scan

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestCollectCombinesPnpmAndDotNetProjects(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	nodeDir := filepath.Join(root, "web")
	dotnetDir := filepath.Join(root, "api")
	if err := os.MkdirAll(nodeDir, 0o755); err != nil {
		t.Fatalf("mkdir node dir: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(dotnetDir, "obj"), 0o755); err != nil {
		t.Fatalf("mkdir obj dir: %v", err)
	}

	if err := os.WriteFile(filepath.Join(nodeDir, "package.json"), []byte(`{"name":"web"}`), 0o644); err != nil {
		t.Fatalf("write package.json: %v", err)
	}
	if err := os.WriteFile(filepath.Join(nodeDir, "pnpm-lock.yaml"), []byte(`lockfileVersion: '9.0'
importers:
  .:
    dependencies:
      react:
        version: 19.2.4
snapshots:
  react@19.2.4: {}
`), 0o644); err != nil {
		t.Fatalf("write lockfile: %v", err)
	}

	projectPath := filepath.Join(dotnetDir, "App.csproj")
	if err := os.WriteFile(projectPath, []byte(`<Project />`), 0o644); err != nil {
		t.Fatalf("write csproj: %v", err)
	}
	assets := `{
  "project": {
    "restore": { "projectPath": "` + filepath.ToSlash(projectPath) + `" },
    "frameworks": {
      "net8.0": { "dependencies": { "Newtonsoft.Json": {} } }
    }
  },
  "libraries": {
    "Newtonsoft.Json/13.0.3": { "type": "package" }
  },
  "targets": {
    "net8.0": {
      "Newtonsoft.Json/13.0.3": {
        "runtime": { "lib/net8.0/Newtonsoft.Json.dll": {} }
      }
    }
  }
}`
	if err := os.WriteFile(filepath.Join(dotnetDir, "obj", "project.assets.json"), []byte(assets), 0o644); err != nil {
		t.Fatalf("write assets: %v", err)
	}

	packages, err := Collect(Config{Root: root})
	if err != nil {
		t.Fatalf("collect: %v", err)
	}
	if len(packages) != 2 {
		t.Fatalf("package count = %d", len(packages))
	}
	if packages[0].Name != "Newtonsoft.Json" || packages[1].Name != "react" {
		t.Fatalf("packages = %#v", packages)
	}
}

func TestCollectUsesPackageJSONWhenNoPnpmLockExists(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "package.json"), []byte(`{
  "name":"web",
  "dependencies":{"react":"19.2.4"},
  "devDependencies":{"vite":"5.4.0"},
  "peerDependencies":{"scheduler":"0.23.0"}
}`), 0o644); err != nil {
		t.Fatalf("write package.json: %v", err)
	}

	packages, err := Collect(Config{Root: root})
	if err != nil {
		t.Fatalf("collect: %v", err)
	}
	if len(packages) != 3 {
		t.Fatalf("package count = %d", len(packages))
	}
	if packages[0].Name != "react" || packages[0].DependencyType != "dependency" ||
		packages[1].Name != "scheduler" || packages[1].DependencyType != "peerDependency" ||
		packages[2].Name != "vite" || packages[2].DependencyType != "devDependency" {
		t.Fatalf("packages = %#v", packages)
	}
}

func TestCollectNodePackagesFallbacksAndErrors(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	packagePath := filepath.Join(root, "package.json")
	if _, err := collectNodePackages(filepath.Join(root, "missing-package.json")); err == nil {
		t.Fatal("expected read error")
	}
	if err := os.WriteFile(packagePath, []byte(`{invalid`), 0o644); err != nil {
		t.Fatalf("write invalid package.json: %v", err)
	}
	if _, err := collectNodePackages(packagePath); err == nil {
		t.Fatal("expected parse error")
	}

	projectDir := filepath.Join(root, "client")
	if err := os.MkdirAll(projectDir, 0o755); err != nil {
		t.Fatalf("mkdir project dir: %v", err)
	}
	projectPackagePath := filepath.Join(projectDir, "package.json")
	if err := os.WriteFile(projectPackagePath, []byte(`{
  "dependencies":{"react":"^19.2.4"}
}`), 0o644); err != nil {
		t.Fatalf("write package.json: %v", err)
	}
	packages, err := collectNodePackages(projectPackagePath)
	if err != nil {
		t.Fatalf("collect node packages: %v", err)
	}
	if len(packages) != 1 {
		t.Fatalf("packages = %#v", packages)
	}
	if packages[0].Project != "client" {
		t.Fatalf("project = %q", packages[0].Project)
	}
	if packages[0].Version != "19.2.4" {
		t.Fatalf("version = %q", packages[0].Version)
	}
}

func TestCollectDotNetPackagesFromProjectUsesVersionElement(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	projectPath := filepath.Join(root, "App.csproj")
	if err := os.WriteFile(projectPath, []byte(`<Project>
  <ItemGroup>
    <PackageReference Include="">
      <Version>0.0.0</Version>
    </PackageReference>
    <PackageReference Include="Serilog">
      <Version>3.1.0</Version>
    </PackageReference>
    <PackageReference Include="Newtonsoft.Json" Version="13.0.3" />
  </ItemGroup>
</Project>`), 0o644); err != nil {
		t.Fatalf("write csproj: %v", err)
	}

	packages, err := collectDotNetPackagesFromProject(projectPath)
	if err != nil {
		t.Fatalf("collect dotnet packages: %v", err)
	}
	if len(packages) != 2 {
		t.Fatalf("packages = %#v", packages)
	}
	if packages[0].Name != "Newtonsoft.Json" || packages[0].Version != "13.0.3" {
		t.Fatalf("first package = %#v", packages[0])
	}
	if packages[1].Name != "Serilog" || packages[1].Version != "3.1.0" {
		t.Fatalf("second package = %#v", packages[1])
	}
}

func TestCollectDotNetPackagesFromProjectHelperBranches(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	projectPath := filepath.Join(root, "Broken.csproj")
	if _, err := collectDotNetPackagesFromProject(projectPath); err == nil {
		t.Fatal("expected missing csproj read error")
	}

	if err := os.WriteFile(projectPath, []byte(`<Project>`), 0o644); err != nil {
		t.Fatalf("write invalid csproj: %v", err)
	}
	if _, err := collectDotNetPackagesFromProject(projectPath); err == nil {
		t.Fatal("expected invalid csproj parse error")
	}

	validPath := filepath.Join(root, "Library.csproj")
	if err := os.WriteFile(validPath, []byte(`<Project>
  <ItemGroup>
    <PackageReference Include="Package.WithoutVersion" />
    <PackageReference Include="Package.WithElement">
      <Version> 1.2.3 </Version>
    </PackageReference>
  </ItemGroup>
</Project>`), 0o644); err != nil {
		t.Fatalf("write valid csproj: %v", err)
	}
	packages, err := collectDotNetPackagesFromProject(validPath)
	if err != nil {
		t.Fatalf("collect dotnet helper branches: %v", err)
	}
	if len(packages) != 2 {
		t.Fatalf("packages = %#v", packages)
	}
	lookup := map[string]Package{}
	for _, pkg := range packages {
		lookup[pkg.Name] = pkg
	}
	if lookup["Package.WithoutVersion"].Project != "Library" || lookup["Package.WithoutVersion"].Version != "" {
		t.Fatalf("package without version = %#v", lookup["Package.WithoutVersion"])
	}
	if lookup["Package.WithElement"].Version != "1.2.3" {
		t.Fatalf("package with element version = %#v", lookup["Package.WithElement"])
	}
}

func TestParseHelpers(t *testing.T) {
	t.Parallel()

	if got := parsePerson(nil); got != "" {
		t.Fatalf("parsePerson nil = %q", got)
	}
	if got := parsePerson([]byte(`"Alice <alice@example.test>"`)); got != "Alice" {
		t.Fatalf("parsePerson string = %q", got)
	}
	if got := parsePerson([]byte(`{"name":"Bob"}`)); got != "Bob" {
		t.Fatalf("parsePerson object = %q", got)
	}
	if got := parsePerson([]byte(`{"email":"only@example.test"}`)); got != "" {
		t.Fatalf("parsePerson missing name = %q", got)
	}
	if got := parseRepository(nil); got != "" {
		t.Fatalf("parseRepository nil = %q", got)
	}
	if got := parseRepository([]byte(`"git+https://example.test/repo.git"`)); got != "https://example.test/repo.git" {
		t.Fatalf("parseRepository string = %q", got)
	}
	if got := parseRepository([]byte(`{"url":"git+https://github.com/example/repo.git"}`)); got != "https://github.com/example/repo.git" {
		t.Fatalf("parseRepository = %q", got)
	}
	if got := parseRepository([]byte(`{"type":"git"}`)); got != "" {
		t.Fatalf("parseRepository missing url = %q", got)
	}
	if got := parseLicense(nil); got != "" {
		t.Fatalf("parseLicense nil = %q", got)
	}
	if got := parseLicense([]byte(`" Apache-2.0 "`)); got != "Apache-2.0" {
		t.Fatalf("parseLicense string = %q", got)
	}
	if got := parseLicense([]byte(`{"type":"MIT"}`)); got != "MIT" {
		t.Fatalf("parseLicense = %q", got)
	}
	if got := parseLicense([]byte(`{"name":"MIT"}`)); got != "" {
		t.Fatalf("parseLicense missing type = %q", got)
	}
	if got := cleanPerson("Carol <carol@example.test>"); got != "Carol" {
		t.Fatalf("cleanPerson = %q", got)
	}
	if got := uniqueStrings([]string{"a", "a", "b"}); len(got) != 2 {
		t.Fatalf("uniqueStrings = %#v", got)
	}
}

func TestPackageBuilderHelpers(t *testing.T) {
	t.Parallel()

	if got := buildNodePackages("web", nil, "dependency"); got != nil {
		t.Fatalf("expected nil node packages, got %#v", got)
	}

	node := buildNodePackages("web", map[string]string{"react": "^19.2.4"}, "dependency")
	if len(node) != 1 || node[0].Version != "19.2.4" || node[0].PURL != "pkg:npm/react@19.2.4" {
		t.Fatalf("node packages = %#v", node)
	}

	packages := buildDotNetPackagesFromAssets(nugetAssetsDocument{
		ProjectName: "api",
		Packages: []resolvedNugetPackage{
			{PackageID: "Newtonsoft.Json", Version: "13.0.3", IsDirect: true, HasRuntimeAssets: true},
			{PackageID: "Serilog", Version: "3.1.0", IsDirect: false},
		},
	})
	if len(packages) != 2 {
		t.Fatalf("dotnet packages = %#v", packages)
	}
	if packages[0].DependencyType != "dependency" || !packages[0].HasRuntimeAssets {
		t.Fatalf("direct package = %#v", packages[0])
	}
	if packages[1].DependencyType != "transitiveDependency" {
		t.Fatalf("transitive package = %#v", packages[1])
	}

	if got := installedNodePackageJSONPath("", "react"); got != "" {
		t.Fatalf("installedNodePackageJSONPath blank project = %q", got)
	}
	if got := installedNodePackageJSONPath(filepath.Join("repo", "web"), "@scope/react"); got != filepath.Join("repo", "web", "node_modules", "@scope", "react", "package.json") {
		t.Fatalf("installedNodePackageJSONPath scoped = %q", got)
	}
	if got := makeNodePackageKey("react", " 19.2.4 "); got != "react@19.2.4" {
		t.Fatalf("makeNodePackageKey versioned = %q", got)
	}
	if got := makeNodePackageKey("react", " "); got != "react" {
		t.Fatalf("makeNodePackageKey blank = %q", got)
	}
	if got := parsePeople([]json.RawMessage{
		json.RawMessage(`"Alice <alice@example.test>"`),
		json.RawMessage(`"Alice <alice@example.test>"`),
		json.RawMessage(`{"name":"Bob"}`),
		json.RawMessage(`{"email":"skip@example.test"}`),
	}); len(got) != 2 || got[0] != "Alice" || got[1] != "Bob" {
		t.Fatalf("parsePeople = %#v", got)
	}
	if got := cleanPerson("  Carol <carol@example.test> "); got != "Carol" {
		t.Fatalf("cleanPerson = %q", got)
	}
	if got := firstCSVValue(" alpha ; beta "); got != "alpha" {
		t.Fatalf("firstCSVValue = %q", got)
	}
	if got := firstCSVValue(" , "); got != "" {
		t.Fatalf("firstCSVValue empty = %q", got)
	}
	if got := uniqueStrings([]string{"alice", "", "alice", "bob"}); len(got) != 2 || got[0] != "alice" || got[1] != "bob" {
		t.Fatalf("uniqueStrings = %#v", got)
	}
	if got := firstNonEmpty("", "  ", "value", "later"); got != "value" {
		t.Fatalf("firstNonEmpty = %q", got)
	}
	if isExactNodeVersion("^1.2.3") || isExactNodeVersion("workspace:*") || !isExactNodeVersion("1.2.3") {
		t.Fatal("unexpected isExactNodeVersion result")
	}
}

func TestCollectSkipsNodeModulesAndObjDirectories(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "node_modules", "ignored"), 0o755); err != nil {
		t.Fatalf("mkdir node_modules: %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, "node_modules", "ignored", "package.json"), []byte(`{"dependencies":{"left-pad":"1.3.0"}}`), 0o644); err != nil {
		t.Fatalf("write ignored package.json: %v", err)
	}
	projectDir := filepath.Join(root, "service")
	if err := os.MkdirAll(filepath.Join(projectDir, "obj"), 0o755); err != nil {
		t.Fatalf("mkdir obj: %v", err)
	}
	if err := os.WriteFile(filepath.Join(projectDir, "package.json"), []byte(`{"dependencies":{"react":"19.2.4"}}`), 0o644); err != nil {
		t.Fatalf("write root package.json: %v", err)
	}
	if err := os.WriteFile(filepath.Join(projectDir, "obj", "project.assets.json"), []byte(`{invalid`), 0o644); err != nil {
		t.Fatalf("write ignored assets: %v", err)
	}

	packages, err := Collect(Config{Root: root})
	if err != nil {
		t.Fatalf("collect: %v", err)
	}
	if len(packages) != 1 || packages[0].Name != "react" {
		t.Fatalf("packages = %#v", packages)
	}
}

func TestCollectReturnsWalkErrorsForMissingRoot(t *testing.T) {
	t.Parallel()

	if _, err := Collect(Config{Root: filepath.Join(t.TempDir(), "missing")}); err == nil {
		t.Fatal("expected walk error for missing root")
	}
}

func TestCollectSkipsPackageJSONWhenCoveredByNestedPnpmLockfile(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	appDir := filepath.Join(root, "apps", "web")
	if err := os.MkdirAll(appDir, 0o755); err != nil {
		t.Fatalf("mkdir app dir: %v", err)
	}

	if err := os.WriteFile(filepath.Join(appDir, "package.json"), []byte(`{
  "name":"@repo/web",
  "dependencies":{"react":"19.2.4","scheduler":"0.23.0"}
}`), 0o644); err != nil {
		t.Fatalf("write package.json: %v", err)
	}
	if err := os.WriteFile(filepath.Join(appDir, "pnpm-lock.yaml"), []byte(`lockfileVersion: '9.0'
importers:
  .:
    dependencies:
      react:
        version: 19.2.4
snapshots:
  react@19.2.4: {}
`), 0o644); err != nil {
		t.Fatalf("write lockfile: %v", err)
	}

	packages, err := Collect(Config{Root: root})
	if err != nil {
		t.Fatalf("collect: %v", err)
	}
	if len(packages) != 1 {
		t.Fatalf("packages = %#v", packages)
	}
	if packages[0].Name != "react" || packages[0].Project != "@repo/web" {
		t.Fatalf("package = %#v", packages[0])
	}
}

func TestCollectSkipsPackageJSONWhenCoveredByYarnLockfile(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	appDir := filepath.Join(root, "apps", "web")
	if err := os.MkdirAll(appDir, 0o755); err != nil {
		t.Fatalf("mkdir app dir: %v", err)
	}

	if err := os.WriteFile(filepath.Join(root, "package.json"), []byte(`{
  "name":"repo",
  "workspaces":["apps/*"]
}`), 0o644); err != nil {
		t.Fatalf("write root package.json: %v", err)
	}
	if err := os.WriteFile(filepath.Join(appDir, "package.json"), []byte(`{
  "name":"@repo/web",
  "dependencies":{"react":"19.2.4","scheduler":"0.23.0"}
}`), 0o644); err != nil {
		t.Fatalf("write package.json: %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, "yarn.lock"), []byte(`react@19.2.4:
  version "19.2.4"
`), 0o644); err != nil {
		t.Fatalf("write lockfile: %v", err)
	}

	packages, err := Collect(Config{Root: root})
	if err != nil {
		t.Fatalf("collect: %v", err)
	}
	if len(packages) != 1 {
		t.Fatalf("packages = %#v", packages)
	}
	if packages[0].Name != "react" || packages[0].Project != "@repo/web" {
		t.Fatalf("package = %#v", packages[0])
	}
}

func TestCollectTreatsCleanedRootAsTraversalBoundary(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	nestedRoot := filepath.Join(root, "apps", "web")
	if err := os.MkdirAll(filepath.Join(nestedRoot, "src"), 0o755); err != nil {
		t.Fatalf("mkdir nested root: %v", err)
	}
	if err := os.WriteFile(filepath.Join(nestedRoot, "package.json"), []byte(`{
  "name":"@repo/web",
  "dependencies":{"react":"19.2.4"}
}`), 0o644); err != nil {
		t.Fatalf("write package.json: %v", err)
	}

	packages, err := Collect(Config{Root: filepath.Join(nestedRoot, ".")})
	if err != nil {
		t.Fatalf("collect: %v", err)
	}
	if len(packages) != 1 {
		t.Fatalf("packages = %#v", packages)
	}
	if packages[0].Project != "@repo/web" || packages[0].Name != "react" {
		t.Fatalf("package = %#v", packages[0])
	}
}
