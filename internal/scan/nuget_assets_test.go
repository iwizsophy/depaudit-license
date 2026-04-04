package scan

import (
	"os"
	"path/filepath"
	"testing"
)

func TestReadNugetAssetsParsesResolvedPackages(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	projectDir := filepath.Join(dir, "App")
	if err := os.MkdirAll(filepath.Join(projectDir, "obj"), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	projectPath := filepath.Join(projectDir, "App.csproj")
	if err := os.WriteFile(projectPath, []byte("<Project />"), 0o644); err != nil {
		t.Fatalf("write project: %v", err)
	}

	assets := `{
  "version": 3,
  "project": {
    "restore": {
      "projectPath": "` + filepath.ToSlash(projectPath) + `"
    },
    "frameworks": {
      "net8.0": {
        "dependencies": {
          "Newtonsoft.Json": {
            "target": "Package",
            "version": "[13.0.3, )"
          }
        }
      }
    }
  },
  "libraries": {
    "Newtonsoft.Json/13.0.3": { "type": "package" },
    "System.Text.Encodings.Web/8.0.0": { "type": "package" },
    "App/1.0.0": { "type": "project" }
  },
  "targets": {
    "net8.0": {
      "Newtonsoft.Json/13.0.3": {
        "runtime": {
          "lib/net8.0/Newtonsoft.Json.dll": {}
        }
      },
      "System.Text.Encodings.Web/8.0.0": {}
    }
  }
}`
	assetsPath := filepath.Join(projectDir, "obj", "project.assets.json")
	if err := os.WriteFile(assetsPath, []byte(assets), 0o644); err != nil {
		t.Fatalf("write assets: %v", err)
	}

	document, err := readNugetAssets(assetsPath)
	if err != nil {
		t.Fatalf("read assets: %v", err)
	}

	if document.ProjectPath != projectPath {
		t.Fatalf("project path = %q, want %q", document.ProjectPath, projectPath)
	}
	if document.ProjectName != "App" {
		t.Fatalf("project name = %q, want App", document.ProjectName)
	}
	if len(document.Packages) != 2 {
		t.Fatalf("package count = %d, want 2", len(document.Packages))
	}

	if document.Packages[0].PackageID != "Newtonsoft.Json" || !document.Packages[0].IsDirect || !document.Packages[0].HasRuntimeAssets {
		t.Fatalf("unexpected first package: %+v", document.Packages[0])
	}
	if document.Packages[1].PackageID != "System.Text.Encodings.Web" || document.Packages[1].IsDirect || document.Packages[1].HasRuntimeAssets {
		t.Fatalf("unexpected second package: %+v", document.Packages[1])
	}
}

func TestReadNugetAssetsErrorBranchesAndConfiguredProjectPath(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	assetsPath := filepath.Join(dir, "project.assets.json")
	if _, err := readNugetAssets(filepath.Join(dir, "missing.assets.json")); err == nil {
		t.Fatal("expected read error")
	}
	if err := os.WriteFile(assetsPath, []byte(`{invalid`), 0o644); err != nil {
		t.Fatalf("write invalid assets: %v", err)
	}
	if _, err := readNugetAssets(assetsPath); err == nil {
		t.Fatal("expected parse error")
	}

	projectPath := filepath.Join(dir, "Configured.csproj")
	if err := os.WriteFile(assetsPath, []byte(`{
  "project": { "restore": { "projectPath": "`+filepath.ToSlash(projectPath)+`" }, "frameworks": {} },
  "libraries": {},
  "targets": {}
}`), 0o644); err != nil {
		t.Fatalf("write configured assets: %v", err)
	}
	document, err := readNugetAssets(assetsPath)
	if err != nil {
		t.Fatalf("read configured assets: %v", err)
	}
	if document.ProjectPath != projectPath {
		t.Fatalf("project path = %q", document.ProjectPath)
	}
}

func TestReadNugetAssetsInfersProjectPathFromAssetsLocation(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	projectDir := filepath.Join(dir, "Library")
	if err := os.MkdirAll(filepath.Join(projectDir, "obj"), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	projectPath := filepath.Join(projectDir, "Library.csproj")
	if err := os.WriteFile(projectPath, []byte("<Project />"), 0o644); err != nil {
		t.Fatalf("write project: %v", err)
	}

	assetsPath := filepath.Join(projectDir, "obj", "project.assets.json")
	if err := os.WriteFile(assetsPath, []byte(`{
  "project": { "restore": { "projectPath": "" }, "frameworks": {} },
  "libraries": {},
  "targets": {}
}`), 0o644); err != nil {
		t.Fatalf("write assets: %v", err)
	}

	document, err := readNugetAssets(assetsPath)
	if err != nil {
		t.Fatalf("read assets: %v", err)
	}

	if document.ProjectPath != projectPath {
		t.Fatalf("project path = %q, want %q", document.ProjectPath, projectPath)
	}
}

func TestCollectDotNetPackagesUsesAssetsDiscovery(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	projectDir := filepath.Join(dir, "Service")
	if err := os.MkdirAll(filepath.Join(projectDir, "obj"), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	projectPath := filepath.Join(projectDir, "Service.csproj")
	if err := os.WriteFile(projectPath, []byte(`<Project><ItemGroup><PackageReference Include="Should.Not.Be.Used" Version="1.0.0" /></ItemGroup></Project>`), 0o644); err != nil {
		t.Fatalf("write project: %v", err)
	}

	assets := `{
  "project": {
    "restore": {
      "projectPath": "` + filepath.ToSlash(projectPath) + `"
    },
    "frameworks": {
      "net8.0": {
        "dependencies": {
          "Newtonsoft.Json": {}
        }
      }
    }
  },
  "libraries": {
    "Newtonsoft.Json/13.0.3": { "type": "package" },
    "System.Text.Encodings.Web/8.0.0": { "type": "package" }
  },
  "targets": {
    "net8.0": {
      "Newtonsoft.Json/13.0.3": {
        "runtime": {
          "lib/net8.0/Newtonsoft.Json.dll": {}
        }
      }
    }
  }
}`
	if err := os.WriteFile(filepath.Join(projectDir, "obj", "project.assets.json"), []byte(assets), 0o644); err != nil {
		t.Fatalf("write assets: %v", err)
	}

	packages, err := collectDotNetPackages(projectPath)
	if err != nil {
		t.Fatalf("collect packages: %v", err)
	}

	if len(packages) != 2 {
		t.Fatalf("package count = %d, want 2", len(packages))
	}
	if packages[0].Name != "Newtonsoft.Json" || packages[0].DependencyType != "dependency" || !packages[0].HasRuntimeAssets {
		t.Fatalf("unexpected direct package: %+v", packages[0])
	}
	if packages[1].Name != "System.Text.Encodings.Web" || packages[1].DependencyType != "transitiveDependency" {
		t.Fatalf("unexpected transitive package: %+v", packages[1])
	}
}

func TestCollectDotNetPackagesFallsBackToProjectReferencesWhenAssetsMissing(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	projectPath := filepath.Join(dir, "Fallback.csproj")
	if err := os.WriteFile(projectPath, []byte(`<Project><ItemGroup><PackageReference Include="Newtonsoft.Json" Version="13.0.3" /></ItemGroup></Project>`), 0o644); err != nil {
		t.Fatalf("write project: %v", err)
	}

	packages, err := collectDotNetPackages(projectPath)
	if err != nil {
		t.Fatalf("collect packages: %v", err)
	}

	if len(packages) != 1 {
		t.Fatalf("package count = %d, want 1", len(packages))
	}
	if packages[0].DependencyType != "dependency" || !packages[0].HasRuntimeAssets {
		t.Fatalf("unexpected fallback package: %+v", packages[0])
	}
}

func TestCollectDotNetPackagesPrefersAssetsErrorsOverProjectFallback(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	projectDir := filepath.Join(dir, "Service")
	if err := os.MkdirAll(filepath.Join(projectDir, "obj"), 0o755); err != nil {
		t.Fatalf("mkdir obj: %v", err)
	}

	projectPath := filepath.Join(projectDir, "Service.csproj")
	if err := os.WriteFile(projectPath, []byte(`<Project><ItemGroup><PackageReference Include="Newtonsoft.Json" Version="13.0.3" /></ItemGroup></Project>`), 0o644); err != nil {
		t.Fatalf("write project: %v", err)
	}
	if err := os.WriteFile(filepath.Join(projectDir, "obj", "project.assets.json"), []byte(`{invalid`), 0o644); err != nil {
		t.Fatalf("write invalid assets: %v", err)
	}

	if _, err := collectDotNetPackages(projectPath); err == nil {
		t.Fatal("expected invalid assets error")
	}
}

func TestResolveAssetsProjectPathEdgeCases(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	projectDir := filepath.Join(dir, "Worker")
	objDir := filepath.Join(projectDir, "obj")
	if err := os.MkdirAll(objDir, 0o755); err != nil {
		t.Fatalf("mkdir obj: %v", err)
	}
	assetsPath := filepath.Join(objDir, "project.assets.json")

	if _, err := resolveAssetsProjectPath(assetsPath, ""); err == nil {
		t.Fatal("expected missing project file error")
	}

	for _, name := range []string{"Api.csproj", "Worker.csproj"} {
		if err := os.WriteFile(filepath.Join(projectDir, name), []byte("<Project />"), 0o644); err != nil {
			t.Fatalf("write project %s: %v", name, err)
		}
	}
	resolved, err := resolveAssetsProjectPath(assetsPath, "")
	if err != nil {
		t.Fatalf("resolveAssetsProjectPath narrowed: %v", err)
	}
	if resolved != filepath.Join(projectDir, "Worker.csproj") {
		t.Fatalf("resolved narrowed project = %q", resolved)
	}

	projectDir2 := filepath.Join(dir, "Ambiguous")
	objDir2 := filepath.Join(projectDir2, "obj")
	if err := os.MkdirAll(objDir2, 0o755); err != nil {
		t.Fatalf("mkdir ambiguous obj: %v", err)
	}
	for _, name := range []string{"One.csproj", "Two.fsproj"} {
		if err := os.WriteFile(filepath.Join(projectDir2, name), []byte("<Project />"), 0o644); err != nil {
			t.Fatalf("write ambiguous project %s: %v", name, err)
		}
	}
	if _, err := resolveAssetsProjectPath(filepath.Join(objDir2, "project.assets.json"), ""); err == nil {
		t.Fatal("expected ambiguous project file error")
	}
}

func TestNugetAssetsHelperFunctions(t *testing.T) {
	t.Parallel()

	if _, _, ok := splitNugetPackageKey("invalid"); ok {
		t.Fatal("expected invalid package key")
	}
	if pkg, version, ok := splitNugetPackageKey("Newtonsoft.Json/13.0.3"); !ok || pkg != "Newtonsoft.Json" || version != "13.0.3" {
		t.Fatalf("splitNugetPackageKey = %q %q %v", pkg, version, ok)
	}

	hasTargets, runtimeKeys := readRuntimeAssetPackageKeys(nugetAssetsFile{})
	if hasTargets || runtimeKeys != nil {
		t.Fatalf("readRuntimeAssetPackageKeys empty = %v %#v", hasTargets, runtimeKeys)
	}
}

func TestNugetAssetsRuntimeAndResolvedPackageHelpers(t *testing.T) {
	t.Parallel()

	file := nugetAssetsFile{
		Libraries: map[string]struct {
			Type string `json:"type"`
		}{
			"Newtonsoft.Json/13.0.3": {Type: "package"},
			"Native.Helper/1.0.0":    {Type: "package"},
			"Runtime.Target/2.0.0":   {Type: "package"},
			"InvalidKey":             {Type: "package"},
		},
		Project: struct {
			Restore struct {
				ProjectPath string `json:"projectPath"`
			} `json:"restore"`
			Frameworks map[string]struct {
				Dependencies map[string]any `json:"dependencies"`
			} `json:"frameworks"`
		}{
			Frameworks: map[string]struct {
				Dependencies map[string]any `json:"dependencies"`
			}{
				"net8.0": {Dependencies: map[string]any{"Newtonsoft.Json": map[string]any{}}},
			},
		},
		Targets: map[string]map[string]struct {
			Runtime        map[string]any `json:"runtime"`
			Native         map[string]any `json:"native"`
			RuntimeTargets map[string]any `json:"runtimeTargets"`
		}{
			"net8.0": {
				"Newtonsoft.Json/13.0.3": {Runtime: map[string]any{"lib/net8.0/a.dll": map[string]any{}}},
				"Native.Helper/1.0.0":    {Native: map[string]any{"runtimes/win/native/a.dll": map[string]any{}}},
				"Runtime.Target/2.0.0":   {RuntimeTargets: map[string]any{"runtimes/linux-x64/lib/a.dll": map[string]any{}}},
			},
		},
	}

	packages := readResolvedNugetPackages(file)
	if len(packages) != 3 {
		t.Fatalf("packages = %#v", packages)
	}
	if !packages[0].HasRuntimeAssets || !packages[1].HasRuntimeAssets || !packages[2].HasRuntimeAssets {
		t.Fatalf("runtime flags = %#v", packages)
	}
	if !packages[1].IsDirect && packages[1].PackageID == "Newtonsoft.Json" {
		t.Fatalf("expected direct package = %#v", packages[1])
	}
}
