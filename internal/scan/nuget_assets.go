package scan

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

type nugetAssetsDocument struct {
	ProjectPath string
	ProjectName string
	Packages    []resolvedNugetPackage
}

type resolvedNugetPackage struct {
	PackageID        string
	Version          string
	IsDirect         bool
	HasRuntimeAssets bool
}

type nugetAssetsFile struct {
	Libraries map[string]struct {
		Type string `json:"type"`
	} `json:"libraries"`
	Project struct {
		Restore struct {
			ProjectPath string `json:"projectPath"`
		} `json:"restore"`
		Frameworks map[string]struct {
			Dependencies map[string]any `json:"dependencies"`
		} `json:"frameworks"`
	} `json:"project"`
	Targets map[string]map[string]struct {
		Runtime        map[string]any `json:"runtime"`
		Native         map[string]any `json:"native"`
		RuntimeTargets map[string]any `json:"runtimeTargets"`
	} `json:"targets"`
}

func readNugetAssets(path string) (nugetAssetsDocument, error) {
	payload, err := os.ReadFile(path)
	if err != nil {
		return nugetAssetsDocument{}, fmt.Errorf("read project.assets.json %s: %w", path, err)
	}

	var file nugetAssetsFile
	if err := json.Unmarshal(payload, &file); err != nil {
		return nugetAssetsDocument{}, fmt.Errorf("parse project.assets.json %s: %w", path, err)
	}

	projectPath, err := resolveAssetsProjectPath(path, file.Project.Restore.ProjectPath)
	if err != nil {
		return nugetAssetsDocument{}, err
	}

	packages := readResolvedNugetPackages(file)
	return nugetAssetsDocument{
		ProjectPath: projectPath,
		ProjectName: strings.TrimSuffix(filepath.Base(projectPath), filepath.Ext(projectPath)),
		Packages:    packages,
	}, nil
}

func resolveAssetsProjectPath(assetsPath string, configuredProjectPath string) (string, error) {
	if strings.TrimSpace(configuredProjectPath) != "" {
		return filepath.Clean(configuredProjectPath), nil
	}

	objDir := filepath.Dir(assetsPath)
	projectDir := filepath.Dir(objDir)
	matches, err := filepath.Glob(filepath.Join(projectDir, "*.*proj"))
	if err != nil {
		return "", fmt.Errorf("resolve project path from assets %s: %w", assetsPath, err)
	}

	var supported []string
	for _, match := range matches {
		switch strings.ToLower(filepath.Ext(match)) {
		case ".csproj", ".fsproj", ".vbproj":
			supported = append(supported, filepath.Clean(match))
		}
	}
	sort.Strings(supported)

	switch len(supported) {
	case 1:
		return supported[0], nil
	case 0:
		return "", fmt.Errorf("resolve project path from assets %s: no supported project file found", assetsPath)
	default:
		dirName := filepath.Base(projectDir)
		var narrowed []string
		for _, candidate := range supported {
			if strings.EqualFold(strings.TrimSuffix(filepath.Base(candidate), filepath.Ext(candidate)), dirName) {
				narrowed = append(narrowed, candidate)
			}
		}
		if len(narrowed) == 1 {
			return narrowed[0], nil
		}
		return "", fmt.Errorf("resolve project path from assets %s: ambiguous project files", assetsPath)
	}
}

func readResolvedNugetPackages(file nugetAssetsFile) []resolvedNugetPackage {
	packageMap := map[string]resolvedNugetPackage{}
	directPackageIDs := readDirectNugetPackageIDs(file)
	hasTargets, runtimePackageKeys := readRuntimeAssetPackageKeys(file)

	for libraryKey, library := range file.Libraries {
		if !strings.EqualFold(library.Type, "package") {
			continue
		}

		packageID, version, ok := splitNugetPackageKey(libraryKey)
		if !ok {
			continue
		}

		key := makeNugetPackageKey(packageID, version)
		packageMap[key] = resolvedNugetPackage{
			PackageID:        packageID,
			Version:          version,
			IsDirect:         directPackageIDs[packageID],
			HasRuntimeAssets: !hasTargets || runtimePackageKeys[key],
		}
	}

	packages := make([]resolvedNugetPackage, 0, len(packageMap))
	for _, pkg := range packageMap {
		packages = append(packages, pkg)
	}
	sort.Slice(packages, func(i, j int) bool {
		if !strings.EqualFold(packages[i].PackageID, packages[j].PackageID) {
			return strings.ToLower(packages[i].PackageID) < strings.ToLower(packages[j].PackageID)
		}
		return strings.ToLower(packages[i].Version) < strings.ToLower(packages[j].Version)
	})
	return packages
}

func readDirectNugetPackageIDs(file nugetAssetsFile) map[string]bool {
	result := map[string]bool{}
	for _, framework := range file.Project.Frameworks {
		for dependency := range framework.Dependencies {
			trimmed := strings.TrimSpace(dependency)
			if trimmed != "" {
				result[trimmed] = true
			}
		}
	}
	return result
}

func readRuntimeAssetPackageKeys(file nugetAssetsFile) (bool, map[string]bool) {
	if len(file.Targets) == 0 {
		return false, nil
	}

	result := map[string]bool{}
	for _, target := range file.Targets {
		for libraryKey, library := range target {
			packageID, version, ok := splitNugetPackageKey(libraryKey)
			if !ok {
				continue
			}
			if len(library.Runtime) == 0 && len(library.Native) == 0 && len(library.RuntimeTargets) == 0 {
				continue
			}
			result[makeNugetPackageKey(packageID, version)] = true
		}
	}
	return true, result
}

func splitNugetPackageKey(key string) (string, string, bool) {
	index := strings.LastIndex(key, "/")
	if index <= 0 || index >= len(key)-1 {
		return "", "", false
	}
	return key[:index], key[index+1:], true
}

func makeNugetPackageKey(packageID string, version string) string {
	return packageID + "/" + version
}
