package policy

import (
	"path/filepath"
	"strings"

	"depaudit-license/internal/inventory"
)

func SelectorMatchesPackage(selector Selector, pkg inventory.Package, projectCandidates ...string) bool {
	if len(selector.Ecosystems) > 0 && !containsEcosystem(selector.Ecosystems, pkg.Ecosystem) {
		return false
	}
	if len(selector.Names) > 0 && !containsNormalized(selector.Names, pkg.Name) {
		return false
	}
	if len(selector.NameGlobs) > 0 && !matchesAnyGlob(selector.NameGlobs, pkg.Name) {
		return false
	}
	if len(selector.Versions) > 0 && !containsTrimmed(selector.Versions, pkg.Version) {
		return false
	}
	if len(selector.Projects) > 0 && !matchesProject(selector.Projects, pkg.Project, projectCandidates...) {
		return false
	}
	if len(selector.DependencyTypes) > 0 && !containsNormalized(selector.DependencyTypes, pkg.DependencyType) {
		return false
	}
	if selector.HasRuntimeAssets != nil && pkg.HasRuntimeAssets != *selector.HasRuntimeAssets {
		return false
	}
	if len(selector.PURLs) > 0 && !containsTrimmed(selector.PURLs, pkg.PURL) {
		return false
	}
	return true
}

func containsEcosystem(values []string, candidate string) bool {
	candidate = strings.ToLower(strings.TrimSpace(candidate))
	for _, value := range values {
		switch strings.ToLower(strings.TrimSpace(value)) {
		case candidate:
			return true
		case "npm":
			if candidate == "node" {
				return true
			}
		case "nuget":
			if candidate == "dotnet" {
				return true
			}
		case "node":
			if candidate == "npm" {
				return true
			}
		case "dotnet":
			if candidate == "nuget" {
				return true
			}
		}
	}
	return false
}

func matchesProject(values []string, project string, projectCandidates ...string) bool {
	candidates := append([]string{project}, projectCandidates...)
	for _, candidate := range candidates {
		if containsTrimmed(values, candidate) {
			return true
		}
	}
	return false
}

func containsNormalized(values []string, candidate string) bool {
	normalizedCandidate := strings.ToLower(strings.TrimSpace(candidate))
	for _, value := range values {
		if strings.ToLower(strings.TrimSpace(value)) == normalizedCandidate {
			return true
		}
	}
	return false
}

func containsTrimmed(values []string, candidate string) bool {
	trimmedCandidate := strings.TrimSpace(candidate)
	for _, value := range values {
		if strings.TrimSpace(value) == trimmedCandidate {
			return true
		}
	}
	return false
}

func matchesAnyGlob(globs []string, candidate string) bool {
	normalizedCandidate := strings.ToLower(strings.TrimSpace(candidate))
	for _, glob := range globs {
		ok, err := filepath.Match(strings.ToLower(strings.TrimSpace(glob)), normalizedCandidate)
		if err == nil && ok {
			return true
		}
	}
	return false
}
