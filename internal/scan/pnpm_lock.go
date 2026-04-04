package scan

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"

	"depaudit-license/internal/inventory"
	"depaudit-license/internal/purl"
)

type pnpmLockFile struct {
	Importers map[string]pnpmImporter `yaml:"importers"`
	Packages  map[string]pnpmSnapshot `yaml:"packages"`
	Snapshots map[string]pnpmSnapshot `yaml:"snapshots"`
}

type pnpmImporter struct {
	Dependencies         map[string]pnpmResolvedRef `yaml:"dependencies"`
	DevDependencies      map[string]pnpmResolvedRef `yaml:"devDependencies"`
	OptionalDependencies map[string]pnpmResolvedRef `yaml:"optionalDependencies"`
}

type pnpmSnapshot struct {
	Dependencies         map[string]string `yaml:"dependencies"`
	OptionalDependencies map[string]string `yaml:"optionalDependencies"`
}

type pnpmResolvedRef struct {
	Version string
}

func (r *pnpmResolvedRef) UnmarshalYAML(node *yaml.Node) error {
	switch node.Kind {
	case yaml.ScalarNode:
		r.Version = strings.TrimSpace(node.Value)
		return nil
	case yaml.MappingNode:
		var payload struct {
			Version string `yaml:"version"`
		}
		if err := node.Decode(&payload); err != nil {
			return err
		}
		r.Version = strings.TrimSpace(payload.Version)
		return nil
	default:
		return fmt.Errorf("unsupported pnpm dependency node kind %d", node.Kind)
	}
}

func collectPnpmPackages(lockfilePath string) ([]Package, error) {
	document, err := readPnpmLockfile(lockfilePath)
	if err != nil {
		return nil, err
	}

	lockDir := filepath.Dir(lockfilePath)
	graph := pnpmSnapshots(document)
	results := make([]Package, 0)

	importerKeys := make([]string, 0, len(document.Importers))
	for key := range document.Importers {
		importerKeys = append(importerKeys, key)
	}
	sort.Strings(importerKeys)

	for _, importerKey := range importerKeys {
		importer := document.Importers[importerKey]
		projectDir := lockDir
		if importerKey != "." {
			projectDir = filepath.Join(lockDir, filepath.FromSlash(importerKey))
		}
		projectName, peerDeps := readNodeProjectMetadata(projectDir, importerKey)
		results = append(results, buildPnpmImporterPackages(projectName, importer, peerDeps, graph)...)
	}

	return results, nil
}

func readPnpmLockfile(path string) (pnpmLockFile, error) {
	payload, err := os.ReadFile(path)
	if err != nil {
		return pnpmLockFile{}, fmt.Errorf("read pnpm lockfile %s: %w", path, err)
	}

	var document pnpmLockFile
	if err := yaml.Unmarshal(payload, &document); err != nil {
		return pnpmLockFile{}, fmt.Errorf("parse pnpm lockfile %s: %w", path, err)
	}
	if len(document.Importers) == 0 {
		return pnpmLockFile{}, fmt.Errorf("pnpm lockfile %s does not define any importers", path)
	}
	return document, nil
}

func pnpmSnapshots(document pnpmLockFile) map[string]pnpmSnapshot {
	source := document.Snapshots
	if len(source) == 0 {
		source = document.Packages
	}

	graph := make(map[string]pnpmSnapshot, len(source))
	for rawKey, snapshot := range source {
		graph[canonicalPnpmSnapshotKey(rawKey)] = snapshot
	}
	return graph
}

func buildPnpmImporterPackages(project string, importer pnpmImporter, peerDeps map[string]struct{}, graph map[string]pnpmSnapshot) []Package {
	categories := map[string]string{}
	seed := func(name string, ref pnpmResolvedRef, category string) {
		key, ok := pnpmKeyFromReference(name, ref.Version)
		if !ok {
			return
		}
		assignPnpmCategory(categories, key, category)
	}

	for name, ref := range importer.Dependencies {
		category := "dependency"
		if _, ok := peerDeps[name]; ok {
			category = "peerDependency"
		}
		seed(name, ref, category)
	}
	for name, ref := range importer.OptionalDependencies {
		category := "dependency"
		if _, ok := peerDeps[name]; ok {
			category = "peerDependency"
		}
		seed(name, ref, category)
	}
	for name, ref := range importer.DevDependencies {
		category := "devDependency"
		if _, ok := peerDeps[name]; ok {
			category = "peerDependency"
		}
		seed(name, ref, category)
	}

	queue := make([]string, 0, len(categories))
	for key := range categories {
		queue = append(queue, key)
	}

	for len(queue) > 0 {
		key := queue[0]
		queue = queue[1:]

		snapshot, ok := graph[key]
		if !ok {
			continue
		}

		for name, ref := range snapshot.Dependencies {
			childKey, ok := pnpmKeyFromReference(name, ref)
			if !ok {
				continue
			}
			if assignPnpmCategory(categories, childKey, categories[key]) {
				queue = append(queue, childKey)
			}
		}
		for name, ref := range snapshot.OptionalDependencies {
			childKey, ok := pnpmKeyFromReference(name, ref)
			if !ok {
				continue
			}
			if assignPnpmCategory(categories, childKey, categories[key]) {
				queue = append(queue, childKey)
			}
		}
	}

	keys := make([]string, 0, len(categories))
	for key := range categories {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	packages := make([]Package, 0, len(keys))
	for _, key := range keys {
		name, version, ok := splitPnpmSnapshotKey(key)
		if !ok {
			continue
		}
		packages = append(packages, Package{
			Ecosystem:      "node",
			Project:        project,
			Name:           name,
			Version:        version,
			PURL:           mustNodePURL(name, version),
			DependencyType: categories[key],
		})
	}
	return packages
}

func assignPnpmCategory(categories map[string]string, key string, category string) bool {
	current, exists := categories[key]
	if !exists || pnpmCategoryPriority(category) > pnpmCategoryPriority(current) {
		categories[key] = category
		return true
	}
	return false
}

func pnpmCategoryPriority(category string) int {
	switch category {
	case "dependency":
		return 3
	case "peerDependency":
		return 2
	case "devDependency":
		return 1
	default:
		return 0
	}
}

func pnpmKeyFromReference(name string, raw string) (string, bool) {
	version := pnpmResolvedVersion(raw)
	if version == "" {
		return "", false
	}
	return canonicalPnpmSnapshotKey(name + "@" + version), true
}

func pnpmResolvedVersion(raw string) string {
	value := strings.TrimSpace(raw)
	if value == "" {
		return ""
	}
	if strings.HasPrefix(value, "link:") || strings.HasPrefix(value, "workspace:") || strings.HasPrefix(value, "file:") {
		return ""
	}
	if idx := strings.Index(value, "("); idx >= 0 {
		value = value[:idx]
	}
	return strings.TrimSpace(value)
}

func canonicalPnpmSnapshotKey(raw string) string {
	value := strings.TrimSpace(raw)
	value = strings.TrimPrefix(value, "/")
	if idx := strings.Index(value, "("); idx >= 0 {
		return value[:idx]
	}
	return value
}

func splitPnpmSnapshotKey(key string) (string, string, bool) {
	value := canonicalPnpmSnapshotKey(key)
	index := strings.LastIndex(value, "@")
	if index <= 0 || index == len(value)-1 {
		return "", "", false
	}
	return value[:index], value[index+1:], true
}

func nearestPnpmLockfile(path string, root string) string {
	current := filepath.Dir(path)
	root = filepath.Clean(root)
	for {
		candidate := filepath.Join(current, "pnpm-lock.yaml")
		if _, err := os.Stat(candidate); err == nil {
			return candidate
		}
		if current == root {
			break
		}
		next := filepath.Dir(current)
		if next == current {
			break
		}
		current = next
	}
	return ""
}

func readNodeProjectMetadata(dir string, importerKey string) (string, map[string]struct{}) {
	packageJSON := filepath.Join(dir, "package.json")
	project := filepath.Base(dir)
	if importerKey == "." {
		project = filepath.Base(dir)
	}

	peerDeps := map[string]struct{}{}
	payload, err := os.ReadFile(packageJSON)
	if err != nil {
		if importerKey == "." {
			return filepath.Base(dir), peerDeps
		}
		return strings.Trim(filepath.ToSlash(importerKey), "/"), peerDeps
	}

	var file nodePackageFile
	if err := json.Unmarshal(payload, &file); err != nil {
		if importerKey == "." {
			return filepath.Base(dir), peerDeps
		}
		return strings.Trim(filepath.ToSlash(importerKey), "/"), peerDeps
	}

	if strings.TrimSpace(file.Name) != "" {
		project = file.Name
	}
	for name := range file.PeerDependencies {
		peerDeps[name] = struct{}{}
	}
	return project, peerDeps
}

func mustNodePURL(name string, version string) string {
	value, _ := purl.FromPackage(inventory.Package{Ecosystem: "node", Name: name, Version: version})
	return value
}
