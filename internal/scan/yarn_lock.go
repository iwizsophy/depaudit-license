package scan

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

type nodeWorkspaces []string

type yarnLockDocument struct {
	Descriptors map[string]string
	Packages    map[string]yarnLockPackage
}

type yarnLockPackage struct {
	Name                 string
	Version              string
	Dependencies         map[string]string
	OptionalDependencies map[string]string
}

type yarnImporter struct {
	Project              string
	Dependencies         map[string]string
	DevDependencies      map[string]string
	OptionalDependencies map[string]string
	PeerDependencies     map[string]struct{}
}

type yarnRawEntry struct {
	Selectors            []string
	Version              string
	Dependencies         map[string]string
	OptionalDependencies map[string]string
}

func (w *nodeWorkspaces) UnmarshalJSON(data []byte) error {
	var list []string
	if err := json.Unmarshal(data, &list); err == nil {
		*w = append((*w)[:0], list...)
		return nil
	}

	var object struct {
		Packages []string `json:"packages"`
	}
	if err := json.Unmarshal(data, &object); err == nil {
		*w = append((*w)[:0], object.Packages...)
		return nil
	}

	return fmt.Errorf("unsupported workspaces payload")
}

func collectYarnPackages(lockfilePath string) ([]Package, error) {
	document, err := readYarnLockfile(lockfilePath)
	if err != nil {
		return nil, err
	}

	importers, err := readYarnImporters(filepath.Dir(lockfilePath))
	if err != nil {
		return nil, err
	}

	results := make([]Package, 0)
	for _, importer := range importers {
		results = append(results, buildYarnImporterPackages(importer, document)...)
	}
	return results, nil
}

func readYarnLockfile(path string) (yarnLockDocument, error) {
	payload, err := os.ReadFile(path)
	if err != nil {
		return yarnLockDocument{}, fmt.Errorf("read yarn lockfile %s: %w", path, err)
	}

	rawEntries, err := parseYarnLockEntries(payload)
	if err != nil {
		return yarnLockDocument{}, fmt.Errorf("parse yarn lockfile %s: %w", path, err)
	}
	if len(rawEntries) == 0 {
		return yarnLockDocument{}, fmt.Errorf("yarn lockfile %s does not define any packages", path)
	}

	document := yarnLockDocument{
		Descriptors: make(map[string]string),
		Packages:    make(map[string]yarnLockPackage),
	}
	for _, entry := range rawEntries {
		for _, selector := range entry.Selectors {
			name, _, ok := splitYarnDescriptor(selector)
			if !ok || strings.TrimSpace(entry.Version) == "" {
				continue
			}

			packageKey := yarnPackageKey(name, entry.Version)
			document.Descriptors[yarnNormalizeDescriptor(selector)] = packageKey
			document.Packages[packageKey] = yarnLockPackage{
				Name:                 name,
				Version:              entry.Version,
				Dependencies:         cloneStringMap(entry.Dependencies),
				OptionalDependencies: cloneStringMap(entry.OptionalDependencies),
			}
		}
	}

	if len(document.Packages) == 0 {
		return yarnLockDocument{}, fmt.Errorf("yarn lockfile %s does not define any resolvable packages", path)
	}
	return document, nil
}

func parseYarnLockEntries(payload []byte) ([]yarnRawEntry, error) {
	scanner := bufio.NewScanner(bytes.NewReader(payload))
	scanner.Buffer(make([]byte, 1024), 1024*1024)

	var (
		entries         []yarnRawEntry
		current         *yarnRawEntry
		section         string
		headerFragments []string
	)

	finishCurrent := func() {
		if current == nil {
			return
		}
		entries = append(entries, *current)
		current = nil
		section = ""
	}

	for scanner.Scan() {
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}

		indent := countLeadingSpaces(line)
		if indent == 0 {
			headerFragments = append(headerFragments, trimmed)
			if !strings.HasSuffix(trimmed, ":") {
				continue
			}

			finishCurrent()
			selectors, ok := parseYarnEntrySelectors(strings.Join(headerFragments, " "))
			headerFragments = nil
			if !ok || len(selectors) == 0 {
				return nil, fmt.Errorf("unsupported entry header %q", trimmed)
			}
			if len(selectors) == 1 && selectors[0] == "__metadata" {
				continue
			}

			current = &yarnRawEntry{
				Selectors:            selectors,
				Dependencies:         map[string]string{},
				OptionalDependencies: map[string]string{},
			}
			continue
		}

		if current == nil {
			continue
		}

		if indent == 2 {
			switch trimmed {
			case "dependencies:":
				section = "dependencies"
				continue
			case "optionalDependencies:":
				section = "optionalDependencies"
				continue
			default:
				section = ""
			}

			key, value, ok := parseYarnPropertyLine(trimmed)
			if ok && key == "version" {
				current.Version = yarnUnquote(value)
			}
			continue
		}

		if indent >= 4 && section != "" {
			name, ref, ok := parseYarnPropertyLine(trimmed)
			if !ok {
				continue
			}
			switch section {
			case "dependencies":
				current.Dependencies[name] = yarnUnquote(ref)
			case "optionalDependencies":
				current.OptionalDependencies[name] = yarnUnquote(ref)
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}
	finishCurrent()
	return entries, nil
}

func parseYarnEntrySelectors(header string) ([]string, bool) {
	header = strings.TrimSpace(header)
	if !strings.HasSuffix(header, ":") {
		return nil, false
	}
	header = strings.TrimSuffix(header, ":")
	if strings.TrimSpace(header) == "" {
		return nil, false
	}

	parts := splitYarnCSV(header)
	selectors := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(yarnUnquote(part))
		if part != "" {
			selectors = append(selectors, part)
		}
	}
	return selectors, len(selectors) > 0
}

func splitYarnCSV(value string) []string {
	var (
		parts    []string
		current  strings.Builder
		inQuotes bool
	)

	for _, ch := range value {
		switch ch {
		case '"':
			inQuotes = !inQuotes
			current.WriteRune(ch)
		case ',':
			if inQuotes {
				current.WriteRune(ch)
				continue
			}
			parts = append(parts, current.String())
			current.Reset()
		default:
			current.WriteRune(ch)
		}
	}
	parts = append(parts, current.String())
	return parts
}

func parseYarnPropertyLine(line string) (string, string, bool) {
	if key, value, ok := strings.Cut(line, ":"); ok {
		return strings.TrimSpace(yarnUnquote(key)), strings.TrimSpace(value), true
	}

	parts := strings.Fields(line)
	if len(parts) < 2 {
		return "", "", false
	}
	return strings.TrimSpace(yarnUnquote(parts[0])), strings.Join(parts[1:], " "), true
}

func yarnUnquote(value string) string {
	return strings.Trim(strings.TrimSpace(value), `"`)
}

func countLeadingSpaces(value string) int {
	count := 0
	for _, ch := range value {
		if ch != ' ' {
			break
		}
		count++
	}
	return count
}

func readYarnImporters(lockDir string) ([]yarnImporter, error) {
	rootManifest, rootExists, err := readNodeManifest(filepath.Join(lockDir, "package.json"))
	if err != nil {
		return nil, err
	}

	importers := make([]yarnImporter, 0)
	seen := map[string]struct{}{}
	addImporter := func(projectDir string, manifest nodePackageFile) {
		project := filepath.Base(projectDir)
		if strings.TrimSpace(manifest.Name) != "" {
			project = manifest.Name
		}

		importer := yarnImporter{
			Project:              project,
			Dependencies:         cloneStringMap(manifest.Dependencies),
			DevDependencies:      cloneStringMap(manifest.DevDependencies),
			OptionalDependencies: cloneStringMap(manifest.OptionalDependencies),
			PeerDependencies:     make(map[string]struct{}, len(manifest.PeerDependencies)),
		}
		for name := range manifest.PeerDependencies {
			importer.PeerDependencies[name] = struct{}{}
		}

		key := strings.Join([]string{importer.Project, projectDir}, "\x00")
		if _, ok := seen[key]; ok {
			return
		}
		seen[key] = struct{}{}
		importers = append(importers, importer)
	}

	if rootExists {
		addImporter(lockDir, rootManifest)
	}

	for _, pattern := range rootManifest.Workspaces {
		matches, err := filepath.Glob(filepath.Join(lockDir, filepath.FromSlash(pattern)))
		if err != nil {
			return nil, fmt.Errorf("expand workspace pattern %q: %w", pattern, err)
		}
		sort.Strings(matches)
		for _, match := range matches {
			manifestPath := match
			info, err := os.Stat(match)
			if err == nil && info.IsDir() {
				manifestPath = filepath.Join(match, "package.json")
			}

			manifest, exists, err := readNodeManifest(manifestPath)
			if err != nil {
				return nil, err
			}
			if !exists {
				continue
			}
			addImporter(filepath.Dir(manifestPath), manifest)
		}
	}

	return importers, nil
}

func readNodeManifest(path string) (nodePackageFile, bool, error) {
	payload, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nodePackageFile{}, false, nil
		}
		return nodePackageFile{}, false, fmt.Errorf("read package.json %s: %w", path, err)
	}

	var manifest nodePackageFile
	if err := json.Unmarshal(payload, &manifest); err != nil {
		return nodePackageFile{}, false, fmt.Errorf("parse package.json %s: %w", path, err)
	}
	return manifest, true, nil
}

func buildYarnImporterPackages(importer yarnImporter, document yarnLockDocument) []Package {
	categories := map[string]string{}
	seed := func(name string, ref string, category string) {
		key, ok := yarnResolvedPackageKey(document, name, ref)
		if !ok {
			return
		}
		assignPnpmCategory(categories, key, category)
	}

	for name, ref := range importer.Dependencies {
		category := "dependency"
		if _, ok := importer.PeerDependencies[name]; ok {
			category = "peerDependency"
		}
		seed(name, ref, category)
	}
	for name, ref := range importer.OptionalDependencies {
		category := "dependency"
		if _, ok := importer.PeerDependencies[name]; ok {
			category = "peerDependency"
		}
		seed(name, ref, category)
	}
	for name, ref := range importer.DevDependencies {
		category := "devDependency"
		if _, ok := importer.PeerDependencies[name]; ok {
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

		pkg, ok := document.Packages[key]
		if !ok {
			continue
		}

		for name, ref := range pkg.Dependencies {
			childKey, ok := yarnResolvedPackageKey(document, name, ref)
			if !ok {
				continue
			}
			if assignPnpmCategory(categories, childKey, categories[key]) {
				queue = append(queue, childKey)
			}
		}
		for name, ref := range pkg.OptionalDependencies {
			childKey, ok := yarnResolvedPackageKey(document, name, ref)
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
		pkg, ok := document.Packages[key]
		if !ok {
			continue
		}
		packages = append(packages, Package{
			Ecosystem:      "node",
			Project:        importer.Project,
			Name:           pkg.Name,
			Version:        pkg.Version,
			PURL:           mustNodePURL(pkg.Name, pkg.Version),
			DependencyType: categories[key],
		})
	}
	return packages
}

func yarnResolvedPackageKey(document yarnLockDocument, name string, ref string) (string, bool) {
	for _, candidate := range yarnDescriptorCandidates(name, ref) {
		if key, ok := document.Descriptors[candidate]; ok {
			return key, true
		}
	}

	version := yarnResolvedVersion(ref)
	if version == "" {
		return "", false
	}

	key := yarnPackageKey(name, version)
	_, ok := document.Packages[key]
	return key, ok
}

func yarnDescriptorCandidates(name string, ref string) []string {
	name = strings.TrimSpace(name)
	ref = strings.TrimSpace(ref)
	if name == "" || ref == "" {
		return nil
	}

	for _, prefix := range []string{"workspace:", "link:", "file:", "portal:"} {
		if strings.HasPrefix(ref, prefix) {
			return nil
		}
	}

	candidates := []string{name + "@" + ref}
	if strings.HasPrefix(ref, "npm:") {
		candidates = append(candidates, name+"@"+strings.TrimPrefix(ref, "npm:"))
	} else {
		candidates = append(candidates, name+"@npm:"+ref)
	}

	version := yarnResolvedVersion(ref)
	if version != "" {
		candidates = append(candidates, yarnPackageKey(name, version))
	}
	return uniqueYarnStrings(candidates)
}

func yarnResolvedVersion(ref string) string {
	value := strings.TrimSpace(ref)
	if value == "" {
		return ""
	}
	if strings.HasPrefix(value, "npm:") {
		value = strings.TrimPrefix(value, "npm:")
	}
	if strings.HasPrefix(value, "workspace:") ||
		strings.HasPrefix(value, "link:") ||
		strings.HasPrefix(value, "file:") ||
		strings.HasPrefix(value, "portal:") {
		return ""
	}
	if strings.ContainsAny(value, "^~*<>| ") {
		return ""
	}
	return sanitizeVersion(value)
}

func splitYarnDescriptor(selector string) (string, string, bool) {
	value := yarnNormalizeDescriptor(selector)
	index := strings.LastIndex(value, "@")
	if index <= 0 || index == len(value)-1 {
		return "", "", false
	}
	return value[:index], value[index+1:], true
}

func yarnNormalizeDescriptor(value string) string {
	return strings.TrimSpace(yarnUnquote(value))
}

func yarnPackageKey(name string, version string) string {
	return strings.TrimSpace(name) + "@" + strings.TrimSpace(version)
}

func uniqueYarnStrings(values []string) []string {
	seen := map[string]struct{}{}
	result := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	return result
}

func cloneStringMap(source map[string]string) map[string]string {
	if len(source) == 0 {
		return nil
	}
	cloned := make(map[string]string, len(source))
	for key, value := range source {
		cloned[key] = value
	}
	return cloned
}

func nearestYarnLockfile(path string, root string) string {
	current := filepath.Dir(path)
	root = filepath.Clean(root)
	for {
		candidate := filepath.Join(current, "yarn.lock")
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
