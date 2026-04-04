package scan

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"depaudit-license/internal/inventory"
	"depaudit-license/internal/purl"
)

type Config struct {
	Root string
}

type Package struct {
	Ecosystem           string `json:"ecosystem"`
	Project             string `json:"project"`
	Name                string `json:"name"`
	Version             string `json:"version"`
	PURL                string `json:"purl,omitempty"`
	DependencyType      string `json:"dependencyType"`
	HasRuntimeAssets    bool   `json:"hasRuntimeAssets,omitempty"`
	RawLicense          string `json:"rawLicense"`
	LicenseKey          string `json:"licenseKey"`
	Repository          string `json:"repository,omitempty"`
	Homepage            string `json:"homepage,omitempty"`
	CopyrightHolder     string `json:"copyrightHolder,omitempty"`
	CopyrightYear       int    `json:"copyrightYear,omitempty"`
	MetadataSource      string `json:"metadataSource,omitempty"`
	EmbeddedLicensePath string `json:"embeddedLicensePath,omitempty"`
	EmbeddedLicenseText string `json:"embeddedLicenseText,omitempty"`
}

type metadata struct {
	RawLicense          string
	Repository          string
	Homepage            string
	Holder              string
	Year                int
	Source              string
	EmbeddedLicensePath string
	EmbeddedLicenseText string
}

type nodePackageFile struct {
	Name             string            `json:"name"`
	Dependencies     map[string]string `json:"dependencies"`
	DevDependencies  map[string]string `json:"devDependencies"`
	PeerDependencies map[string]string `json:"peerDependencies"`
}

type npmVersionPayload struct {
	Author       json.RawMessage   `json:"author"`
	Maintainers  []json.RawMessage `json:"maintainers"`
	Contributors []json.RawMessage `json:"contributors"`
	License      json.RawMessage   `json:"license"`
	Homepage     string            `json:"homepage"`
	Repository   json.RawMessage   `json:"repository"`
}

type installedNodePackage struct {
	Version string `json:"version"`
	npmVersionPayload
}

type projectFile struct {
	ItemGroups []struct {
		PackageReferences []struct {
			Include        string `xml:"Include,attr"`
			Version        string `xml:"Version,attr"`
			VersionElement string `xml:"Version"`
		} `xml:"PackageReference"`
	} `xml:"ItemGroup"`
}

type nodeResolver struct {
	client          *http.Client
	cache           map[string]metadata
	registryBaseURL string
}

func Collect(cfg Config) ([]Package, error) {
	var packages []Package

	err := filepath.WalkDir(cfg.Root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}

		if entry.IsDir() {
			switch entry.Name() {
			case ".git", "node_modules", "bin", "obj":
				if path != cfg.Root {
					return filepath.SkipDir
				}
			}
			return nil
		}

		switch filepath.Base(path) {
		case "pnpm-lock.yaml":
			resolved, err := collectPnpmPackages(path)
			if err != nil {
				return err
			}
			packages = append(packages, resolved...)
		case "package.json":
			if nearestPnpmLockfile(path, cfg.Root) != "" {
				return nil
			}
			resolved, err := collectNodePackages(path)
			if err != nil {
				return err
			}
			packages = append(packages, resolved...)
		default:
			if strings.HasSuffix(path, ".csproj") {
				resolved, err := collectDotNetPackages(path)
				if err != nil {
					return err
				}
				packages = append(packages, resolved...)
			}
		}

		return nil
	})
	if err != nil {
		return nil, err
	}

	sort.Slice(packages, func(i, j int) bool {
		left := packages[i]
		right := packages[j]
		return strings.Join([]string{left.Ecosystem, left.Project, left.Name, left.Version}, "\x00") <
			strings.Join([]string{right.Ecosystem, right.Project, right.Name, right.Version}, "\x00")
	})

	return packages, nil
}

func collectNodePackages(path string) ([]Package, error) {
	payload, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read package.json %s: %w", path, err)
	}

	var file nodePackageFile
	if err := json.Unmarshal(payload, &file); err != nil {
		return nil, fmt.Errorf("parse package.json %s: %w", path, err)
	}

	project := filepath.Base(filepath.Dir(path))
	if file.Name != "" {
		project = file.Name
	}

	var result []Package
	result = append(result, buildNodePackages(project, file.Dependencies, "dependency")...)
	result = append(result, buildNodePackages(project, file.DevDependencies, "devDependency")...)
	result = append(result, buildNodePackages(project, file.PeerDependencies, "peerDependency")...)
	return result, nil
}

func buildNodePackages(project string, deps map[string]string, depType string) []Package {
	if len(deps) == 0 {
		return nil
	}

	names := make([]string, 0, len(deps))
	for name := range deps {
		names = append(names, name)
	}
	sort.Strings(names)

	result := make([]Package, 0, len(names))
	for _, name := range names {
		result = append(result, Package{
			Ecosystem:      "node",
			Project:        project,
			Name:           name,
			Version:        sanitizeVersion(deps[name]),
			PURL:           mustPURL(Package{Ecosystem: "node", Name: name, Version: sanitizeVersion(deps[name])}),
			DependencyType: depType,
		})
	}

	return result
}

func collectDotNetPackages(path string) ([]Package, error) {
	assetsPath := filepath.Join(filepath.Dir(path), "obj", "project.assets.json")
	if _, err := os.Stat(assetsPath); err == nil {
		document, err := readNugetAssets(assetsPath)
		if err != nil {
			return nil, err
		}
		return buildDotNetPackagesFromAssets(document), nil
	}

	return collectDotNetPackagesFromProject(path)
}

func collectDotNetPackagesFromProject(path string) ([]Package, error) {
	payload, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read csproj %s: %w", path, err)
	}

	var file projectFile
	decoder := xml.NewDecoder(bytes.NewReader(payload))
	if err := decoder.Decode(&file); err != nil {
		return nil, fmt.Errorf("parse csproj %s: %w", path, err)
	}

	project := strings.TrimSuffix(filepath.Base(path), filepath.Ext(path))
	var packages []Package

	for _, group := range file.ItemGroups {
		for _, ref := range group.PackageReferences {
			if strings.TrimSpace(ref.Include) == "" {
				continue
			}

			version := strings.TrimSpace(ref.Version)
			if version == "" {
				version = strings.TrimSpace(ref.VersionElement)
			}

			packages = append(packages, Package{
				Ecosystem:        "dotnet",
				Project:          project,
				Name:             ref.Include,
				Version:          version,
				PURL:             mustPURL(Package{Ecosystem: "dotnet", Name: ref.Include, Version: version}),
				DependencyType:   "dependency",
				HasRuntimeAssets: true,
			})
		}
	}

	sort.Slice(packages, func(i, j int) bool {
		return packages[i].Name < packages[j].Name
	})

	return packages, nil
}

func buildDotNetPackagesFromAssets(document nugetAssetsDocument) []Package {
	packages := make([]Package, 0, len(document.Packages))
	for _, resolved := range document.Packages {
		dependencyType := "transitiveDependency"
		if resolved.IsDirect {
			dependencyType = "dependency"
		}

		packages = append(packages, Package{
			Ecosystem:        "dotnet",
			Project:          document.ProjectName,
			Name:             resolved.PackageID,
			Version:          resolved.Version,
			PURL:             mustPURL(Package{Ecosystem: "dotnet", Name: resolved.PackageID, Version: resolved.Version}),
			DependencyType:   dependencyType,
			HasRuntimeAssets: resolved.HasRuntimeAssets,
		})
	}
	return packages
}

func (r *nodeResolver) resolveFromInstalledPackage(packageName string, version string, projectDir string) (metadata, bool) {
	packageJSON := installedNodePackageJSONPath(projectDir, packageName)
	if strings.TrimSpace(packageJSON) == "" {
		return metadata{}, false
	}

	payload, err := os.ReadFile(packageJSON)
	if err != nil {
		return metadata{}, false
	}

	var file installedNodePackage
	if err := json.Unmarshal(payload, &file); err != nil {
		return metadata{}, false
	}

	if isExactNodeVersion(version) && strings.TrimSpace(file.Version) != strings.TrimSpace(version) {
		return metadata{}, false
	}

	meta := metadata{
		RawLicense: parseLicense(file.License),
		Repository: parseRepository(file.Repository),
		Homepage:   strings.TrimSpace(file.Homepage),
		Holder: firstNonEmpty(
			parsePerson(file.Author),
			firstNonEmpty(parsePeople(file.Maintainers)...),
			firstNonEmpty(parsePeople(file.Contributors)...),
			packageName,
		),
		Year:   now().Year(),
		Source: "node-modules",
	}
	if strings.TrimSpace(meta.RawLicense) == "" {
		meta.RawLicense = "Unknown"
	}
	return meta, true
}

func installedNodePackageJSONPath(projectDir string, packageName string) string {
	if strings.TrimSpace(projectDir) == "" {
		return ""
	}

	segments := append([]string{projectDir, "node_modules"}, strings.Split(packageName, "/")...)
	segments = append(segments, "package.json")
	return filepath.Join(segments...)
}

func makeNodePackageKey(packageName string, version string) string {
	value := strings.TrimSpace(packageName)
	if strings.TrimSpace(version) == "" {
		return value
	}
	return value + "@" + strings.TrimSpace(version)
}

func isExactNodeVersion(version string) bool {
	value := strings.TrimSpace(version)
	if value == "" {
		return false
	}
	if strings.HasPrefix(value, "workspace:") ||
		strings.HasPrefix(value, "link:") ||
		strings.HasPrefix(value, "file:") {
		return false
	}
	if strings.ContainsAny(value, "^~*<>| ") {
		return false
	}
	return true
}

func parsePerson(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}

	var asString string
	if err := json.Unmarshal(raw, &asString); err == nil {
		return cleanPerson(asString)
	}

	var asObject struct {
		Name string `json:"name"`
	}
	if err := json.Unmarshal(raw, &asObject); err == nil {
		return strings.TrimSpace(asObject.Name)
	}

	return ""
}

func parsePeople(rawList []json.RawMessage) []string {
	var people []string
	for _, raw := range rawList {
		person := parsePerson(raw)
		if person != "" {
			people = append(people, person)
		}
	}
	return uniqueStrings(people)
}

func parseRepository(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}

	var asString string
	if err := json.Unmarshal(raw, &asString); err == nil {
		return strings.TrimSpace(strings.TrimPrefix(asString, "git+"))
	}

	var asObject struct {
		URL string `json:"url"`
	}
	if err := json.Unmarshal(raw, &asObject); err == nil {
		return strings.TrimSpace(strings.TrimPrefix(asObject.URL, "git+"))
	}

	return ""
}

func parseLicense(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}

	var asString string
	if err := json.Unmarshal(raw, &asString); err == nil {
		return strings.TrimSpace(asString)
	}

	var asObject struct {
		Type string `json:"type"`
	}
	if err := json.Unmarshal(raw, &asObject); err == nil {
		return strings.TrimSpace(asObject.Type)
	}

	return ""
}

func cleanPerson(value string) string {
	value = strings.TrimSpace(value)
	if index := strings.Index(value, "<"); index >= 0 {
		value = value[:index]
	}
	return strings.TrimSpace(value)
}

func firstCSVValue(value string) string {
	separators := []string{",", ";"}
	parts := []string{value}
	for _, separator := range separators {
		if strings.Contains(value, separator) {
			parts = strings.Split(value, separator)
			break
		}
	}
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part != "" {
			return part
		}
	}
	return ""
}

func uniqueStrings(values []string) []string {
	seen := map[string]struct{}{}
	result := make([]string, 0, len(values))
	for _, value := range values {
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

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func mustPURL(pkg Package) string {
	value, _ := purl.FromPackage(inventory.Package{
		Ecosystem: pkg.Ecosystem,
		Name:      pkg.Name,
		Version:   pkg.Version,
		PURL:      pkg.PURL,
	})
	return value
}
