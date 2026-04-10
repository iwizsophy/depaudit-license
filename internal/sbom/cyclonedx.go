package sbom

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"depaudit-license/internal/catalog"
	"depaudit-license/internal/inventory"
	"depaudit-license/internal/purl"
)

type cycloneDXDocument struct {
	Metadata struct {
		Component *cycloneDXComponent `json:"component"`
	} `json:"metadata"`
	Components   []cycloneDXComponent  `json:"components"`
	Dependencies []cycloneDXDependency `json:"dependencies"`
}

type cycloneDXDependency struct {
	Ref       string   `json:"ref"`
	DependsOn []string `json:"dependsOn"`
}

type cycloneDXComponent struct {
	BOMRef             string                   `json:"bom-ref"`
	Type               string                   `json:"type"`
	Group              string                   `json:"group"`
	Name               string                   `json:"name"`
	Version            string                   `json:"version"`
	Scope              string                   `json:"scope"`
	PURL               string                   `json:"purl"`
	Copyright          string                   `json:"copyright"`
	Licenses           []cycloneDXLicenseChoice `json:"licenses"`
	ExternalReferences []cycloneDXExternalRef   `json:"externalReferences"`
	Evidence           cycloneDXEvidence        `json:"evidence"`
}

type cycloneDXEvidence struct {
	Licenses []cycloneDXLicenseChoice `json:"licenses"`
}

type cycloneDXLicenseChoice struct {
	Expression string            `json:"expression"`
	License    *cycloneDXLicense `json:"license"`
}

type cycloneDXLicense struct {
	ID   string              `json:"id"`
	Name string              `json:"name"`
	URL  string              `json:"url"`
	Text *cycloneDXTextBlock `json:"text"`
}

type cycloneDXTextBlock struct {
	Content     string `json:"content"`
	ContentType string `json:"contentType"`
	Encoding    string `json:"encoding"`
}

type cycloneDXExternalRef struct {
	Type string `json:"type"`
	URL  string `json:"url"`
}

func LoadCycloneDXJSON(path string, cat *catalog.Catalog) ([]inventory.Package, error) {
	payload, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read CycloneDX JSON %s: %w", path, err)
	}

	var document cycloneDXDocument
	if err := json.Unmarshal(payload, &document); err != nil {
		return nil, fmt.Errorf("parse CycloneDX JSON %s: %w", path, err)
	}
	if len(document.Components) == 0 {
		return nil, fmt.Errorf("CycloneDX JSON %s does not contain components", filepath.Base(path))
	}

	project := resolveCycloneDXProject(document, path)
	rootRef := ""
	if document.Metadata.Component != nil {
		rootRef = componentRef(*document.Metadata.Component)
	}
	graph := buildCycloneDXGraph(document, rootRef)

	packages := make([]inventory.Package, 0, len(document.Components))
	for _, component := range document.Components {
		ref := componentRef(component)
		if rootRef != "" && ref == rootRef {
			continue
		}

		rawLicense, embeddedPath, embeddedText := resolveCycloneDXLicense(component)
		licenseKey := normalizeCycloneDXLicenseKey(rawLicense, embeddedText, cat)
		repository, homepage := resolveCycloneDXURLs(component.ExternalReferences)
		holder, year := parseCycloneDXCopyright(component.Copyright)
		packageURL := canonicalCycloneDXPURL(component)
		packages = append(packages, inventory.Package{
			Ecosystem:           resolveCycloneDXEcosystem(component),
			Project:             project,
			Name:                componentDisplayName(component),
			Version:             strings.TrimSpace(component.Version),
			PURL:                packageURL,
			DependencyType:      classifyCycloneDXDependency(component.Scope, ref, graph),
			RawLicense:          rawLicense,
			LicenseKey:          licenseKey,
			Repository:          repository,
			Homepage:            homepage,
			CopyrightHolder:     holder,
			CopyrightYear:       year,
			MetadataSource:      "cyclonedx-json",
			EmbeddedLicensePath: embeddedPath,
			EmbeddedLicenseText: embeddedText,
		})
	}

	sort.Slice(packages, func(i, j int) bool {
		left := packages[i]
		right := packages[j]
		return strings.Join([]string{left.Ecosystem, left.Project, left.Name, left.Version}, "\x00") <
			strings.Join([]string{right.Ecosystem, right.Project, right.Name, right.Version}, "\x00")
	})
	return packages, nil
}

type cycloneDXGraph struct {
	hasGraph bool
	direct   map[string]struct{}
}

func buildCycloneDXGraph(document cycloneDXDocument, rootRef string) cycloneDXGraph {
	if len(document.Dependencies) == 0 {
		return cycloneDXGraph{direct: map[string]struct{}{}}
	}

	dependsOn := map[string][]string{}
	dependedUpon := map[string]struct{}{}
	for _, entry := range document.Dependencies {
		ref := strings.TrimSpace(entry.Ref)
		if ref == "" {
			continue
		}
		dependsOn[ref] = append([]string(nil), entry.DependsOn...)
		for _, child := range entry.DependsOn {
			child = strings.TrimSpace(child)
			if child != "" {
				dependedUpon[child] = struct{}{}
			}
		}
	}

	direct := map[string]struct{}{}
	if strings.TrimSpace(rootRef) != "" {
		for _, child := range dependsOn[rootRef] {
			child = strings.TrimSpace(child)
			if child != "" {
				direct[child] = struct{}{}
			}
		}
		return cycloneDXGraph{hasGraph: true, direct: direct}
	}

	for ref, children := range dependsOn {
		if _, ok := dependedUpon[ref]; ok {
			continue
		}
		for _, child := range children {
			child = strings.TrimSpace(child)
			if child != "" {
				direct[child] = struct{}{}
			}
		}
	}
	return cycloneDXGraph{hasGraph: true, direct: direct}
}

func classifyCycloneDXDependency(scope string, ref string, graph cycloneDXGraph) string {
	isDirect := !graph.hasGraph
	if graph.hasGraph {
		_, isDirect = graph.direct[ref]
	}

	switch strings.ToLower(strings.TrimSpace(scope)) {
	case "excluded", "optional":
		if isDirect {
			return "devDependency"
		}
		return "devTransitiveDependency"
	default:
		if isDirect {
			return "dependency"
		}
		return "transitiveDependency"
	}
}

func resolveCycloneDXProject(document cycloneDXDocument, path string) string {
	if document.Metadata.Component != nil {
		name := componentDisplayName(*document.Metadata.Component)
		if strings.TrimSpace(name) != "" {
			return name
		}
	}
	base := filepath.Base(path)
	return strings.TrimSuffix(base, filepath.Ext(base))
}

func componentDisplayName(component cycloneDXComponent) string {
	group := strings.TrimSpace(component.Group)
	name := strings.TrimSpace(component.Name)
	if group == "" {
		return name
	}
	if purlType(component.PURL) == "npm" {
		if strings.HasPrefix(group, "@") {
			return group + "/" + name
		}
		return "@" + group + "/" + name
	}
	return group + "/" + name
}

func componentRef(component cycloneDXComponent) string {
	for _, candidate := range []string{component.BOMRef, component.PURL, componentDisplayName(component)} {
		if strings.TrimSpace(candidate) != "" {
			return strings.TrimSpace(candidate)
		}
	}
	return ""
}

func resolveCycloneDXLicense(component cycloneDXComponent) (string, string, string) {
	for _, source := range [][]cycloneDXLicenseChoice{component.Licenses, component.Evidence.Licenses} {
		raw, embeddedPath, embeddedText := selectCycloneDXLicense(source, componentRef(component))
		if strings.TrimSpace(raw) != "" {
			return raw, embeddedPath, embeddedText
		}
	}
	return "Unknown", "", ""
}

func selectCycloneDXLicense(choices []cycloneDXLicenseChoice, componentRef string) (string, string, string) {
	var names []string
	for index, choice := range choices {
		if expression := strings.TrimSpace(choice.Expression); expression != "" {
			return expression, "", ""
		}
		if choice.License == nil {
			continue
		}
		if id := strings.TrimSpace(choice.License.ID); id != "" {
			embeddedText := decodeCycloneDXText(choice.License.Text)
			return id, buildCycloneDXLicensePath(componentRef, index), embeddedText
		}
		if name := strings.TrimSpace(choice.License.Name); name != "" {
			names = append(names, name)
			if embeddedText := decodeCycloneDXText(choice.License.Text); embeddedText != "" {
				return name, buildCycloneDXLicensePath(componentRef, index), embeddedText
			}
		}
	}
	if len(names) == 0 {
		return "", "", ""
	}
	return strings.Join(uniqueStrings(names), " OR "), "", ""
}

func buildCycloneDXLicensePath(componentRef string, index int) string {
	if strings.TrimSpace(componentRef) == "" {
		return ""
	}
	return fmt.Sprintf("cyclonedx:%s:license[%d]", componentRef, index)
}

func decodeCycloneDXText(text *cycloneDXTextBlock) string {
	if text == nil {
		return ""
	}
	content := strings.TrimSpace(text.Content)
	if content == "" {
		return ""
	}
	if strings.EqualFold(strings.TrimSpace(text.Encoding), "base64") {
		decoded, err := base64.StdEncoding.DecodeString(content)
		if err != nil {
			return ""
		}
		return string(decoded)
	}
	return content
}

func resolveCycloneDXURLs(refs []cycloneDXExternalRef) (string, string) {
	var repository string
	var homepage string
	for _, ref := range refs {
		urlValue := strings.TrimSpace(ref.URL)
		if urlValue == "" {
			continue
		}
		switch strings.ToLower(strings.TrimSpace(ref.Type)) {
		case "vcs":
			if repository == "" {
				repository = urlValue
			}
		case "website", "documentation":
			if homepage == "" {
				homepage = urlValue
			}
		}
	}
	return repository, homepage
}

func parseCycloneDXCopyright(raw string) (string, int) {
	value := strings.TrimSpace(raw)
	if value == "" {
		return "", 0
	}
	fields := strings.Fields(value)
	for index, field := range fields {
		trimmed := strings.Trim(field, "(),.")
		if len(trimmed) != 4 {
			continue
		}
		year, err := strconv.Atoi(trimmed)
		if err != nil {
			continue
		}
		holder := strings.TrimSpace(strings.Join(fields[index+1:], " "))
		holder = strings.TrimPrefix(holder, "(c)")
		holder = strings.TrimPrefix(holder, "©")
		holder = strings.TrimSpace(holder)
		return holder, year
	}
	return value, 0
}

func resolveCycloneDXEcosystem(component cycloneDXComponent) string {
	switch kind := purlType(component.PURL); kind {
	case "npm":
		return "node"
	case "nuget":
		return "dotnet"
	case "":
		value := strings.TrimSpace(component.Type)
		if value == "" {
			return "generic"
		}
		return value
	default:
		return kind
	}
}

func purlType(value string) string {
	raw := strings.TrimSpace(value)
	if !strings.HasPrefix(raw, "pkg:") {
		return ""
	}
	raw = strings.TrimPrefix(raw, "pkg:")
	for _, separator := range []string{"/", "@", "?"} {
		if index := strings.Index(raw, separator); index >= 0 {
			raw = raw[:index]
			break
		}
	}
	return strings.ToLower(strings.TrimSpace(raw))
}

func uniqueStrings(values []string) []string {
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

func normalizeCycloneDXLicenseKey(raw string, embeddedText string, cat *catalog.Catalog) string {
	if cat == nil {
		return ""
	}
	if isCompoundLicenseExpression(raw) {
		return cat.Fallback
	}
	key, _ := cat.Normalize(raw)
	if strings.TrimSpace(key) != "" && key != cat.Fallback {
		return key
	}
	if strings.TrimSpace(embeddedText) != "" {
		if textKey, _ := cat.NormalizeText(embeddedText); strings.TrimSpace(textKey) != "" && textKey != cat.Fallback {
			return textKey
		}
	}
	return key
}

func canonicalCycloneDXPURL(component cycloneDXComponent) string {
	if normalized, ok := purl.Normalize(component.PURL); ok {
		return normalized
	}
	value, _ := purl.FromPackage(inventory.Package{
		Ecosystem: resolveCycloneDXEcosystem(component),
		Name:      componentDisplayName(component),
		Version:   strings.TrimSpace(component.Version),
	})
	return value
}

func isCompoundLicenseExpression(raw string) bool {
	value := strings.ToLower(strings.TrimSpace(raw))
	return strings.Contains(value, " or ") || strings.Contains(value, " and ")
}
