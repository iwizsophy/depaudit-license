package sbom

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"depaudit-license/internal/catalog"
	"depaudit-license/internal/inventory"
	"depaudit-license/internal/purl"
)

type spdxDocument struct {
	Name                    string                 `json:"name"`
	DocumentDescribes       []string               `json:"documentDescribes"`
	Packages                []spdxPackage          `json:"packages"`
	Relationships           []spdxRelationship     `json:"relationships"`
	ExtractedLicensingInfos []spdxExtractedLicense `json:"hasExtractedLicensingInfos"`
}

type spdxPackage struct {
	SPDXID               string            `json:"SPDXID"`
	Name                 string            `json:"name"`
	VersionInfo          string            `json:"versionInfo"`
	LicenseConcluded     string            `json:"licenseConcluded"`
	LicenseDeclared      string            `json:"licenseDeclared"`
	LicenseInfoFromFiles []string          `json:"licenseInfoFromFiles"`
	CopyrightText        string            `json:"copyrightText"`
	Homepage             string            `json:"homepage"`
	ExternalRefs         []spdxExternalRef `json:"externalRefs"`
}

type spdxExternalRef struct {
	ReferenceCategory string `json:"referenceCategory"`
	ReferenceType     string `json:"referenceType"`
	ReferenceLocator  string `json:"referenceLocator"`
}

type spdxRelationship struct {
	SPDXElementID    string `json:"spdxElementId"`
	RelationshipType string `json:"relationshipType"`
	RelatedElementID string `json:"relatedSpdxElement"`
}

type spdxExtractedLicense struct {
	LicenseID     string `json:"licenseId"`
	Name          string `json:"name"`
	ExtractedText string `json:"extractedText"`
}

func LoadSPDXJSON(path string, cat *catalog.Catalog) ([]inventory.Package, error) {
	payload, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read SPDX JSON %s: %w", path, err)
	}

	var document spdxDocument
	if err := json.Unmarshal(payload, &document); err != nil {
		return nil, fmt.Errorf("parse SPDX JSON %s: %w", path, err)
	}
	if len(document.Packages) == 0 {
		return nil, fmt.Errorf("SPDX JSON %s does not contain packages", filepath.Base(path))
	}

	project := resolveSPDXProject(document, path)
	graph := buildSPDXGraph(document)
	extracted := make(map[string]spdxExtractedLicense, len(document.ExtractedLicensingInfos))
	for _, item := range document.ExtractedLicensingInfos {
		if strings.TrimSpace(item.LicenseID) != "" {
			extracted[strings.TrimSpace(item.LicenseID)] = item
		}
	}

	described := make(map[string]struct{}, len(document.DocumentDescribes))
	for _, id := range document.DocumentDescribes {
		id = strings.TrimSpace(id)
		if id != "" {
			described[id] = struct{}{}
		}
	}

	packages := make([]inventory.Package, 0, len(document.Packages))
	for _, pkg := range document.Packages {
		if _, ok := described[strings.TrimSpace(pkg.SPDXID)]; ok {
			continue
		}

		rawLicense, embeddedPath, embeddedText := resolveSPDXLicense(pkg, extracted)
		licenseKey := normalizeCycloneDXLicenseKey(rawLicense, cat)
		repository, purl := resolveSPDXRepositoryAndPURL(pkg.ExternalRefs)
		holder, year := parseCycloneDXCopyright(pkg.CopyrightText)
		packageURL := canonicalSPDXPURL(pkg, purl)
		packages = append(packages, inventory.Package{
			Ecosystem:           resolveSPDZEcosystem(purl),
			Project:             project,
			Name:                strings.TrimSpace(pkg.Name),
			Version:             strings.TrimSpace(pkg.VersionInfo),
			PURL:                packageURL,
			DependencyType:      classifySPDXDependency(strings.TrimSpace(pkg.SPDXID), graph),
			RawLicense:          rawLicense,
			LicenseKey:          licenseKey,
			Repository:          repository,
			Homepage:            strings.TrimSpace(pkg.Homepage),
			CopyrightHolder:     holder,
			CopyrightYear:       year,
			MetadataSource:      "spdx-json",
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

type spdxGraph struct {
	hasGraph bool
	direct   map[string]struct{}
}

func buildSPDXGraph(document spdxDocument) spdxGraph {
	if len(document.Relationships) == 0 {
		return spdxGraph{direct: map[string]struct{}{}}
	}

	edges := map[string][]string{}
	dependedUpon := map[string]struct{}{}
	for _, relation := range document.Relationships {
		from, to, ok := normalizeSPDXRelationship(relation)
		if !ok {
			continue
		}
		edges[from] = append(edges[from], to)
		dependedUpon[to] = struct{}{}
	}

	direct := map[string]struct{}{}
	roots := append([]string(nil), document.DocumentDescribes...)
	if len(roots) == 0 {
		for _, pkg := range document.Packages {
			if _, ok := dependedUpon[strings.TrimSpace(pkg.SPDXID)]; ok {
				continue
			}
			roots = append(roots, strings.TrimSpace(pkg.SPDXID))
		}
	}

	for _, root := range roots {
		for _, child := range edges[strings.TrimSpace(root)] {
			child = strings.TrimSpace(child)
			if child != "" {
				direct[child] = struct{}{}
			}
		}
	}
	return spdxGraph{hasGraph: true, direct: direct}
}

func normalizeSPDXRelationship(relation spdxRelationship) (string, string, bool) {
	left := strings.TrimSpace(relation.SPDXElementID)
	right := strings.TrimSpace(relation.RelatedElementID)
	switch strings.TrimSpace(relation.RelationshipType) {
	case "DEPENDS_ON":
		if left == "" || right == "" {
			return "", "", false
		}
		return left, right, true
	case "DEPENDENCY_OF":
		if left == "" || right == "" {
			return "", "", false
		}
		return right, left, true
	default:
		return "", "", false
	}
}

func classifySPDXDependency(id string, graph spdxGraph) string {
	if !graph.hasGraph {
		return "dependency"
	}
	if _, ok := graph.direct[id]; ok {
		return "dependency"
	}
	return "transitiveDependency"
}

func resolveSPDXProject(document spdxDocument, path string) string {
	if len(document.DocumentDescribes) > 0 {
		described := strings.TrimSpace(document.DocumentDescribes[0])
		for _, pkg := range document.Packages {
			if strings.TrimSpace(pkg.SPDXID) == described && strings.TrimSpace(pkg.Name) != "" {
				return strings.TrimSpace(pkg.Name)
			}
		}
	}
	if strings.TrimSpace(document.Name) != "" {
		return strings.TrimSpace(document.Name)
	}
	base := filepath.Base(path)
	return strings.TrimSuffix(base, filepath.Ext(base))
}

func resolveSPDXLicense(pkg spdxPackage, extracted map[string]spdxExtractedLicense) (string, string, string) {
	for _, candidate := range []string{
		cleanSPDXLicenseField(pkg.LicenseConcluded),
		cleanSPDXLicenseField(pkg.LicenseDeclared),
	} {
		if candidate == "" {
			continue
		}
		if item, ok := extracted[candidate]; ok && strings.TrimSpace(item.ExtractedText) != "" {
			return candidate, "spdx:" + candidate, strings.TrimSpace(item.ExtractedText)
		}
		return candidate, "", ""
	}

	values := make([]string, 0, len(pkg.LicenseInfoFromFiles))
	for _, value := range pkg.LicenseInfoFromFiles {
		candidate := cleanSPDXLicenseField(value)
		if candidate == "" {
			continue
		}
		values = append(values, candidate)
		if item, ok := extracted[candidate]; ok && strings.TrimSpace(item.ExtractedText) != "" {
			return candidate, "spdx:" + candidate, strings.TrimSpace(item.ExtractedText)
		}
	}
	if len(values) == 0 {
		return "Unknown", "", ""
	}
	return strings.Join(uniqueStrings(values), " OR "), "", ""
}

func cleanSPDXLicenseField(value string) string {
	value = strings.TrimSpace(value)
	switch value {
	case "", "NOASSERTION", "NONE":
		return ""
	default:
		return value
	}
}

func resolveSPDXRepositoryAndPURL(refs []spdxExternalRef) (string, string) {
	var repository string
	var purl string
	for _, ref := range refs {
		category := strings.ToUpper(strings.TrimSpace(ref.ReferenceCategory))
		refType := strings.TrimSpace(ref.ReferenceType)
		locator := strings.TrimSpace(ref.ReferenceLocator)
		if locator == "" {
			continue
		}
		if strings.EqualFold(refType, "purl") {
			purl = locator
		}
		if category == "SECURITY" || category == "OTHER" {
			continue
		}
		if strings.Contains(strings.ToLower(refType), "vcs") && repository == "" {
			repository = locator
		}
	}
	return repository, purl
}

func resolveSPDZEcosystem(purl string) string {
	switch kind := purlType(purl); kind {
	case "npm":
		return "node"
	case "nuget":
		return "dotnet"
	case "":
		return "generic"
	default:
		return kind
	}
}

func canonicalSPDXPURL(pkg spdxPackage, raw string) string {
	if normalized, ok := purl.Normalize(raw); ok {
		return normalized
	}
	value, _ := purl.FromPackage(inventory.Package{
		Ecosystem: resolveSPDZEcosystem(raw),
		Name:      strings.TrimSpace(pkg.Name),
		Version:   strings.TrimSpace(pkg.VersionInfo),
	})
	return value
}
