package scan

import (
	"net/http"
	"path/filepath"
	"slices"
	"strings"

	"depaudit-license/internal/catalog"
	"depaudit-license/internal/inventory"
)

const MetadataEnrichmentSourceKind = "metadata-enrichment"

type MetadataLookupConfig struct {
	Client                   *http.Client
	Catalog                  *catalog.Catalog
	RepositoryRoots          []string
	NodeRegistryBaseURL      string
	NuGetGlobalPackagesRoot  string
	NuGetRegistrationBaseURL string
}

type MetadataLookupService struct {
	catalog         *catalog.Catalog
	repositoryRoots []string
	node            *nodeResolver
	nuget           *nugetResolver
}

func NewMetadataLookupService(cfg MetadataLookupConfig) *MetadataLookupService {
	return &MetadataLookupService{
		catalog:         cfg.Catalog,
		repositoryRoots: normalizeRoots(cfg.RepositoryRoots),
		node: &nodeResolver{
			client:          cfg.Client,
			cache:           map[string]metadata{},
			registryBaseURL: cfg.NodeRegistryBaseURL,
		},
		nuget: &nugetResolver{
			client:              cfg.Client,
			cache:               map[string]metadata{},
			globalPackagesRoot:  cfg.NuGetGlobalPackagesRoot,
			registrationBaseURL: cfg.NuGetRegistrationBaseURL,
		},
	}
}

func (s *MetadataLookupService) EnrichPackage(pkg inventory.Package) (inventory.Package, *inventory.Source, bool) {
	meta, ok := s.lookupMetadata(pkg)
	if !ok {
		return pkg, nil, false
	}

	source := inventory.Source{
		ID:       "enrich:" + strings.TrimSpace(meta.Source),
		Kind:     MetadataEnrichmentSourceKind,
		Location: strings.TrimSpace(meta.Source),
	}
	enriched, changed, sourceChanged := applyMetadata(pkg, meta, s.catalog, source.ID)
	if !changed {
		return pkg, nil, false
	}
	if !sourceChanged {
		return enriched, nil, true
	}
	return enriched, &source, true
}

func (s *MetadataLookupService) lookupMetadata(pkg inventory.Package) (metadata, bool) {
	switch strings.ToLower(strings.TrimSpace(pkg.Ecosystem)) {
	case "node":
		for _, projectDir := range s.nodeProjectDirs(pkg) {
			if meta, ok := s.node.resolveFromInstalledPackage(pkg.Name, pkg.Version, projectDir); ok {
				return meta, true
			}
		}
		meta := s.node.resolve(pkg.Name, pkg.Version, "")
		return meta, strings.TrimSpace(meta.Source) != "" && meta.Source != "fallback"
	case "dotnet":
		meta := s.nuget.resolve(pkg.Name, pkg.Version)
		return meta, strings.TrimSpace(meta.Source) != "" && meta.Source != "fallback"
	default:
		return metadata{}, false
	}
}

func (s *MetadataLookupService) nodeProjectDirs(pkg inventory.Package) []string {
	dirs := make([]string, 0, len(s.repositoryRoots)*2)
	project := strings.TrimSpace(pkg.Project)
	for _, root := range s.repositoryRoots {
		if project != "" {
			dirs = append(dirs, filepath.Join(root, project))
		}
		dirs = append(dirs, root)
	}
	return uniqueNonEmpty(dirs)
}

func applyMetadata(pkg inventory.Package, meta metadata, cat *catalog.Catalog, sourceID string) (inventory.Package, bool, bool) {
	changed := false
	sourceChanged := false
	if pkg.Provenance.FieldOrigins == nil {
		pkg.Provenance.FieldOrigins = map[string]string{}
	}

	if isMissingLicense(pkg.RawLicense) && strings.TrimSpace(meta.RawLicense) != "" && meta.RawLicense != "Unknown" {
		pkg.RawLicense = strings.TrimSpace(meta.RawLicense)
		pkg.Provenance.FieldOrigins["rawLicense"] = sourceID
		changed = true
		sourceChanged = true
	}
	if isMissingLicenseKey(pkg.LicenseKey, cat) {
		if key := resolveLicenseKeyFromMetadata(pkg, meta, cat); key != "" {
			pkg.LicenseKey = key
			pkg.Provenance.FieldOrigins["licenseKey"] = sourceID
			changed = true
			sourceChanged = true
		}
	}
	if strings.TrimSpace(pkg.Repository) == "" && strings.TrimSpace(meta.Repository) != "" {
		pkg.Repository = strings.TrimSpace(meta.Repository)
		pkg.Provenance.FieldOrigins["repository"] = sourceID
		changed = true
		sourceChanged = true
	}
	if strings.TrimSpace(pkg.Homepage) == "" && strings.TrimSpace(meta.Homepage) != "" {
		pkg.Homepage = strings.TrimSpace(meta.Homepage)
		pkg.Provenance.FieldOrigins["homepage"] = sourceID
		changed = true
		sourceChanged = true
	}
	if strings.TrimSpace(pkg.CopyrightHolder) == "" && strings.TrimSpace(meta.Holder) != "" {
		pkg.CopyrightHolder = strings.TrimSpace(meta.Holder)
		pkg.Provenance.FieldOrigins["copyrightHolder"] = sourceID
		changed = true
		sourceChanged = true
	}
	if pkg.CopyrightYear == 0 && meta.Year != 0 {
		pkg.CopyrightYear = meta.Year
		pkg.Provenance.FieldOrigins["copyrightYear"] = sourceID
		changed = true
		sourceChanged = true
	}
	if strings.TrimSpace(pkg.EmbeddedLicensePath) == "" && strings.TrimSpace(meta.EmbeddedLicensePath) != "" {
		pkg.EmbeddedLicensePath = strings.TrimSpace(meta.EmbeddedLicensePath)
		pkg.Provenance.FieldOrigins["embeddedLicensePath"] = sourceID
		changed = true
		sourceChanged = true
	}
	if strings.TrimSpace(pkg.EmbeddedLicenseText) == "" && strings.TrimSpace(meta.EmbeddedLicenseText) != "" {
		pkg.EmbeddedLicenseText = strings.TrimSpace(meta.EmbeddedLicenseText)
		pkg.Provenance.FieldOrigins["embeddedLicenseText"] = sourceID
		changed = true
		sourceChanged = true
	}
	if pkg.Provenance.ArtifactResolution == nil && meta.ArtifactResolution != nil {
		resolution := *meta.ArtifactResolution
		pkg.Provenance.ArtifactResolution = &resolution
		changed = true
	}
	if sourceChanged {
		switch current := strings.TrimSpace(pkg.MetadataSource); {
		case current == "":
			pkg.MetadataSource = strings.TrimSpace(meta.Source)
		case current != strings.TrimSpace(meta.Source):
			pkg.MetadataSource = "merged"
		}
		pkg.Provenance.FieldOrigins["metadataSource"] = sourceID
		pkg.Provenance.SourceIDs = uniqueNonEmpty(append(pkg.Provenance.SourceIDs, sourceID))
	}
	return pkg, changed, sourceChanged
}

func resolveLicenseKeyFromMetadata(pkg inventory.Package, meta metadata, cat *catalog.Catalog) string {
	if cat == nil {
		return ""
	}

	embeddedText := firstNonEmpty(pkg.EmbeddedLicenseText, meta.EmbeddedLicenseText)
	rawLicense := strings.TrimSpace(pkg.RawLicense)
	if rawLicense != "" {
		key, _ := cat.Normalize(rawLicense)
		if strings.TrimSpace(key) != "" && key != cat.Fallback {
			return key
		}
		if strings.TrimSpace(embeddedText) != "" {
			if textKey, _ := cat.NormalizeText(embeddedText); strings.TrimSpace(textKey) != "" && textKey != cat.Fallback {
				return textKey
			}
		}
		return strings.TrimSpace(key)
	}

	if strings.TrimSpace(embeddedText) == "" {
		return ""
	}
	key, _ := cat.NormalizeText(embeddedText)
	return strings.TrimSpace(key)
}

func isMissingLicense(value string) bool {
	normalized := strings.TrimSpace(value)
	return normalized == "" || strings.EqualFold(normalized, "unknown")
}

func isMissingLicenseKey(value string, cat *catalog.Catalog) bool {
	normalized := strings.TrimSpace(value)
	if normalized == "" {
		return true
	}
	return cat != nil && normalized == cat.Fallback
}

func normalizeRoots(values []string) []string {
	result := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value != "" {
			result = append(result, value)
		}
	}
	return uniqueNonEmpty(result)
}

func uniqueNonEmpty(values []string) []string {
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
	slices.Sort(result)
	return result
}
