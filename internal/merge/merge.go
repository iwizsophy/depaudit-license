package merge

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"depaudit-license/internal/inventory"
	"depaudit-license/internal/purl"
)

type Config struct{}

func Documents(cfg Config, docs ...inventory.Document) inventory.Document {
	result := inventory.Document{
		Sources:  make([]inventory.Source, 0),
		Packages: make([]inventory.Package, 0),
	}
	primaryIndex := map[string]int{}
	secondaryIndex := map[string][]int{}

	for _, doc := range docs {
		result.Sources = append(result.Sources, doc.Sources...)
		for _, pkg := range doc.Packages {
			if idx, ok := findMergeTarget(pkg, result.Packages, primaryIndex, secondaryIndex); ok {
				merged, conflicts := mergePackage(result.Packages[idx], pkg)
				result.Packages[idx] = merged
				result.Conflicts = append(result.Conflicts, conflicts...)
				continue
			}

			pkg = normalizePackage(pkg)
			result.Packages = append(result.Packages, pkg)
			index := len(result.Packages) - 1
			primaryIndex[primaryKey(pkg)] = index
			secondary := secondaryKey(pkg)
			secondaryIndex[secondary] = append(secondaryIndex[secondary], index)
		}
	}

	sort.Slice(result.Sources, func(i, j int) bool {
		return result.Sources[i].ID < result.Sources[j].ID
	})
	sort.Slice(result.Packages, func(i, j int) bool {
		left := result.Packages[i]
		right := result.Packages[j]
		return strings.Join([]string{left.Ecosystem, left.Project, left.Name, left.Version}, "\x00") <
			strings.Join([]string{right.Ecosystem, right.Project, right.Name, right.Version}, "\x00")
	})
	sort.Slice(result.Conflicts, func(i, j int) bool {
		left := strings.Join([]string{result.Conflicts[i].Identity, result.Conflicts[i].Field}, "\x00")
		right := strings.Join([]string{result.Conflicts[j].Identity, result.Conflicts[j].Field}, "\x00")
		return left < right
	})
	return result
}

func findMergeTarget(pkg inventory.Package, existing []inventory.Package, primary map[string]int, secondary map[string][]int) (int, bool) {
	if idx, ok := primary[primaryKey(pkg)]; ok {
		return idx, true
	}
	if key := purl.CanonicalKey(pkg); key != "" {
		for idx, candidate := range existing {
			if purl.CanonicalKey(candidate) == key {
				return idx, true
			}
		}
	}
	candidates := secondary[secondaryKey(pkg)]
	if len(candidates) == 1 {
		return candidates[0], true
	}
	return 0, false
}

func mergePackage(base inventory.Package, incoming inventory.Package) (inventory.Package, []inventory.Conflict) {
	base = normalizePackage(base)
	incoming = normalizePackage(incoming)

	merged := base
	merged.Provenance.SourceIDs = uniqueSorted(append(append([]string(nil), base.Provenance.SourceIDs...), incoming.Provenance.SourceIDs...))
	merged.Provenance.FieldOrigins = cloneFieldOrigins(base.Provenance.FieldOrigins)
	merged.Provenance.ConflictFields = uniqueSorted(append([]string(nil), base.Provenance.ConflictFields...))

	var conflicts []inventory.Conflict
	conflicts = append(conflicts, mergeStringField(primaryKey(base), "project", &merged.Project, &merged.Provenance, base.Project, incoming.Project, base, incoming)...)
	conflicts = append(conflicts, mergeStringField(primaryKey(base), "purl", &merged.PURL, &merged.Provenance, base.PURL, incoming.PURL, base, incoming)...)
	conflicts = append(conflicts, mergeStringField(primaryKey(base), "dependencyType", &merged.DependencyType, &merged.Provenance, base.DependencyType, incoming.DependencyType, base, incoming)...)
	conflicts = append(conflicts, mergeStringField(primaryKey(base), "rawLicense", &merged.RawLicense, &merged.Provenance, base.RawLicense, incoming.RawLicense, base, incoming)...)
	conflicts = append(conflicts, mergeStringField(primaryKey(base), "licenseKey", &merged.LicenseKey, &merged.Provenance, base.LicenseKey, incoming.LicenseKey, base, incoming)...)
	conflicts = append(conflicts, mergeStringField(primaryKey(base), "repository", &merged.Repository, &merged.Provenance, base.Repository, incoming.Repository, base, incoming)...)
	conflicts = append(conflicts, mergeStringField(primaryKey(base), "homepage", &merged.Homepage, &merged.Provenance, base.Homepage, incoming.Homepage, base, incoming)...)
	conflicts = append(conflicts, mergeStringField(primaryKey(base), "copyrightHolder", &merged.CopyrightHolder, &merged.Provenance, base.CopyrightHolder, incoming.CopyrightHolder, base, incoming)...)
	conflicts = append(conflicts, mergeStringField(primaryKey(base), "embeddedLicensePath", &merged.EmbeddedLicensePath, &merged.Provenance, base.EmbeddedLicensePath, incoming.EmbeddedLicensePath, base, incoming)...)
	conflicts = append(conflicts, mergeStringField(primaryKey(base), "embeddedLicenseText", &merged.EmbeddedLicenseText, &merged.Provenance, base.EmbeddedLicenseText, incoming.EmbeddedLicenseText, base, incoming)...)

	if merged.CopyrightYear == 0 && incoming.CopyrightYear != 0 {
		merged.CopyrightYear = incoming.CopyrightYear
		setFieldOrigin(&merged.Provenance, "copyrightYear", firstSource(incoming.Provenance.SourceIDs))
	} else if base.CopyrightYear != 0 && incoming.CopyrightYear != 0 && base.CopyrightYear != incoming.CopyrightYear {
		merged.Provenance.ConflictFields = uniqueSorted(append(merged.Provenance.ConflictFields, "copyrightYear"))
		conflicts = append(conflicts, inventory.Conflict{
			Identity: primaryKey(base),
			Field:    "copyrightYear",
			Values: []inventory.ConflictValue{
				{SourceID: firstSource(base.Provenance.SourceIDs), Value: strconv.Itoa(base.CopyrightYear)},
				{SourceID: firstSource(incoming.Provenance.SourceIDs), Value: strconv.Itoa(incoming.CopyrightYear)},
			},
		})
	}

	merged.HasRuntimeAssets = base.HasRuntimeAssets || incoming.HasRuntimeAssets
	merged.MetadataSource = mergeMetadataSource(base.MetadataSource, incoming.MetadataSource)
	return merged, conflicts
}

func mergeStringField(identity string, field string, target *string, provenance *inventory.PackageProvenance, base string, incoming string, basePkg inventory.Package, incomingPkg inventory.Package) []inventory.Conflict {
	base = strings.TrimSpace(base)
	incoming = strings.TrimSpace(incoming)
	switch {
	case base == "" && incoming != "":
		*target = incoming
		setFieldOrigin(provenance, field, firstSource(incomingPkg.Provenance.SourceIDs))
		return nil
	case base != "" && incoming == "":
		return nil
	case base == incoming:
		if provenance.FieldOrigins[field] == "" {
			setFieldOrigin(provenance, field, firstSource(basePkg.Provenance.SourceIDs))
		}
		return nil
	case base == "" && incoming == "":
		return nil
	default:
		provenance.ConflictFields = uniqueSorted(append(provenance.ConflictFields, field))
		return []inventory.Conflict{{
			Identity: identity,
			Field:    field,
			Values: []inventory.ConflictValue{
				{SourceID: firstSource(basePkg.Provenance.SourceIDs), Value: base},
				{SourceID: firstSource(incomingPkg.Provenance.SourceIDs), Value: incoming},
			},
		}}
	}
}

func normalizePackage(pkg inventory.Package) inventory.Package {
	pkg.Provenance.SourceIDs = uniqueSorted(pkg.Provenance.SourceIDs)
	pkg.Provenance.ConflictFields = uniqueSorted(pkg.Provenance.ConflictFields)
	pkg.Provenance.FieldOrigins = cloneFieldOrigins(pkg.Provenance.FieldOrigins)
	pkg.Ecosystem = strings.TrimSpace(pkg.Ecosystem)
	pkg.Project = strings.TrimSpace(pkg.Project)
	pkg.Name = strings.TrimSpace(pkg.Name)
	pkg.Version = strings.TrimSpace(pkg.Version)
	pkg.PURL = strings.TrimSpace(pkg.PURL)
	pkg.DependencyType = strings.TrimSpace(pkg.DependencyType)
	pkg.RawLicense = strings.TrimSpace(pkg.RawLicense)
	pkg.LicenseKey = strings.TrimSpace(pkg.LicenseKey)
	pkg.Repository = strings.TrimSpace(pkg.Repository)
	pkg.Homepage = strings.TrimSpace(pkg.Homepage)
	pkg.CopyrightHolder = strings.TrimSpace(pkg.CopyrightHolder)
	pkg.MetadataSource = strings.TrimSpace(pkg.MetadataSource)
	pkg.EmbeddedLicensePath = strings.TrimSpace(pkg.EmbeddedLicensePath)
	pkg.EmbeddedLicenseText = strings.TrimSpace(pkg.EmbeddedLicenseText)
	return pkg
}

func primaryKey(pkg inventory.Package) string {
	return strings.ToLower(strings.Join([]string{
		strings.TrimSpace(pkg.Ecosystem),
		strings.TrimSpace(pkg.Project),
		strings.TrimSpace(pkg.Name),
		strings.TrimSpace(pkg.Version),
	}, "\x00"))
}

func secondaryKey(pkg inventory.Package) string {
	return strings.ToLower(strings.Join([]string{
		strings.TrimSpace(pkg.Ecosystem),
		strings.TrimSpace(pkg.Name),
		strings.TrimSpace(pkg.Version),
	}, "\x00"))
}

func firstSource(values []string) string {
	if len(values) == 0 {
		return ""
	}
	return values[0]
}

func uniqueSorted(values []string) []string {
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
	sort.Strings(result)
	return result
}

func mergeMetadataSource(base string, incoming string) string {
	base = strings.TrimSpace(base)
	incoming = strings.TrimSpace(incoming)
	switch {
	case base == "":
		return incoming
	case incoming == "":
		return base
	case base == incoming:
		return base
	default:
		return "merged"
	}
}

func NewSource(id string, kind string, location string, displayLocation string) inventory.Source {
	return inventory.Source{
		ID:              strings.TrimSpace(id),
		Kind:            strings.TrimSpace(kind),
		Location:        strings.TrimSpace(location),
		DisplayLocation: strings.TrimSpace(displayLocation),
	}
}

func SingleSourceDocument(source inventory.Source, packages []inventory.Package) inventory.Document {
	doc := inventory.Document{
		Sources:  []inventory.Source{source},
		Packages: make([]inventory.Package, 0, len(packages)),
	}
	for _, pkg := range packages {
		pkg = normalizePackage(pkg)
		if len(pkg.Provenance.SourceIDs) == 0 && source.ID != "" {
			pkg.Provenance.SourceIDs = []string{source.ID}
		}
		ensureFieldOrigins(&pkg)
		if len(pkg.Provenance.FieldOrigins) == 0 && source.ID != "" {
			seedFieldOrigins(&pkg, source.ID)
		}
		doc.Packages = append(doc.Packages, pkg)
	}
	return doc
}

func ValidateDocument(doc inventory.Document) error {
	sourceIDs := map[string]struct{}{}
	for _, source := range doc.Sources {
		if source.ID == "" {
			return fmt.Errorf("inventory source id is empty")
		}
		if _, exists := sourceIDs[source.ID]; exists {
			return fmt.Errorf("duplicate inventory source id %q", source.ID)
		}
		sourceIDs[source.ID] = struct{}{}
	}
	for _, pkg := range doc.Packages {
		for _, sourceID := range pkg.Provenance.SourceIDs {
			if _, ok := sourceIDs[sourceID]; !ok {
				return fmt.Errorf("package %s references unknown source id %q", pkg.Name, sourceID)
			}
		}
	}
	return nil
}

func cloneFieldOrigins(input map[string]string) map[string]string {
	if len(input) == 0 {
		return nil
	}
	result := make(map[string]string, len(input))
	for key, value := range input {
		result[key] = strings.TrimSpace(value)
	}
	return result
}

func ensureFieldOrigins(pkg *inventory.Package) {
	if pkg.Provenance.FieldOrigins == nil {
		pkg.Provenance.FieldOrigins = map[string]string{}
	}
}

func seedFieldOrigins(pkg *inventory.Package, sourceID string) {
	for field, value := range map[string]string{
		"ecosystem":           pkg.Ecosystem,
		"project":             pkg.Project,
		"name":                pkg.Name,
		"version":             pkg.Version,
		"purl":                pkg.PURL,
		"dependencyType":      pkg.DependencyType,
		"rawLicense":          pkg.RawLicense,
		"licenseKey":          pkg.LicenseKey,
		"repository":          pkg.Repository,
		"homepage":            pkg.Homepage,
		"copyrightHolder":     pkg.CopyrightHolder,
		"metadataSource":      pkg.MetadataSource,
		"embeddedLicensePath": pkg.EmbeddedLicensePath,
		"embeddedLicenseText": pkg.EmbeddedLicenseText,
	} {
		if strings.TrimSpace(value) != "" {
			pkg.Provenance.FieldOrigins[field] = sourceID
		}
	}
	if pkg.CopyrightYear != 0 {
		pkg.Provenance.FieldOrigins["copyrightYear"] = sourceID
	}
}

func setFieldOrigin(prov *inventory.PackageProvenance, field string, sourceID string) {
	if strings.TrimSpace(sourceID) == "" {
		return
	}
	ensurePackageProvenance(prov)
	prov.FieldOrigins[field] = sourceID
}

func ensurePackageProvenance(prov *inventory.PackageProvenance) {
	if prov.FieldOrigins == nil {
		prov.FieldOrigins = map[string]string{}
	}
}
