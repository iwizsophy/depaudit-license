package vuln

import (
	"fmt"
	"sort"
	"strings"

	"depaudit-license/internal/inventory"
	"depaudit-license/internal/purl"
)

const InputSchemaVersion = "1"

type AssessmentInput struct {
	SchemaVersion string       `json:"schemaVersion"`
	Packages      []PackageRef `json:"packages"`
	Sources       []SourceRef  `json:"sources,omitempty"`
}

type SourceRef struct {
	ID       string `json:"id"`
	Kind     string `json:"kind"`
	Location string `json:"location"`
}

type PackageRef struct {
	Key                string                        `json:"key"`
	PURL               string                        `json:"purl,omitempty"`
	Ecosystem          string                        `json:"ecosystem,omitempty"`
	Name               string                        `json:"name"`
	Version            string                        `json:"version,omitempty"`
	Aliases            []string                      `json:"aliases,omitempty"`
	SourceIDs          []string                      `json:"sourceIds,omitempty"`
	FieldOrigins       map[string]string             `json:"fieldOrigins,omitempty"`
	ConflictFields     []string                      `json:"conflictFields,omitempty"`
	ArtifactResolution *inventory.ArtifactResolution `json:"artifactResolution,omitempty"`
}

func BuildAssessmentInput(doc inventory.Document) (AssessmentInput, error) {
	input := AssessmentInput{
		SchemaVersion: InputSchemaVersion,
		Sources:       make([]SourceRef, 0, len(doc.Sources)),
		Packages:      make([]PackageRef, 0, len(doc.Packages)),
	}

	for _, source := range doc.Sources {
		input.Sources = append(input.Sources, SourceRef{
			ID:       strings.TrimSpace(source.ID),
			Kind:     strings.TrimSpace(source.Kind),
			Location: sourceLocationForDisplay(source),
		})
	}

	for _, pkg := range doc.Packages {
		ref, err := buildPackageRef(pkg)
		if err != nil {
			return AssessmentInput{}, err
		}
		input.Packages = append(input.Packages, ref)
	}

	sort.Slice(input.Sources, func(i, j int) bool {
		return input.Sources[i].ID < input.Sources[j].ID
	})
	sort.Slice(input.Packages, func(i, j int) bool {
		return input.Packages[i].Key < input.Packages[j].Key
	})
	return input, nil
}

func buildPackageRef(pkg inventory.Package) (PackageRef, error) {
	name := strings.TrimSpace(pkg.Name)
	if name == "" {
		return PackageRef{}, fmt.Errorf("vulnerability input requires package name")
	}

	packageURL, _ := purl.FromPackage(pkg)
	key := purl.CanonicalKey(pkg)
	ref := PackageRef{
		Key:                key,
		PURL:               packageURL,
		Ecosystem:          strings.TrimSpace(pkg.Ecosystem),
		Name:               name,
		Version:            strings.TrimSpace(pkg.Version),
		Aliases:            aliasesForPackage(pkg, packageURL),
		SourceIDs:          cloneStrings(pkg.Provenance.SourceIDs),
		FieldOrigins:       cloneMap(pkg.Provenance.FieldOrigins),
		ConflictFields:     cloneStrings(pkg.Provenance.ConflictFields),
		ArtifactResolution: cloneArtifactResolution(pkg.Provenance.ArtifactResolution),
	}
	return ref, nil
}

func aliasesForPackage(pkg inventory.Package, packageURL string) []string {
	values := []string{
		strings.TrimSpace(pkg.Name),
		strings.TrimSpace(pkg.Ecosystem) + ":" + strings.TrimSpace(pkg.Name),
	}
	if strings.TrimSpace(pkg.Version) != "" {
		values = append(values, strings.TrimSpace(pkg.Name)+"@"+strings.TrimSpace(pkg.Version))
	}
	if packageURL != "" {
		values = append(values, packageURL)
	}
	return uniqueSorted(values)
}

func cloneStrings(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	result := append([]string(nil), values...)
	sort.Strings(result)
	return result
}

func cloneMap(values map[string]string) map[string]string {
	if len(values) == 0 {
		return nil
	}
	result := make(map[string]string, len(values))
	for key, value := range values {
		result[key] = strings.TrimSpace(value)
	}
	return result
}

func cloneArtifactResolution(value *inventory.ArtifactResolution) *inventory.ArtifactResolution {
	if value == nil {
		return nil
	}
	cloned := *value
	return &cloned
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

func sourceLocationForDisplay(source inventory.Source) string {
	if strings.TrimSpace(source.DisplayLocation) != "" {
		return strings.TrimSpace(source.DisplayLocation)
	}
	return strings.TrimSpace(source.Location)
}
