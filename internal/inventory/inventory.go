package inventory

// Document is the canonical inventory model shared between importers, merge
// engines, and report rendering.
type Document struct {
	Sources     []Source     `json:"sources,omitempty"`
	Packages    []Package    `json:"packages"`
	Conflicts   []Conflict   `json:"conflicts,omitempty"`
	Diagnostics []Diagnostic `json:"diagnostics,omitempty"`
}

type Source struct {
	ID              string `json:"id"`
	Kind            string `json:"kind"`
	Location        string `json:"location"`
	DisplayLocation string `json:"displayLocation,omitempty"`
}

type Conflict struct {
	Identity string          `json:"identity"`
	Field    string          `json:"field"`
	Values   []ConflictValue `json:"values"`
}

type ConflictValue struct {
	SourceID string `json:"sourceId"`
	Value    string `json:"value"`
}

type Diagnostic struct {
	SourceID          string   `json:"sourceId,omitempty"`
	RuleID            string   `json:"ruleId,omitempty"`
	Code              string   `json:"code"`
	Severity          string   `json:"severity"`
	Message           string   `json:"message"`
	Path              string   `json:"path,omitempty"`
	Ecosystem         string   `json:"ecosystem,omitempty"`
	Project           string   `json:"project,omitempty"`
	ProjectPath       string   `json:"projectPath,omitempty"`
	MatchedRoots      []string `json:"matchedRoots,omitempty"`
	RemovedPackages   []string `json:"removedPackages,omitempty"`
	PreservedPackages []string `json:"preservedPackages,omitempty"`
}

// Package is the canonical report input model shared by repository scanners and
// future SBOM importers.
type Package struct {
	Provenance          PackageProvenance `json:"provenance,omitempty"`
	Ecosystem           string            `json:"ecosystem"`
	Project             string            `json:"project"`
	Name                string            `json:"name"`
	Version             string            `json:"version"`
	PURL                string            `json:"purl,omitempty"`
	DependencyType      string            `json:"dependencyType"`
	HasRuntimeAssets    bool              `json:"hasRuntimeAssets,omitempty"`
	RawLicense          string            `json:"rawLicense"`
	LicenseKey          string            `json:"licenseKey"`
	Repository          string            `json:"repository,omitempty"`
	Homepage            string            `json:"homepage,omitempty"`
	CopyrightHolder     string            `json:"copyrightHolder,omitempty"`
	CopyrightYear       int               `json:"copyrightYear,omitempty"`
	MetadataSource      string            `json:"metadataSource,omitempty"`
	EmbeddedLicensePath string            `json:"embeddedLicensePath,omitempty"`
	EmbeddedLicenseText string            `json:"embeddedLicenseText,omitempty"`
}

type PackageProvenance struct {
	SourceIDs      []string          `json:"sourceIds,omitempty"`
	FieldOrigins   map[string]string `json:"fieldOrigins,omitempty"`
	ConflictFields []string          `json:"conflictFields,omitempty"`
}
