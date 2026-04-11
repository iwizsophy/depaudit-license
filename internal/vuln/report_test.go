package vuln

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"depaudit-license/internal/externalaccess"
	"depaudit-license/internal/inventory"
)

func setTestNow(t *testing.T, instant time.Time) {
	t.Helper()
	previous := now
	now = func() time.Time { return instant }
	t.Cleanup(func() {
		now = previous
	})
}

func TestBuildChecklistSummarizesAssessment(t *testing.T) {
	t.Parallel()
	setTestNow(t, time.Date(2026, time.April, 4, 12, 0, 0, 0, time.UTC))

	input := AssessmentInput{
		SchemaVersion: InputSchemaVersion,
		Sources: []SourceRef{
			{ID: "repo-scan", Kind: "repository-scan"},
		},
	}
	checklist := BuildChecklist(input, PipelineResult{
		Mode: ModeOSVOnly,
		Stages: []PipelineStage{{
			Name:   "osv",
			Status: StageStatusSucceeded,
		}},
		Output: AssessmentOutput{Packages: []PackageFinding{
			{
				Package: PackageRef{
					Key:       "pkg:npm/react@19.2.4",
					Name:      "react",
					Version:   "19.2.4",
					Ecosystem: "node",
					PURL:      "pkg:npm/react@19.2.4",
				},
				Query: QueryRef{Method: "purl"},
				Advisories: []AdvisoryRef{
					{ID: "GHSA-react-1", Severity: "high", Summary: "Critical rendering bug"},
					{ID: "GHSA-react-2"},
				},
			},
			{
				Package:       PackageRef{Key: "pkg:generic/custom-lib@1.0.0", Name: "custom-lib", Ecosystem: "generic"},
				SkippedReason: "unsupported-ecosystem",
			},
		}},
	})

	if checklist.TotalPackages != 2 {
		t.Fatalf("total packages = %d", checklist.TotalPackages)
	}
	if checklist.GeneratedAt != "2026-04-04T12:00:00Z" {
		t.Fatalf("generated at = %q", checklist.GeneratedAt)
	}
	if checklist.PackagesWithFinds != 1 {
		t.Fatalf("packages with findings = %d", checklist.PackagesWithFinds)
	}
	if checklist.SkippedPackages != 1 {
		t.Fatalf("skipped packages = %d", checklist.SkippedPackages)
	}
	if checklist.TotalAdvisories != 2 {
		t.Fatalf("total advisories = %d", checklist.TotalAdvisories)
	}
	if checklist.PackageFindings[0].Severity != "high" {
		t.Fatalf("severity = %q", checklist.PackageFindings[0].Severity)
	}
	if checklist.Mode != ModeOSVOnly {
		t.Fatalf("mode = %q", checklist.Mode)
	}

	output := BuildChecklistOutput(input, checklist, []externalaccess.Service{
		{ID: "osv", Purpose: "vulnerability", BaseURL: "https://api.osv.dev", CacheMode: "use", CacheTTL: "24h0m0s"},
	})
	if output.SchemaVersion != JSONChecklistSchemaVersion {
		t.Fatalf("schema version = %q", output.SchemaVersion)
	}
	if output.Provenance.InputSchemaVersion != InputSchemaVersion {
		t.Fatalf("input schema version = %q", output.Provenance.InputSchemaVersion)
	}
	if len(output.Provenance.ExternalSources) != 1 || output.Provenance.ExternalSources[0].ID != "osv" {
		t.Fatalf("external sources = %#v", output.Provenance.ExternalSources)
	}
}

func TestRenderChecklistHTMLUsesTemplate(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	templatePath := filepath.Join(dir, "vuln.html.tmpl")
	cssPath := filepath.Join(dir, "vuln.css")
	if err := os.WriteFile(templatePath, []byte(`<!doctype html><style>{{.ThemeCSS}}</style><h1>{{.TotalAdvisories}}</h1><div>{{(index .PackageFindings 0).Name}}</div><div>{{(index (index .PackageFindings 0).Advisories 0).Summary}}</div><div>{{formatCVSSScore (index (index .PackageFindings 0).Advisories 0).CVSSScore}}</div><div>{{(index (index (index .PackageFindings 0).Advisories 0).VendorComments 0).Comment}}</div>`), 0o644); err != nil {
		t.Fatalf("write template: %v", err)
	}
	if err := os.WriteFile(cssPath, []byte(`body{color:red;}`), 0o644); err != nil {
		t.Fatalf("write css: %v", err)
	}

	checklist := Checklist{
		TotalAdvisories: 2,
		PackageFindings: []PackageFindingView{{
			Name: "react",
			Advisories: []AdvisoryRef{{
				ID:        "GHSA-react-1",
				Summary:   "Important advisory",
				CVSSScore: func() *float64 { value := 7.6; return &value }(),
				VendorComments: []VendorCommentRef{{
					Organization: "vendor-a",
					Comment:      "Patched in 1.2.3",
				}},
			}},
		}},
	}
	rendered, err := RenderChecklistHTML(checklist, templatePath, cssPath)
	if err != nil {
		t.Fatalf("render html: %v", err)
	}
	if !strings.Contains(string(rendered), "react") || !strings.Contains(string(rendered), "color:red") || !strings.Contains(string(rendered), "Important advisory") || !strings.Contains(string(rendered), "7.6") || !strings.Contains(string(rendered), "Patched in 1.2.3") {
		t.Fatalf("unexpected rendered html: %s", string(rendered))
	}
}

func TestRenderChecklistHTMLHandlesTemplateFailures(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	templatePath := filepath.Join(dir, "vuln.html.tmpl")
	cssPath := filepath.Join(dir, "vuln.css")
	if err := os.WriteFile(cssPath, []byte(`body{color:red;}`), 0o644); err != nil {
		t.Fatalf("write css: %v", err)
	}

	if err := os.WriteFile(templatePath, []byte(`{{if`), 0o644); err != nil {
		t.Fatalf("write invalid template: %v", err)
	}
	if _, err := RenderChecklistHTML(Checklist{}, templatePath, cssPath); err == nil {
		t.Fatal("expected template parse error")
	}

	if err := os.WriteFile(templatePath, []byte(`{{index .PackageFindings 0}}`), 0o644); err != nil {
		t.Fatalf("write runtime-failing template: %v", err)
	}
	if _, err := RenderChecklistHTML(Checklist{}, templatePath, cssPath); err == nil {
		t.Fatal("expected template render error")
	}
}

func TestBuildChecklistOutputJSONRoundTrips(t *testing.T) {
	t.Parallel()

	output := BuildChecklistOutput(AssessmentInput{SchemaVersion: InputSchemaVersion}, Checklist{
		PackageFindings: []PackageFindingView{{Name: "react"}},
	}, nil)
	data, err := json.Marshal(output)
	if err != nil {
		t.Fatalf("marshal output: %v", err)
	}
	if !strings.Contains(string(data), `"schemaVersion":"1"`) {
		t.Fatalf("unexpected json: %s", string(data))
	}
}

func TestBuildChecklistSortsSourcesAndFindingsBySeverity(t *testing.T) {
	t.Parallel()

	checklist := BuildChecklist(AssessmentInput{
		SchemaVersion: InputSchemaVersion,
		Sources: []SourceRef{
			{ID: "b", Kind: "repository-scan"},
			{ID: "a", Kind: "cyclonedx-json"},
			{ID: "dup", Kind: "repository-scan"},
		},
	}, PipelineResult{
		Mode: "full",
		Stages: []PipelineStage{
			{Name: "github-advisory", Status: StageStatusSucceeded},
			{Name: "osv", Status: StageStatusSucceeded},
			{Name: "osv", Status: StageStatusSucceeded},
		},
		Output: AssessmentOutput{Packages: []PackageFinding{
			{
				Package:    PackageRef{Key: "pkg:npm/a@1.0.0", Name: "a", Ecosystem: "node", Version: "1.0.0"},
				Advisories: []AdvisoryRef{{ID: "GHSA-a", Severity: "low"}},
			},
			{
				Package:    PackageRef{Key: "pkg:npm/b@1.0.0", Name: "b", Ecosystem: "node", Version: "1.0.0"},
				Advisories: []AdvisoryRef{{ID: "GHSA-b", Severity: "critical"}},
			},
			{
				Package: PackageRef{Key: "pkg:npm/c@1.0.0", Name: "c", Ecosystem: "node", Version: "1.0.0"},
			},
		}},
	})

	if got := checklist.Sources; !slices.Equal(got, []string{"cyclonedx-json", "github-advisory", "osv", "repository-scan"}) {
		t.Fatalf("sources = %#v", got)
	}
	if got := []string{checklist.PackageFindings[0].Name, checklist.PackageFindings[1].Name, checklist.PackageFindings[2].Name}; !slices.Equal(got, []string{"b", "a", "c"}) {
		t.Fatalf("finding order = %#v", got)
	}
	if checklist.SeveritySummary[0].Count != 1 || checklist.SeveritySummary[3].Count != 1 || checklist.SeveritySummary[5].Count != 1 {
		t.Fatalf("severity summary = %#v", checklist.SeveritySummary)
	}
}

func TestBuildChecklistPreservesPackageProvenanceInOutput(t *testing.T) {
	t.Parallel()

	input := AssessmentInput{
		SchemaVersion: InputSchemaVersion,
		Sources: []SourceRef{
			{ID: "repo-scan", Kind: "repository-scan"},
			{ID: "sbom", Kind: "cyclonedx-json"},
		},
	}
	checklist := BuildChecklist(input, PipelineResult{
		Mode: ModeOSVGitHub,
		Stages: []PipelineStage{
			{Name: "osv", Status: StageStatusSucceeded},
			{Name: "github-advisory", Status: StageStatusSucceeded},
		},
		Output: AssessmentOutput{Packages: []PackageFinding{
			{
				Package: PackageRef{
					Key:            "pkg:npm/react@19.2.4",
					Name:           "react",
					Version:        "19.2.4",
					Ecosystem:      "node",
					PURL:           "pkg:npm/react@19.2.4",
					Aliases:        []string{"node:react", "react", "react@19.2.4"},
					SourceIDs:      []string{"repo-scan", "sbom"},
					FieldOrigins:   map[string]string{"repository": "repo-scan", "licenseKey": "sbom"},
					ConflictFields: []string{"repository"},
					ArtifactResolution: &inventory.ArtifactResolution{
						Kind:           "remote-metadata",
						Detail:         "npm-registry-version",
						ReviewRequired: true,
						ReviewReason:   "local-package-manager-artifact-not-available",
					},
				},
				Query: QueryRef{Method: "purl"},
				Advisories: []AdvisoryRef{
					{ID: "GHSA-react-1", Severity: "high", Summary: "Supplemental advisory"},
				},
			},
		}},
	})

	if len(checklist.PackageFindings) != 1 {
		t.Fatalf("package findings = %#v", checklist.PackageFindings)
	}
	finding := checklist.PackageFindings[0]
	if finding.QueryMethod != "purl" {
		t.Fatalf("query method = %q", finding.QueryMethod)
	}
	if !slices.Equal(finding.Aliases, []string{"node:react", "react", "react@19.2.4"}) {
		t.Fatalf("aliases = %#v", finding.Aliases)
	}
	if !slices.Equal(finding.SourceIDs, []string{"repo-scan", "sbom"}) {
		t.Fatalf("source ids = %#v", finding.SourceIDs)
	}
	if finding.FieldOrigins["repository"] != "repo-scan" || finding.FieldOrigins["licenseKey"] != "sbom" {
		t.Fatalf("field origins = %#v", finding.FieldOrigins)
	}
	if !slices.Equal(finding.ConflictFields, []string{"repository"}) {
		t.Fatalf("conflict fields = %#v", finding.ConflictFields)
	}
	if finding.ArtifactResolution == nil || finding.ArtifactResolution.Kind != "remote-metadata" || !finding.ArtifactResolution.ReviewRequired {
		t.Fatalf("artifact resolution = %#v", finding.ArtifactResolution)
	}

	output := BuildChecklistOutput(input, checklist, []externalaccess.Service{
		{ID: "github-advisory", Purpose: "vulnerability", BaseURL: "https://api.github.com", AuthConfigured: true, CacheMode: "use", CacheTTL: "24h0m0s"},
		{ID: "osv", Purpose: "vulnerability", BaseURL: "https://api.osv.dev", CacheMode: "use", CacheTTL: "24h0m0s"},
	})
	if !slices.Equal(output.Provenance.Sources, checklist.Sources) {
		t.Fatalf("output provenance sources = %#v", output.Provenance.Sources)
	}
	if len(output.Provenance.ExternalSources) != 2 || output.Provenance.ExternalSources[0].ID != "github-advisory" {
		t.Fatalf("external sources = %#v", output.Provenance.ExternalSources)
	}
}
