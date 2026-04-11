package vuln

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestSeverityLabelAndCloneStringMap(t *testing.T) {
	t.Parallel()

	cases := map[string]string{
		"critical": "Critical",
		"high":     "High",
		"medium":   "Medium",
		"low":      "Low",
		"unknown":  "Unknown",
		"none":     "None",
		"other":    "None",
	}
	for input, want := range cases {
		if got := severityLabel(input); got != want {
			t.Fatalf("severityLabel(%q) = %q", input, got)
		}
	}

	if cloneStringMap(nil) != nil {
		t.Fatal("expected nil clone for nil map")
	}
	cloned := cloneStringMap(map[string]string{"a": "b"})
	if cloned["a"] != "b" {
		t.Fatalf("cloneStringMap = %#v", cloned)
	}
}

func TestPackageSeverityDefaultsToUnknownWhenAdvisorySeverityMissing(t *testing.T) {
	t.Parallel()

	if got := packageSeverity(PackageFinding{Advisories: []AdvisoryRef{{ID: "GHSA-1"}}}); got != "unknown" {
		t.Fatalf("packageSeverity = %q", got)
	}
}

func TestSeverityOrderAndPackageSeverityBranches(t *testing.T) {
	t.Parallel()

	if got := severityOrder("high"); got != "1" {
		t.Fatalf("severityOrder(high) = %q", got)
	}
	if got := severityOrder("something-else"); got != "6" {
		t.Fatalf("severityOrder(unknown) = %q", got)
	}
	if got := packageSeverity(PackageFinding{Advisories: []AdvisoryRef{
		{ID: "GHSA-1", Severity: "medium"},
		{ID: "GHSA-2", Severity: "critical"},
		{ID: "GHSA-3", Severity: "high"},
	}}); got != "critical" {
		t.Fatalf("packageSeverity best = %q", got)
	}
}

func TestVulnerabilityHelperBranches(t *testing.T) {
	t.Parallel()

	if got := normalizePipelineMode(" weird "); got != ModeDisabled {
		t.Fatalf("normalizePipelineMode invalid = %q", got)
	}
	if got := normalizeOSVEcosystem("go"); got != "Go" {
		t.Fatalf("normalizeOSVEcosystem go = %q", got)
	}
	if got := normalizeOSVEcosystem("ruby"); got != "" {
		t.Fatalf("normalizeOSVEcosystem unsupported = %q", got)
	}
	if got := normalizeGitHubAdvisoryEcosystem("go"); got != "go" {
		t.Fatalf("normalizeGitHubAdvisoryEcosystem go = %q", got)
	}
	if got := normalizeGitHubAdvisoryEcosystem("ruby"); got != "" {
		t.Fatalf("normalizeGitHubAdvisoryEcosystem unsupported = %q", got)
	}
	if got := formatCVSSScore(nil); got != "" {
		t.Fatalf("formatCVSSScore nil = %q", got)
	}
	score := 7.125
	if got := formatCVSSScore(&score); got != "7.125" {
		t.Fatalf("formatCVSSScore = %q", got)
	}
}

func TestRenderChecklistHTMLErrorBranches(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	missingCSS := filepath.Join(dir, "missing.css")
	templatePath := filepath.Join(dir, "broken.html.tmpl")
	if err := os.WriteFile(templatePath, []byte(`{{`), 0o644); err != nil {
		t.Fatalf("write template: %v", err)
	}
	if _, err := RenderChecklistHTML(Checklist{}, templatePath, missingCSS); err == nil {
		t.Fatal("expected CSS read error")
	}

	cssPath := filepath.Join(dir, "theme.css")
	if err := os.WriteFile(cssPath, []byte(`body{}`), 0o644); err != nil {
		t.Fatalf("write css: %v", err)
	}
	if _, err := RenderChecklistHTML(Checklist{}, templatePath, cssPath); err == nil {
		t.Fatal("expected parse error")
	}

	execTemplatePath := filepath.Join(dir, "execute.html.tmpl")
	if err := os.WriteFile(execTemplatePath, []byte(`{{.ThemeCSS.Missing}}`), 0o644); err != nil {
		t.Fatalf("write execute template: %v", err)
	}
	if _, err := RenderChecklistHTML(Checklist{}, execTemplatePath, cssPath); err == nil || !strings.Contains(err.Error(), "render template") {
		t.Fatalf("expected execute error, got %v", err)
	}
}

func TestBuildChecklistAndRenderSuccessBranches(t *testing.T) {
	t.Parallel()

	input := AssessmentInput{
		SchemaVersion: InputSchemaVersion,
		Sources: []SourceRef{
			{Kind: "repo-scan"},
		},
	}
	pipeline := PipelineResult{
		Mode: ModeFull,
		Stages: []PipelineStage{
			{Name: "osv", Status: StageStatusSucceeded, AdvisoryCount: 1, AffectedPackage: 1},
			{Name: "nvd", Status: StageStatusSucceeded, AdvisoryCount: 0, AffectedPackage: 0},
		},
		Output: AssessmentOutput{
			Packages: []PackageFinding{
				{
					Package: PackageRef{
						Key:            "pkg:npm/react@19.2.4",
						Name:           "react",
						Version:        "19.2.4",
						Ecosystem:      "node",
						PURL:           "pkg:npm/react@19.2.4",
						Aliases:        []string{"npm:react"},
						SourceIDs:      []string{"repo-scan"},
						FieldOrigins:   map[string]string{"licenseKey": "repo-scan"},
						ConflictFields: []string{"repository"},
					},
					Query: QueryRef{Method: "purl"},
					Advisories: []AdvisoryRef{
						{ID: "GHSA-1", Severity: "high", Summary: "summary"},
					},
				},
				{
					Package:       PackageRef{Key: "pkg:nuget/newtonsoft.json@13.0.3", Name: "Newtonsoft.Json", Version: "13.0.3", Ecosystem: "dotnet"},
					SkippedReason: "unsupported-ecosystem",
				},
			},
		},
	}

	checklist := BuildChecklist(input, pipeline)
	if checklist.Mode != ModeFull || checklist.TotalPackages != 2 || checklist.PackagesWithFinds != 1 || checklist.SkippedPackages != 1 || checklist.TotalAdvisories != 1 {
		t.Fatalf("unexpected checklist summary: %#v", checklist)
	}
	if !slices.Equal(checklist.Sources, []string{"nvd", "osv", "repo-scan"}) {
		t.Fatalf("sources = %#v", checklist.Sources)
	}
	if len(checklist.PackageFindings) != 2 || checklist.PackageFindings[0].Name != "react" || checklist.PackageFindings[1].Name != "Newtonsoft.Json" {
		t.Fatalf("package findings = %#v", checklist.PackageFindings)
	}
	output := BuildChecklistOutput(input, checklist, nil)
	if output.SchemaVersion != JSONChecklistSchemaVersion || output.Provenance.InputSchemaVersion != InputSchemaVersion {
		t.Fatalf("output provenance = %#v", output)
	}
	if !slices.Equal(output.Provenance.Sources, checklist.Sources) {
		t.Fatalf("provenance sources = %#v", output.Provenance.Sources)
	}

	dir := t.TempDir()
	cssPath := filepath.Join(dir, "theme.css")
	templatePath := filepath.Join(dir, "report.html.tmpl")
	if err := os.WriteFile(cssPath, []byte(`body{color:black;}`), 0o644); err != nil {
		t.Fatalf("write css: %v", err)
	}
	if err := os.WriteFile(templatePath, []byte(`{{.Mode}}|{{len .PackageFindings}}|{{.ThemeCSS}}|{{prettyJSON .Sources}}`), 0o644); err != nil {
		t.Fatalf("write template: %v", err)
	}
	rendered, err := RenderChecklistHTML(checklist, templatePath, cssPath)
	if err != nil {
		t.Fatalf("render success: %v", err)
	}
	if !strings.Contains(string(rendered), ModeFull) || !strings.Contains(string(rendered), "body{color:black;}") || !strings.Contains(string(rendered), "repo-scan") {
		t.Fatalf("rendered html = %q", string(rendered))
	}

	serialized, err := json.Marshal(output)
	if err != nil {
		t.Fatalf("marshal output: %v", err)
	}
	if !strings.Contains(string(serialized), `"schemaVersion":"1"`) {
		t.Fatalf("serialized output = %s", string(serialized))
	}
}

func TestBuildChecklistClonesPackageSlicesAndMaps(t *testing.T) {
	t.Parallel()

	input := AssessmentInput{
		SchemaVersion: InputSchemaVersion,
		Sources:       []SourceRef{{Kind: "repo-scan"}},
	}
	pipeline := PipelineResult{
		Mode: ModeOSVOnly,
		Output: AssessmentOutput{
			Packages: []PackageFinding{{
				Package: PackageRef{
					Key:            "pkg:npm/react@19.2.4",
					Name:           "react",
					Version:        "19.2.4",
					Ecosystem:      "node",
					PURL:           "pkg:npm/react@19.2.4",
					Aliases:        []string{"react", "node:react"},
					SourceIDs:      []string{"repo-scan"},
					FieldOrigins:   map[string]string{"repository": "repo-scan"},
					ConflictFields: []string{"repository"},
				},
				Query: QueryRef{Method: "purl"},
				Advisories: []AdvisoryRef{{
					ID:       "GHSA-react-1",
					Severity: "high",
					Summary:  "summary",
				}},
			}},
		},
	}

	checklist := BuildChecklist(input, pipeline)
	view := checklist.PackageFindings[0]
	view.Aliases[0] = "mutated-alias"
	view.SourceIDs[0] = "mutated-source"
	view.FieldOrigins["repository"] = "mutated-origin"
	view.ConflictFields[0] = "mutated-conflict"
	view.Advisories[0].Summary = "mutated-summary"

	original := pipeline.Output.Packages[0]
	if original.Package.Aliases[0] != "react" {
		t.Fatalf("aliases mutated: %#v", original.Package.Aliases)
	}
	if original.Package.SourceIDs[0] != "repo-scan" {
		t.Fatalf("source ids mutated: %#v", original.Package.SourceIDs)
	}
	if original.Package.FieldOrigins["repository"] != "repo-scan" {
		t.Fatalf("field origins mutated: %#v", original.Package.FieldOrigins)
	}
	if original.Package.ConflictFields[0] != "repository" {
		t.Fatalf("conflict fields mutated: %#v", original.Package.ConflictFields)
	}
	if original.Advisories[0].Summary != "summary" {
		t.Fatalf("advisories mutated: %#v", original.Advisories)
	}
}

func TestRenderChecklistHTMLPrettyJSONFormatsStructuredValues(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	cssPath := filepath.Join(dir, "theme.css")
	templatePath := filepath.Join(dir, "report.html.tmpl")
	if err := os.WriteFile(cssPath, []byte(`body{color:navy;}`), 0o644); err != nil {
		t.Fatalf("write css: %v", err)
	}
	if err := os.WriteFile(templatePath, []byte(`<pre>{{prettyJSON .PackageFindings}}</pre>`), 0o644); err != nil {
		t.Fatalf("write template: %v", err)
	}

	rendered, err := RenderChecklistHTML(Checklist{
		PackageFindings: []PackageFindingView{{
			Name:      "react",
			Ecosystem: "node",
			Severity:  "high",
		}},
	}, templatePath, cssPath)
	if err != nil {
		t.Fatalf("render success: %v", err)
	}
	if !strings.Contains(string(rendered), "\n  {\n") || !strings.Contains(string(rendered), "&#34;name&#34;: &#34;react&#34;") {
		t.Fatalf("prettyJSON output = %q", string(rendered))
	}
}
