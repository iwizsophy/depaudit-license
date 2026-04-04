package vuln

import (
	"bytes"
	"encoding/json"
	"fmt"
	"html/template"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

var now = time.Now

const JSONChecklistSchemaVersion = "1"

type Checklist struct {
	GeneratedAt       string               `json:"generatedAt"`
	Mode              string               `json:"mode"`
	TotalPackages     int                  `json:"totalPackages"`
	PackagesWithFinds int                  `json:"packagesWithFindings"`
	SkippedPackages   int                  `json:"skippedPackages"`
	TotalAdvisories   int                  `json:"totalAdvisories"`
	SeveritySummary   []SeverityStat       `json:"severitySummary"`
	PipelineStages    []PipelineStage      `json:"pipelineStages,omitempty"`
	PackageFindings   []PackageFindingView `json:"packageFindings"`
	Sources           []string             `json:"sources"`
}

type SeverityStat struct {
	Level string `json:"level"`
	Label string `json:"label"`
	Count int    `json:"count"`
}

type PackageFindingView struct {
	Key            string            `json:"key"`
	Name           string            `json:"name"`
	Version        string            `json:"version,omitempty"`
	Ecosystem      string            `json:"ecosystem,omitempty"`
	PURL           string            `json:"purl,omitempty"`
	Aliases        []string          `json:"aliases,omitempty"`
	SourceIDs      []string          `json:"sourceIds,omitempty"`
	FieldOrigins   map[string]string `json:"fieldOrigins,omitempty"`
	ConflictFields []string          `json:"conflictFields,omitempty"`
	QueryMethod    string            `json:"queryMethod,omitempty"`
	SkippedReason  string            `json:"skippedReason,omitempty"`
	Severity       string            `json:"severity"`
	Advisories     []AdvisoryRef     `json:"advisories,omitempty"`
}

type ChecklistOutput struct {
	SchemaVersion string              `json:"schemaVersion"`
	Provenance    ChecklistProvenance `json:"provenance"`
	Checklist     Checklist           `json:"checklist"`
}

type ChecklistProvenance struct {
	InputSchemaVersion string   `json:"inputSchemaVersion"`
	Sources            []string `json:"sources"`
}

type checklistHTMLView struct {
	Checklist
	ThemeCSS template.CSS
}

func BuildChecklist(input AssessmentInput, pipeline PipelineResult) Checklist {
	items := make([]PackageFindingView, 0, len(pipeline.Output.Packages))
	severitySummary := []SeverityStat{
		{Level: "critical", Label: "Critical", Count: 0},
		{Level: "high", Label: "High", Count: 0},
		{Level: "medium", Label: "Medium", Count: 0},
		{Level: "low", Label: "Low", Count: 0},
		{Level: "unknown", Label: "Unknown", Count: 0},
		{Level: "none", Label: "None", Count: 0},
	}
	lookup := map[string]*SeverityStat{
		"critical": &severitySummary[0],
		"high":     &severitySummary[1],
		"medium":   &severitySummary[2],
		"low":      &severitySummary[3],
		"unknown":  &severitySummary[4],
		"none":     &severitySummary[5],
	}

	packagesWithFinds := 0
	skipped := 0
	totalAdvisories := 0
	sourceSet := map[string]struct{}{}
	for _, source := range input.Sources {
		if strings.TrimSpace(source.Kind) != "" {
			sourceSet[source.Kind] = struct{}{}
		}
	}
	for _, stage := range pipeline.Stages {
		if strings.TrimSpace(stage.Name) != "" {
			sourceSet[stage.Name] = struct{}{}
		}
	}

	for _, finding := range pipeline.Output.Packages {
		severity := packageSeverity(finding)
		if len(finding.Advisories) > 0 {
			packagesWithFinds++
			totalAdvisories += len(finding.Advisories)
		}
		if strings.TrimSpace(finding.SkippedReason) != "" {
			skipped++
		}
		lookup[severity].Count++
		items = append(items, PackageFindingView{
			Key:            finding.Package.Key,
			Name:           finding.Package.Name,
			Version:        finding.Package.Version,
			Ecosystem:      finding.Package.Ecosystem,
			PURL:           finding.Package.PURL,
			Aliases:        append([]string(nil), finding.Package.Aliases...),
			SourceIDs:      append([]string(nil), finding.Package.SourceIDs...),
			FieldOrigins:   cloneStringMap(finding.Package.FieldOrigins),
			ConflictFields: append([]string(nil), finding.Package.ConflictFields...),
			QueryMethod:    finding.Query.Method,
			SkippedReason:  finding.SkippedReason,
			Severity:       severity,
			Advisories:     append([]AdvisoryRef(nil), finding.Advisories...),
		})
	}

	sort.Slice(items, func(i, j int) bool {
		left := strings.Join([]string{severityOrder(items[i].Severity), items[i].Ecosystem, items[i].Name, items[i].Version}, "\x00")
		right := strings.Join([]string{severityOrder(items[j].Severity), items[j].Ecosystem, items[j].Name, items[j].Version}, "\x00")
		return left < right
	})

	sources := make([]string, 0, len(sourceSet))
	for source := range sourceSet {
		sources = append(sources, source)
	}
	sort.Strings(sources)

	return Checklist{
		GeneratedAt:       now().Format(time.RFC3339),
		Mode:              pipeline.Mode,
		TotalPackages:     len(pipeline.Output.Packages),
		PackagesWithFinds: packagesWithFinds,
		SkippedPackages:   skipped,
		TotalAdvisories:   totalAdvisories,
		SeveritySummary:   severitySummary,
		PipelineStages:    append([]PipelineStage(nil), pipeline.Stages...),
		PackageFindings:   items,
		Sources:           sources,
	}
}

func BuildChecklistOutput(input AssessmentInput, checklist Checklist) ChecklistOutput {
	return ChecklistOutput{
		SchemaVersion: JSONChecklistSchemaVersion,
		Provenance: ChecklistProvenance{
			InputSchemaVersion: input.SchemaVersion,
			Sources:            append([]string(nil), checklist.Sources...),
		},
		Checklist: checklist,
	}
}

func RenderChecklistHTML(checklist Checklist, templatePath string, cssPath string) ([]byte, error) {
	cssPayload, err := os.ReadFile(cssPath)
	if err != nil {
		return nil, fmt.Errorf("read CSS: %w", err)
	}
	templatePayload, err := os.ReadFile(templatePath)
	if err != nil {
		return nil, fmt.Errorf("read template: %w", err)
	}

	tpl, err := template.New(filepath.Base(templatePath)).Funcs(template.FuncMap{
		"severityLabel":   severityLabel,
		"formatCVSSScore": formatCVSSScore,
		"prettyJSON": func(value any) string {
			data, _ := json.MarshalIndent(value, "", "  ")
			return string(data)
		},
	}).Parse(string(templatePayload))
	if err != nil {
		return nil, fmt.Errorf("parse template: %w", err)
	}

	var rendered bytes.Buffer
	if err := tpl.Execute(&rendered, checklistHTMLView{
		Checklist: checklist,
		ThemeCSS:  template.CSS(string(cssPayload)),
	}); err != nil {
		return nil, fmt.Errorf("render template: %w", err)
	}
	return rendered.Bytes(), nil
}

func severityOrder(value string) string {
	return strconv.Itoa(severityRank(value))
}

func severityLabel(value string) string {
	switch strings.TrimSpace(value) {
	case "critical":
		return "Critical"
	case "high":
		return "High"
	case "medium":
		return "Medium"
	case "low":
		return "Low"
	case "unknown":
		return "Unknown"
	default:
		return "None"
	}
}

func packageSeverity(finding PackageFinding) string {
	if len(finding.Advisories) == 0 {
		return "none"
	}
	best := "unknown"
	for _, advisory := range finding.Advisories {
		severity := strings.ToLower(strings.TrimSpace(advisory.Severity))
		if severity == "" {
			severity = "unknown"
		}
		if severityRank(severity) < severityRank(best) {
			best = severity
		}
	}
	return best
}

func cloneStringMap(values map[string]string) map[string]string {
	if len(values) == 0 {
		return nil
	}
	result := make(map[string]string, len(values))
	for key, value := range values {
		result[key] = value
	}
	return result
}
