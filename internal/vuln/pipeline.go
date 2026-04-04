package vuln

import (
	"context"
	"net/http"
	"regexp"
	"sort"
	"strings"
)

const (
	ModeDisabled  = "disabled"
	ModeOSVOnly   = "osv-only"
	ModeOSVGitHub = "osv+github"
	ModeFull      = "full"
)

const (
	StageStatusSucceeded = "succeeded"
	StageStatusSkipped   = "skipped"
	StageStatusFailed    = "failed"
)

type PipelineConfig struct {
	Mode                  string
	Client                *http.Client
	OSVBaseURL            string
	GitHubAdvisoryBaseURL string
	GitHubToken           string
	NVDBaseURL            string
	NVDAPIKey             string
}

type PipelineResult struct {
	Mode   string           `json:"mode"`
	Stages []PipelineStage  `json:"stages"`
	Output AssessmentOutput `json:"output"`
}

type PipelineStage struct {
	Name            string `json:"name"`
	Status          string `json:"status"`
	Reason          string `json:"reason,omitempty"`
	AdvisoryCount   int    `json:"advisoryCount"`
	AffectedPackage int    `json:"affectedPackages"`
}

type AssessmentOutput struct {
	Packages []PackageFinding `json:"packages"`
}

func RunPipeline(ctx context.Context, input AssessmentInput, cfg PipelineConfig) PipelineResult {
	mode := normalizePipelineMode(cfg.Mode)
	stages := make([]PipelineStage, 0)
	findings := cloneFindings(input.Packages)

	if mode == ModeDisabled {
		return PipelineResult{
			Mode: ModeDisabled,
			Stages: []PipelineStage{{
				Name:   "pipeline",
				Status: StageStatusSkipped,
				Reason: "disabled",
			}},
			Output: AssessmentOutput{Packages: findings},
		}
	}

	osvAssessment, err := OSVClient{BaseURL: cfg.OSVBaseURL, Client: cfg.Client}.QueryBatch(ctx, input)
	if err != nil {
		stages = append(stages, PipelineStage{
			Name:   "osv",
			Status: StageStatusFailed,
			Reason: err.Error(),
		})
	} else {
		findings = mergePackageFindings(findings, osvAssessment.Packages)
		stages = append(stages, summarizeStage("osv", StageStatusSucceeded, "", osvAssessment.Packages))
	}

	switch mode {
	case ModeOSVGitHub, ModeFull:
		githubAssessment, err := GitHubAdvisoryClient{
			BaseURL: cfg.GitHubAdvisoryBaseURL,
			Client:  cfg.Client,
			Token:   cfg.GitHubToken,
		}.Query(ctx, input)
		if err != nil {
			stages = append(stages, PipelineStage{
				Name:   "github-advisory",
				Status: StageStatusFailed,
				Reason: err.Error(),
			})
		} else {
			findings = mergePackageFindings(findings, githubAssessment.Packages)
			stages = append(stages, summarizeStage("github-advisory", StageStatusSucceeded, "", githubAssessment.Packages))
		}
	}
	if mode == ModeFull {
		enrichedFindings, stage, err := NVDClient{
			BaseURL: cfg.NVDBaseURL,
			Client:  cfg.Client,
			APIKey:  cfg.NVDAPIKey,
		}.Enrich(ctx, findings)
		if err != nil {
			stages = append(stages, PipelineStage{
				Name:   "nvd",
				Status: StageStatusFailed,
				Reason: err.Error(),
			})
		} else {
			findings = enrichedFindings
			stages = append(stages, stage)
		}
	}

	return PipelineResult{
		Mode:   mode,
		Stages: stages,
		Output: AssessmentOutput{Packages: findings},
	}
}

func normalizePipelineMode(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "", ModeDisabled:
		return ModeDisabled
	case ModeOSVOnly:
		return ModeOSVOnly
	case ModeOSVGitHub:
		return ModeOSVGitHub
	case ModeFull:
		return ModeFull
	default:
		return ModeDisabled
	}
}

func summarizeStage(name string, status string, reason string, findings []PackageFinding) PipelineStage {
	stage := PipelineStage{
		Name:   name,
		Status: status,
		Reason: strings.TrimSpace(reason),
	}
	for _, finding := range findings {
		if len(finding.Advisories) > 0 {
			stage.AffectedPackage++
			stage.AdvisoryCount += len(finding.Advisories)
		}
	}
	return stage
}

func cloneFindings(packages []PackageRef) []PackageFinding {
	result := make([]PackageFinding, 0, len(packages))
	for _, pkg := range packages {
		result = append(result, PackageFinding{Package: pkg})
	}
	return result
}

func mergePackageFindings(base []PackageFinding, incoming []PackageFinding) []PackageFinding {
	indexByKey := map[string]int{}
	for index, finding := range base {
		indexByKey[finding.Package.Key] = index
	}

	for _, finding := range incoming {
		index, ok := indexByKey[finding.Package.Key]
		if !ok {
			base = append(base, finding)
			indexByKey[finding.Package.Key] = len(base) - 1
			continue
		}

		current := base[index]
		current.Package = finding.Package
		if current.Query.Method == "" {
			current.Query = finding.Query
		}
		if current.SkippedReason == "" {
			current.SkippedReason = finding.SkippedReason
		}
		current.Advisories = dedupeAdvisories(append(current.Advisories, finding.Advisories...))
		base[index] = current
	}

	sort.Slice(base, func(i, j int) bool {
		return base[i].Package.Key < base[j].Package.Key
	})
	return base
}

func dedupeAdvisories(values []AdvisoryRef) []AdvisoryRef {
	seen := map[string]int{}
	result := make([]AdvisoryRef, 0, len(values))
	for _, advisory := range values {
		keys := advisoryKeys(advisory)
		if len(keys) == 0 {
			continue
		}
		existingIndex := -1
		for _, key := range keys {
			if index, ok := seen[key]; ok {
				existingIndex = index
				break
			}
		}
		if existingIndex >= 0 {
			result[existingIndex] = mergeAdvisoryRef(result[existingIndex], advisory)
			for _, key := range advisoryKeys(result[existingIndex]) {
				seen[key] = existingIndex
			}
			continue
		}
		advisory = normalizeAdvisoryRef(advisory)
		result = append(result, advisory)
		index := len(result) - 1
		for _, key := range advisoryKeys(advisory) {
			seen[key] = index
		}
	}
	sort.Slice(result, func(i, j int) bool {
		return result[i].ID < result[j].ID
	})
	return result
}

func advisoryKeys(value AdvisoryRef) []string {
	value = normalizeAdvisoryRef(value)
	keys := append([]string(nil), value.Aliases...)
	if value.ID != "" {
		keys = append(keys, value.ID)
	}
	return uniqueSorted(keys)
}

func normalizeAdvisoryRef(value AdvisoryRef) AdvisoryRef {
	value.ID = strings.TrimSpace(value.ID)
	value.Source = strings.TrimSpace(value.Source)
	value.Summary = strings.TrimSpace(value.Summary)
	value.Severity = strings.ToLower(strings.TrimSpace(value.Severity))
	value.URL = strings.TrimSpace(value.URL)
	value.CVSSVector = strings.TrimSpace(value.CVSSVector)
	value.Modified = strings.TrimSpace(value.Modified)
	value.Aliases = uniqueSorted(append(value.Aliases, value.ID))
	value.CVEs = extractCVEs(append(append([]string(nil), value.CVEs...), value.Aliases...))
	value.References = uniqueSorted(value.References)
	value.VendorComments = normalizeVendorComments(value.VendorComments)
	return value
}

func mergeAdvisoryRef(base AdvisoryRef, incoming AdvisoryRef) AdvisoryRef {
	base = normalizeAdvisoryRef(base)
	incoming = normalizeAdvisoryRef(incoming)

	if base.ID == "" {
		base.ID = incoming.ID
	}
	base.Aliases = uniqueSorted(append(base.Aliases, incoming.Aliases...))
	if base.Source == "" {
		base.Source = incoming.Source
	}
	if base.Summary == "" {
		base.Summary = incoming.Summary
	}
	if severityRank(incoming.Severity) < severityRank(base.Severity) {
		base.Severity = incoming.Severity
	}
	if base.URL == "" {
		base.URL = incoming.URL
	}
	base.References = uniqueSorted(append(base.References, incoming.References...))
	if incoming.Source == "nvd" && incoming.CVSSScore != nil {
		scoreCopy := *incoming.CVSSScore
		base.CVSSScore = &scoreCopy
	} else if base.CVSSScore == nil && incoming.CVSSScore != nil {
		scoreCopy := *incoming.CVSSScore
		base.CVSSScore = &scoreCopy
	}
	if incoming.Source == "nvd" && incoming.CVSSVector != "" {
		base.CVSSVector = incoming.CVSSVector
	} else if base.CVSSVector == "" {
		base.CVSSVector = incoming.CVSSVector
	}
	if base.Modified == "" {
		base.Modified = incoming.Modified
	}
	base.CVEs = uniqueSorted(append(base.CVEs, incoming.CVEs...))
	base.VendorComments = mergeVendorComments(base.VendorComments, incoming.VendorComments)
	if incoming.Source == "nvd" && incoming.Severity != "" {
		base.Severity = incoming.Severity
	}
	return base
}

func severityRank(value string) int {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "critical":
		return 0
	case "high":
		return 1
	case "medium":
		return 2
	case "low":
		return 3
	case "unknown":
		return 4
	case "none":
		return 5
	default:
		return 6
	}
}

var cvePattern = regexp.MustCompile(`(?i)^CVE-\d{4}-\d+$`)

func extractCVEs(values []string) []string {
	result := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.ToUpper(strings.TrimSpace(value))
		if cvePattern.MatchString(value) {
			result = append(result, value)
		}
	}
	return uniqueSorted(result)
}

func normalizeVendorComments(values []VendorCommentRef) []VendorCommentRef {
	if len(values) == 0 {
		return nil
	}
	seen := map[string]struct{}{}
	result := make([]VendorCommentRef, 0, len(values))
	for _, value := range values {
		value.Organization = strings.TrimSpace(value.Organization)
		value.Comment = strings.TrimSpace(value.Comment)
		value.LastModified = strings.TrimSpace(value.LastModified)
		key := strings.Join([]string{value.Organization, value.Comment, value.LastModified}, "\x00")
		if key == "\x00\x00" || key == "" {
			continue
		}
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		result = append(result, value)
	}
	sort.Slice(result, func(i, j int) bool {
		left := strings.Join([]string{result[i].Organization, result[i].LastModified, result[i].Comment}, "\x00")
		right := strings.Join([]string{result[j].Organization, result[j].LastModified, result[j].Comment}, "\x00")
		return left < right
	})
	return result
}

func mergeVendorComments(base []VendorCommentRef, incoming []VendorCommentRef) []VendorCommentRef {
	return normalizeVendorComments(append(append([]VendorCommentRef(nil), base...), incoming...))
}
