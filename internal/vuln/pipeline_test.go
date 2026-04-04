package vuln

import (
	"context"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"
)

func TestRunPipelineOSVOnly(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"results":[{"vulns":[{"id":"GHSA-react-1"}]}]}`))
	}))
	defer server.Close()

	input := AssessmentInput{
		SchemaVersion: InputSchemaVersion,
		Packages: []PackageRef{{
			Key:  "pkg:npm/react@19.2.4",
			PURL: "pkg:npm/react@19.2.4",
			Name: "react",
		}},
	}

	result := RunPipeline(context.Background(), input, PipelineConfig{
		Mode:       ModeOSVOnly,
		Client:     server.Client(),
		OSVBaseURL: server.URL,
	})
	if result.Mode != ModeOSVOnly {
		t.Fatalf("mode = %q", result.Mode)
	}
	if len(result.Stages) != 1 || result.Stages[0].Status != StageStatusSucceeded {
		t.Fatalf("stages = %#v", result.Stages)
	}
	if len(result.Output.Packages) != 1 || len(result.Output.Packages[0].Advisories) != 1 {
		t.Fatalf("packages = %#v", result.Output.Packages)
	}
}

func TestRunPipelineFullDegradesWhenSupplementalSourcesAreUnavailable(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/querybatch":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"results":[{"vulns":[{"id":"GHSA-custom-1"}]}]}`))
		case "/advisories":
			http.Error(w, "temporary failure", http.StatusBadGateway)
		case "/rest/json/cves/2.0":
			http.Error(w, "temporary failure", http.StatusBadGateway)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	input := AssessmentInput{
		SchemaVersion: InputSchemaVersion,
		Packages: []PackageRef{{
			Key:       "pkg:npm/custom-lib@1.0.0",
			PURL:      "pkg:npm/custom-lib@1.0.0",
			Ecosystem: "node",
			Name:      "custom-lib",
			Version:   "1.0.0",
		}},
	}

	result := RunPipeline(context.Background(), input, PipelineConfig{
		Mode:                  ModeFull,
		Client:                server.Client(),
		OSVBaseURL:            server.URL,
		GitHubAdvisoryBaseURL: server.URL,
		NVDBaseURL:            server.URL,
	})
	if len(result.Stages) != 3 {
		t.Fatalf("stages = %#v", result.Stages)
	}
	if result.Stages[0].Status != StageStatusSucceeded {
		t.Fatalf("unexpected first stage status = %q", result.Stages[0].Status)
	}
	if result.Stages[1].Status != StageStatusFailed || result.Stages[1].Reason == "" {
		t.Fatalf("github stage = %#v", result.Stages[1])
	}
	if result.Stages[2].Status != StageStatusSucceeded {
		t.Fatalf("nvd stage = %#v", result.Stages[2])
	}
}

func TestRunPipelineOSVGitHubMergesSupplementalMetadata(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/querybatch":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"results":[{"vulns":[{"id":"CVE-2026-0001"}]}]}`))
		case "/advisories":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`[
  {
    "ghsa_id":"GHSA-react-1",
    "cve_id":"CVE-2026-0001",
    "html_url":"https://github.com/advisories/GHSA-react-1",
    "summary":"Supplemental advisory",
    "severity":"high",
    "references":["https://example.test/advisory"],
    "updated_at":"2026-04-02T00:00:00Z",
    "cvss":{"vector_string":"CVSS:3.1/...","score":7.6}
  }
]`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	result := RunPipeline(context.Background(), AssessmentInput{
		SchemaVersion: InputSchemaVersion,
		Packages: []PackageRef{{
			Key:       "pkg:npm/react@19.2.4",
			PURL:      "pkg:npm/react@19.2.4",
			Ecosystem: "node",
			Name:      "react",
			Version:   "19.2.4",
		}},
	}, PipelineConfig{
		Mode:                  ModeOSVGitHub,
		Client:                server.Client(),
		OSVBaseURL:            server.URL,
		GitHubAdvisoryBaseURL: server.URL,
	})

	if len(result.Stages) != 2 || result.Stages[1].Status != StageStatusSucceeded {
		t.Fatalf("stages = %#v", result.Stages)
	}
	if len(result.Output.Packages) != 1 || len(result.Output.Packages[0].Advisories) != 1 {
		t.Fatalf("packages = %#v", result.Output.Packages)
	}
	advisory := result.Output.Packages[0].Advisories[0]
	if advisory.Summary != "Supplemental advisory" {
		t.Fatalf("summary = %q", advisory.Summary)
	}
	if advisory.Severity != "high" {
		t.Fatalf("severity = %q", advisory.Severity)
	}
	if advisory.CVSSScore == nil || *advisory.CVSSScore != 7.6 {
		t.Fatalf("cvss = %#v", advisory.CVSSScore)
	}
}

func TestRunPipelineFullAppliesNVDEnrichment(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/querybatch":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"results":[{"vulns":[{"id":"CVE-2026-0001"}]}]}`))
		case "/advisories":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`[
  {
    "ghsa_id":"GHSA-react-1",
    "cve_id":"CVE-2026-0001",
    "summary":"Supplemental advisory",
    "severity":"high"
  }
]`))
		case "/rest/json/cves/2.0":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{
  "vulnerabilities": [
    {
      "cve": {
        "id":"CVE-2026-0001",
        "vendorComments":[{"organization":"vendor-a","comment":"Patched in 1.2.3"}],
        "metrics":{
          "cvssMetricV40":[{"type":"Primary","cvssData":{"baseScore":9.3,"baseSeverity":"CRITICAL","vectorString":"CVSS:4.0/..."}}]
        }
      }
    }
  ]
}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	result := RunPipeline(context.Background(), AssessmentInput{
		SchemaVersion: InputSchemaVersion,
		Packages: []PackageRef{{
			Key:       "pkg:npm/react@19.2.4",
			PURL:      "pkg:npm/react@19.2.4",
			Ecosystem: "node",
			Name:      "react",
			Version:   "19.2.4",
		}},
	}, PipelineConfig{
		Mode:                  ModeFull,
		Client:                server.Client(),
		OSVBaseURL:            server.URL,
		GitHubAdvisoryBaseURL: server.URL,
		NVDBaseURL:            server.URL,
	})

	if len(result.Stages) != 3 || result.Stages[2].Status != StageStatusSucceeded {
		t.Fatalf("stages = %#v", result.Stages)
	}
	advisory := result.Output.Packages[0].Advisories[0]
	if advisory.CVSSScore == nil || *advisory.CVSSScore != 9.3 {
		t.Fatalf("cvss = %#v", advisory.CVSSScore)
	}
	if len(advisory.VendorComments) != 1 {
		t.Fatalf("vendor comments = %#v", advisory.VendorComments)
	}
}

func TestRunPipelineAggregatesStagesAcrossMultiplePackages(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/querybatch":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{
  "results": [
    {"vulns":[{"id":"CVE-2026-1000"}]},
    {"vulns":[{"id":"GHSA-vue-1"},{"id":"GHSA-vue-2"}]}
  ]
}`))
		case "/advisories":
			w.Header().Set("Content-Type", "application/json")
			switch r.URL.Query().Get("affects") {
			case "react@19.2.4":
				_, _ = w.Write([]byte(`[
  {
    "ghsa_id":"GHSA-react-1",
    "cve_id":"CVE-2026-1000",
    "summary":"React supplemental advisory",
    "severity":"high"
  }
]`))
			case "vue@3.5.13":
				_, _ = w.Write([]byte(`[]`))
			default:
				http.NotFound(w, r)
			}
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	result := RunPipeline(context.Background(), AssessmentInput{
		SchemaVersion: InputSchemaVersion,
		Packages: []PackageRef{
			{
				Key:       "pkg:npm/react@19.2.4",
				PURL:      "pkg:npm/react@19.2.4",
				Ecosystem: "node",
				Name:      "react",
				Version:   "19.2.4",
			},
			{
				Key:       "pkg:npm/vue@3.5.13",
				PURL:      "pkg:npm/vue@3.5.13",
				Ecosystem: "node",
				Name:      "vue",
				Version:   "3.5.13",
			},
		},
	}, PipelineConfig{
		Mode:                  ModeOSVGitHub,
		Client:                server.Client(),
		OSVBaseURL:            server.URL,
		GitHubAdvisoryBaseURL: server.URL,
	})

	if len(result.Stages) != 2 {
		t.Fatalf("stages = %#v", result.Stages)
	}
	if result.Stages[0].Name != "osv" || result.Stages[0].AdvisoryCount != 3 || result.Stages[0].AffectedPackage != 2 {
		t.Fatalf("osv stage = %#v", result.Stages[0])
	}
	if result.Stages[1].Name != "github-advisory" || result.Stages[1].AdvisoryCount != 1 || result.Stages[1].AffectedPackage != 1 {
		t.Fatalf("github stage = %#v", result.Stages[1])
	}
	if len(result.Output.Packages) != 2 {
		t.Fatalf("packages = %#v", result.Output.Packages)
	}
	if got := len(result.Output.Packages[0].Advisories); got != 1 {
		t.Fatalf("react advisories = %#v", result.Output.Packages[0].Advisories)
	}
	if result.Output.Packages[0].Advisories[0].Summary != "React supplemental advisory" {
		t.Fatalf("react advisory summary = %#v", result.Output.Packages[0].Advisories[0])
	}
	if got := len(result.Output.Packages[1].Advisories); got != 2 {
		t.Fatalf("vue advisories = %#v", result.Output.Packages[1].Advisories)
	}
}

func TestPipelineHelpersMergeAndNormalize(t *testing.T) {
	t.Parallel()

	stage := summarizeStage("osv", StageStatusSucceeded, "  ok  ", []PackageFinding{
		{Package: PackageRef{Key: "pkg:npm/react@1.0.0"}, Advisories: []AdvisoryRef{{ID: "GHSA-1"}, {ID: "GHSA-2"}}},
		{Package: PackageRef{Key: "pkg:npm/empty@1.0.0"}},
	})
	if stage.AffectedPackage != 1 || stage.AdvisoryCount != 2 || stage.Reason != "ok" {
		t.Fatalf("stage = %#v", stage)
	}

	cloned := cloneFindings([]PackageRef{{Key: "pkg:npm/react@1.0.0", Name: "react"}})
	if len(cloned) != 1 || cloned[0].Package.Name != "react" {
		t.Fatalf("cloned findings = %#v", cloned)
	}

	base := []PackageFinding{
		{
			Package: PackageRef{Key: "pkg:npm/react@1.0.0", Name: "react"},
			Query:   QueryRef{Method: "purl"},
			Advisories: []AdvisoryRef{{
				ID:       "GHSA-react-1",
				Aliases:  []string{"CVE-2026-0001"},
				Source:   "osv",
				Severity: "medium",
			}},
		},
	}
	incoming := []PackageFinding{
		{
			Package:       PackageRef{Key: "pkg:npm/react@1.0.0", Name: "react"},
			SkippedReason: "ignored-on-merge",
			Advisories: []AdvisoryRef{{
				ID:         "CVE-2026-0001",
				Aliases:    []string{"GHSA-react-1"},
				Source:     "nvd",
				Severity:   "critical",
				References: []string{"https://example.test/react"},
			}},
		},
		{
			Package:       PackageRef{Key: "pkg:npm/vue@1.0.0", Name: "vue"},
			SkippedReason: "unsupported-ecosystem",
		},
	}
	merged := mergePackageFindings(base, incoming)
	if got := []string{merged[0].Package.Key, merged[1].Package.Key}; !slices.Equal(got, []string{"pkg:npm/react@1.0.0", "pkg:npm/vue@1.0.0"}) {
		t.Fatalf("merged order = %#v", got)
	}
	if merged[0].Query.Method != "purl" {
		t.Fatalf("query method = %q", merged[0].Query.Method)
	}
	if merged[0].SkippedReason != "ignored-on-merge" {
		t.Fatalf("skipped reason = %q", merged[0].SkippedReason)
	}
	if len(merged[0].Advisories) != 1 || merged[0].Advisories[0].Severity != "critical" {
		t.Fatalf("merged advisories = %#v", merged[0].Advisories)
	}
}

func TestVulnerabilityHelpersDedupeAndNormalizeEdgeCases(t *testing.T) {
	t.Parallel()

	score := 8.5
	values := dedupeAdvisories([]AdvisoryRef{
		{ID: " ", Aliases: []string{"  "}},
		{
			ID:         "GHSA-react-1",
			Aliases:    []string{"CVE-2026-0001", "GHSA-react-1"},
			Source:     "github-advisory",
			Severity:   "high",
			References: []string{"https://example.test/a", "https://example.test/a"},
		},
		{
			ID:         "CVE-2026-0001",
			Aliases:    []string{"GHSA-react-1"},
			Source:     "nvd",
			Severity:   "critical",
			CVSSScore:  &score,
			CVSSVector: "CVSS:4.0/...",
			VendorComments: []VendorCommentRef{
				{Organization: "vendor-a", Comment: " patched ", LastModified: "2026-04-03"},
				{Organization: "vendor-a", Comment: "patched", LastModified: "2026-04-03"},
				{Organization: " ", Comment: " ", LastModified: " "},
			},
		},
	})
	if len(values) != 1 {
		t.Fatalf("deduped values = %#v", values)
	}
	if values[0].Severity != "critical" || values[0].CVSSScore == nil || *values[0].CVSSScore != 8.5 {
		t.Fatalf("merged advisory = %#v", values[0])
	}
	if len(values[0].VendorComments) != 1 || values[0].VendorComments[0].Comment != "patched" {
		t.Fatalf("vendor comments = %#v", values[0].VendorComments)
	}

	if got := extractCVEs([]string{"cve-2026-0001", "GHSA-1", "cve-2026-0001", "CVE-20-100"}); !slices.Equal(got, []string{"CVE-2026-0001"}) {
		t.Fatalf("extractCVEs = %#v", got)
	}

	comments := mergeVendorComments(
		[]VendorCommentRef{{Organization: "vendor-b", Comment: "beta", LastModified: "2026-02-01"}},
		[]VendorCommentRef{{Organization: "vendor-a", Comment: "alpha", LastModified: "2026-01-01"}},
	)
	if got := []string{comments[0].Organization, comments[1].Organization}; !slices.Equal(got, []string{"vendor-a", "vendor-b"}) {
		t.Fatalf("merged vendor comments = %#v", comments)
	}
}

func TestPipelineModeAndDisabledStageNormalization(t *testing.T) {
	t.Parallel()

	if got := normalizePipelineMode(" OSV+GITHUB "); got != ModeOSVGitHub {
		t.Fatalf("normalizePipelineMode osv+github = %q", got)
	}
	if got := normalizePipelineMode(""); got != ModeDisabled {
		t.Fatalf("normalizePipelineMode empty = %q", got)
	}

	result := RunPipeline(context.Background(), AssessmentInput{SchemaVersion: InputSchemaVersion}, PipelineConfig{Mode: " disabled "})
	if result.Mode != ModeDisabled {
		t.Fatalf("mode = %q", result.Mode)
	}
	if len(result.Stages) != 1 || result.Stages[0].Name != "pipeline" || result.Stages[0].Status != StageStatusSkipped || result.Stages[0].Reason != "disabled" {
		t.Fatalf("disabled stage = %#v", result.Stages)
	}
}
