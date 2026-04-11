package vuln

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"depaudit-license/internal/testutil"
)

func TestGitHubAdvisoryClientQueryUsesPackageVersionAndPagination(t *testing.T) {
	t.Parallel()

	callCount := 0
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		if r.URL.Path != "/advisories" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
		if callCount == 1 {
			if got := r.URL.Query().Get("ecosystem"); got != "npm" {
				t.Fatalf("ecosystem = %q", got)
			}
			if got := r.URL.Query().Get("affects"); got != "react@19.2.4" {
				t.Fatalf("affects = %q", got)
			}
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Link", `<`+server.URL+`/advisories?page=2>; rel="next"`)
			_, _ = w.Write([]byte(`[
  {
    "ghsa_id":"GHSA-react-1",
    "cve_id":"CVE-2026-0001",
    "html_url":"https://github.com/advisories/GHSA-react-1",
    "summary":"First advisory",
    "severity":"high",
    "references":["https://example.test/1"],
    "updated_at":"2026-04-02T00:00:00Z",
    "identifiers":[
      {"type":"GHSA","value":"GHSA-react-1"},
      {"type":"CVE","value":"CVE-2026-0001"}
    ],
    "cvss":{"vector_string":"CVSS:3.1/...","score":7.6}
  }
]`))
			return
		}

		if got := r.URL.Query().Get("page"); got != "2" {
			t.Fatalf("page = %q", got)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`[
  {
    "ghsa_id":"GHSA-react-2",
    "html_url":"https://github.com/advisories/GHSA-react-2",
    "summary":"Second advisory",
    "severity":"medium",
    "updated_at":"2026-04-03T00:00:00Z"
  }
]`))
	}))
	defer server.Close()

	assessment, err := GitHubAdvisoryClient{
		BaseURL: server.URL,
		Client:  server.Client(),
	}.Query(context.Background(), AssessmentInput{
		SchemaVersion: InputSchemaVersion,
		Packages: []PackageRef{
			{Key: "pkg:npm/react@19.2.4", Ecosystem: "node", Name: "react", Version: "19.2.4"},
			{Key: "pkg:generic/custom@1.0.0", Ecosystem: "generic", Name: "custom", Version: "1.0.0"},
		},
	})
	if err != nil {
		t.Fatalf("query github advisories: %v", err)
	}
	if len(assessment.Packages) != 2 {
		t.Fatalf("packages = %d", len(assessment.Packages))
	}
	if len(assessment.Packages[0].Advisories) != 2 {
		t.Fatalf("advisories = %#v", assessment.Packages[0].Advisories)
	}
	if assessment.Packages[0].Advisories[0].CVSSScore == nil {
		t.Fatal("expected CVSS score")
	}
	if assessment.Packages[1].SkippedReason != "unsupported-ecosystem" {
		t.Fatalf("skipped reason = %q", assessment.Packages[1].SkippedReason)
	}
}

func TestDedupeAdvisoriesMergesOSVAndGitHubMetadata(t *testing.T) {
	t.Parallel()

	score := 7.6
	values := dedupeAdvisories([]AdvisoryRef{
		{ID: "CVE-2026-0001", Aliases: []string{"CVE-2026-0001"}, Source: "osv"},
		{
			ID:         "GHSA-react-1",
			Aliases:    []string{"GHSA-react-1", "CVE-2026-0001"},
			Source:     "github-advisory",
			Summary:    "Merged advisory",
			Severity:   "high",
			URL:        "https://github.com/advisories/GHSA-react-1",
			References: []string{"https://example.test/1"},
			CVSSScore:  &score,
		},
	})
	if len(values) != 1 {
		t.Fatalf("deduped advisory count = %d", len(values))
	}
	if values[0].Summary != "Merged advisory" {
		t.Fatalf("summary = %q", values[0].Summary)
	}
	if values[0].Severity != "high" {
		t.Fatalf("severity = %q", values[0].Severity)
	}
	if values[0].CVSSScore == nil || *values[0].CVSSScore != 7.6 {
		t.Fatalf("cvss = %#v", values[0].CVSSScore)
	}
	if !strings.Contains(strings.Join(values[0].Aliases, ","), "CVE-2026-0001") {
		t.Fatalf("aliases = %#v", values[0].Aliases)
	}
}

func TestGitHubAdvisoryHelpersHandleEdgeCases(t *testing.T) {
	t.Parallel()

	if _, ok, reason := buildGitHubAdvisoryQuery(PackageRef{Ecosystem: "generic", Name: "pkg", Version: "1.0.0"}); ok || reason != "unsupported-ecosystem" {
		t.Fatalf("unsupported ecosystem = %v, %q", ok, reason)
	}
	if _, ok, reason := buildGitHubAdvisoryQuery(PackageRef{Ecosystem: "node", Name: "pkg"}); ok || reason != "missing-package-version" {
		t.Fatalf("missing version = %v, %q", ok, reason)
	}
	if query, ok, reason := buildGitHubAdvisoryQuery(PackageRef{Ecosystem: " dotnet ", Name: "Newtonsoft.Json", Version: "13.0.3"}); !ok || reason != "" || query.Ecosystem != "nuget" {
		t.Fatalf("query = %#v, ok=%v, reason=%q", query, ok, reason)
	}

	client := GitHubAdvisoryClient{}
	if _, err := client.queryPackage(context.Background(), http.DefaultClient, "://bad-base", QueryRef{}); err == nil {
		t.Fatal("expected queryPackage parse error")
	}
	if _, _, err := client.fetchAdvisoryPage(context.Background(), http.DefaultClient, DefaultGitHubAdvisoryBaseURL, "://bad-endpoint"); err == nil {
		t.Fatal("expected fetchAdvisoryPage request build error")
	}

	statusServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "rate limited", http.StatusTooManyRequests)
	}))
	defer statusServer.Close()
	if _, _, err := client.fetchAdvisoryPage(context.Background(), statusServer.Client(), statusServer.URL, statusServer.URL); err == nil || !strings.Contains(err.Error(), "status 429") {
		t.Fatalf("expected status error, got %v", err)
	}

	invalidJSONServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte("{"))
	}))
	defer invalidJSONServer.Close()
	if _, _, err := client.fetchAdvisoryPage(context.Background(), invalidJSONServer.Client(), invalidJSONServer.URL, invalidJSONServer.URL); err == nil {
		t.Fatal("expected invalid JSON error")
	}

	bodyErrClient := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     http.Header{"Content-Type": []string{"application/json"}},
			Body:       testutil.ErrorBody(errors.New("boom")),
		}, nil
	})}
	if _, _, err := client.fetchAdvisoryPage(context.Background(), bodyErrClient, DefaultGitHubAdvisoryBaseURL, "https://example.test/advisories"); err == nil {
		t.Fatal("expected body read/decode error")
	}

	mapped := mapGitHubAdvisory(githubGlobalAdvisory{
		GHSAID:     " GHSA-123 ",
		CVEID:      " CVE-2026-1234 ",
		HTMLURL:    " https://github.com/advisories/GHSA-123 ",
		Summary:    " advisory ",
		Severity:   " HIGH ",
		References: []string{"https://example.test/ref", "https://example.test/ref"},
		UpdatedAt:  " 2026-04-03T00:00:00Z ",
		Identifiers: []struct {
			Type  string `json:"type"`
			Value string `json:"value"`
		}{
			{Type: "GHSA", Value: "GHSA-123"},
			{Type: "CVE", Value: "CVE-2026-1234"},
		},
	})
	if mapped.ID != "GHSA-123" || mapped.Severity != "high" {
		t.Fatalf("mapped advisory = %#v", mapped)
	}
	if mapped.CVSSScore != nil {
		t.Fatalf("expected nil CVSS score, got %#v", mapped.CVSSScore)
	}
	if len(mapped.Aliases) != 2 {
		t.Fatalf("aliases = %#v", mapped.Aliases)
	}

	if got := parseNextLink(`<https://example.test/prev>; rel="prev", <https://example.test/next>; rel="next"`); got != "https://example.test/next" {
		t.Fatalf("parseNextLink next = %q", got)
	}
	if got := parseNextLink(`rel="next"`); got != "" {
		t.Fatalf("parseNextLink malformed = %q", got)
	}
	if got := normalizeGitHubAdvisoryEcosystem(" PyPI "); got != "pip" {
		t.Fatalf("normalizeGitHubAdvisoryEcosystem pypi = %q", got)
	}
	if got := normalizeGitHubAdvisoryEcosystem("Go"); got != "go" {
		t.Fatalf("normalizeGitHubAdvisoryEcosystem go = %q", got)
	}
}

func TestGitHubAdvisoryRequestHeadersIncludeVersionAndToken(t *testing.T) {
	t.Parallel()

	var gotAccept string
	var gotVersion string
	var gotUserAgent string
	var gotAuthorization string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAccept = r.Header.Get("Accept")
		gotVersion = r.Header.Get("X-GitHub-Api-Version")
		gotUserAgent = r.Header.Get("User-Agent")
		gotAuthorization = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`[]`))
	}))
	defer server.Close()

	_, _, err := GitHubAdvisoryClient{
		BaseURL: server.URL,
		Client:  server.Client(),
		Token:   " test-token ",
	}.fetchAdvisoryPage(context.Background(), server.Client(), server.URL, server.URL+"/advisories")
	if err != nil {
		t.Fatalf("fetchAdvisoryPage: %v", err)
	}
	if gotAccept != "application/vnd.github+json" {
		t.Fatalf("accept = %q", gotAccept)
	}
	if gotVersion != defaultGitHubAPIVersion {
		t.Fatalf("api version = %q", gotVersion)
	}
	if gotUserAgent != "depaudit-license" {
		t.Fatalf("user agent = %q", gotUserAgent)
	}
	if gotAuthorization != "Bearer test-token" {
		t.Fatalf("authorization = %q", gotAuthorization)
	}
}

type roundTripFunc = testutil.RoundTripFunc
