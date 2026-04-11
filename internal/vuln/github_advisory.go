package vuln

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"depaudit-license/internal/externalaccess"
)

const (
	DefaultGitHubAdvisoryBaseURL = "https://api.github.com"
	defaultGitHubAPIVersion      = "2026-03-10"
)

type GitHubAdvisoryClient struct {
	BaseURL string
	Client  *http.Client
	Token   string
}

type githubGlobalAdvisory struct {
	GHSAID      string   `json:"ghsa_id"`
	CVEID       string   `json:"cve_id"`
	HTMLURL     string   `json:"html_url"`
	Summary     string   `json:"summary"`
	Severity    string   `json:"severity"`
	References  []string `json:"references"`
	UpdatedAt   string   `json:"updated_at"`
	Identifiers []struct {
		Type  string `json:"type"`
		Value string `json:"value"`
	} `json:"identifiers"`
	CVSS struct {
		VectorString string  `json:"vector_string"`
		Score        float64 `json:"score"`
	} `json:"cvss"`
}

func (c GitHubAdvisoryClient) Query(ctx context.Context, input AssessmentInput) (Assessment, error) {
	client := c.Client
	if client == nil {
		client = http.DefaultClient
	}

	findings := make([]PackageFinding, len(input.Packages))
	baseURL := strings.TrimRight(strings.TrimSpace(c.BaseURL), "/")
	if baseURL == "" {
		baseURL = DefaultGitHubAdvisoryBaseURL
	}

	for index, pkg := range input.Packages {
		query, ok, skippedReason := buildGitHubAdvisoryQuery(pkg)
		findings[index] = PackageFinding{
			Package:       pkg,
			Query:         query,
			SkippedReason: skippedReason,
		}
		if !ok {
			continue
		}

		advisories, err := c.queryPackage(ctx, client, baseURL, query)
		if err != nil {
			return Assessment{}, err
		}
		findings[index].Advisories = advisories
	}

	return Assessment{
		Source:   "github-advisory",
		Packages: findings,
	}, nil
}

func buildGitHubAdvisoryQuery(pkg PackageRef) (QueryRef, bool, string) {
	ecosystem := normalizeGitHubAdvisoryEcosystem(pkg.Ecosystem)
	if ecosystem == "" {
		return QueryRef{}, false, "unsupported-ecosystem"
	}
	if strings.TrimSpace(pkg.Name) == "" || strings.TrimSpace(pkg.Version) == "" {
		return QueryRef{}, false, "missing-package-version"
	}
	return QueryRef{
		Method:    "github-advisory",
		Ecosystem: ecosystem,
		Name:      strings.TrimSpace(pkg.Name),
		Version:   strings.TrimSpace(pkg.Version),
	}, true, ""
}

func normalizeGitHubAdvisoryEcosystem(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "node":
		return "npm"
	case "dotnet":
		return "nuget"
	case "pypi":
		return "pip"
	case "maven":
		return "maven"
	case "golang", "go":
		return "go"
	default:
		return ""
	}
}

func (c GitHubAdvisoryClient) queryPackage(ctx context.Context, client *http.Client, baseURL string, query QueryRef) ([]AdvisoryRef, error) {
	endpoint, err := url.Parse(baseURL + "/advisories")
	if err != nil {
		return nil, err
	}

	values := endpoint.Query()
	values.Set("ecosystem", query.Ecosystem)
	values.Set("affects", query.Name+"@"+query.Version)
	values.Set("per_page", "100")
	endpoint.RawQuery = values.Encode()

	var advisories []AdvisoryRef
	nextURL := endpoint.String()
	for nextURL != "" {
		page, pageNextURL, err := c.fetchAdvisoryPage(ctx, client, baseURL, nextURL)
		if err != nil {
			return nil, err
		}
		advisories = append(advisories, page...)
		nextURL = pageNextURL
	}
	return dedupeAdvisories(advisories), nil
}

func (c GitHubAdvisoryClient) fetchAdvisoryPage(ctx context.Context, client *http.Client, baseURL string, endpoint string) ([]AdvisoryRef, string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, "", err
	}
	req = externalaccess.WithRequestService(req, externalaccess.Service{
		ID:             "github-advisory",
		Purpose:        "vulnerability",
		BaseURL:        baseURL,
		AuthConfigured: strings.TrimSpace(c.Token) != "",
	})
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", defaultGitHubAPIVersion)
	req.Header.Set("User-Agent", "depaudit-license")
	if token := strings.TrimSpace(c.Token); token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return nil, "", fmt.Errorf("github advisory query failed with status %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	var payload []githubGlobalAdvisory
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return nil, "", err
	}

	advisories := make([]AdvisoryRef, 0, len(payload))
	for _, advisory := range payload {
		advisories = append(advisories, mapGitHubAdvisory(advisory))
	}
	return advisories, parseNextLink(resp.Header.Get("Link")), nil
}

func mapGitHubAdvisory(advisory githubGlobalAdvisory) AdvisoryRef {
	result := AdvisoryRef{
		ID:         strings.TrimSpace(advisory.GHSAID),
		Source:     "github-advisory",
		Summary:    strings.TrimSpace(advisory.Summary),
		Severity:   strings.ToLower(strings.TrimSpace(advisory.Severity)),
		URL:        strings.TrimSpace(advisory.HTMLURL),
		References: uniqueSorted(advisory.References),
		Modified:   strings.TrimSpace(advisory.UpdatedAt),
	}
	if score := advisory.CVSS.Score; score > 0 {
		scoreCopy := score
		result.CVSSScore = &scoreCopy
	}
	result.CVSSVector = strings.TrimSpace(advisory.CVSS.VectorString)

	aliases := []string{result.ID, strings.TrimSpace(advisory.CVEID)}
	for _, identifier := range advisory.Identifiers {
		aliases = append(aliases, strings.TrimSpace(identifier.Value))
	}
	result.Aliases = uniqueSorted(aliases)
	return result
}

func parseNextLink(headerValue string) string {
	for _, part := range strings.Split(headerValue, ",") {
		part = strings.TrimSpace(part)
		if part == "" || !strings.Contains(part, `rel="next"`) {
			continue
		}
		start := strings.Index(part, "<")
		end := strings.Index(part, ">")
		if start >= 0 && end > start {
			return strings.TrimSpace(part[start+1 : end])
		}
	}
	return ""
}

func formatCVSSScore(score *float64) string {
	if score == nil {
		return ""
	}
	return strconv.FormatFloat(*score, 'f', -1, 64)
}
