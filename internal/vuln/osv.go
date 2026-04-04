package vuln

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

const DefaultOSVBaseURL = "https://api.osv.dev"

type OSVClient struct {
	BaseURL string
	Client  *http.Client
}

type Assessment struct {
	Source   string           `json:"source"`
	Packages []PackageFinding `json:"packages"`
}

type PackageFinding struct {
	Package       PackageRef    `json:"package"`
	Query         QueryRef      `json:"query,omitempty"`
	Advisories    []AdvisoryRef `json:"advisories,omitempty"`
	SkippedReason string        `json:"skippedReason,omitempty"`
}

type QueryRef struct {
	Method    string `json:"method"`
	PURL      string `json:"purl,omitempty"`
	Ecosystem string `json:"ecosystem,omitempty"`
	Name      string `json:"name,omitempty"`
	Version   string `json:"version,omitempty"`
}

type AdvisoryRef struct {
	ID             string             `json:"id"`
	Aliases        []string           `json:"aliases,omitempty"`
	CVEs           []string           `json:"cves,omitempty"`
	Source         string             `json:"source,omitempty"`
	Summary        string             `json:"summary,omitempty"`
	Severity       string             `json:"severity,omitempty"`
	URL            string             `json:"url,omitempty"`
	References     []string           `json:"references,omitempty"`
	CVSSScore      *float64           `json:"cvssScore,omitempty"`
	CVSSVector     string             `json:"cvssVector,omitempty"`
	VendorComments []VendorCommentRef `json:"vendorComments,omitempty"`
	Modified       string             `json:"modified,omitempty"`
}

type VendorCommentRef struct {
	Organization string `json:"organization,omitempty"`
	Comment      string `json:"comment,omitempty"`
	LastModified string `json:"lastModified,omitempty"`
}

type osvQueryBatchRequest struct {
	Queries []osvBatchQuery `json:"queries"`
}

type osvBatchQuery struct {
	Package struct {
		Name      string `json:"name,omitempty"`
		Ecosystem string `json:"ecosystem,omitempty"`
		PURL      string `json:"purl,omitempty"`
	} `json:"package,omitempty"`
	Version   string `json:"version,omitempty"`
	PageToken string `json:"page_token,omitempty"`
}

type osvQueryBatchResponse struct {
	Results []struct {
		Vulns []struct {
			ID       string `json:"id"`
			Modified string `json:"modified"`
		} `json:"vulns"`
		NextPageToken string `json:"next_page_token"`
	} `json:"results"`
}

func (c OSVClient) QueryBatch(ctx context.Context, input AssessmentInput) (Assessment, error) {
	client := c.Client
	if client == nil {
		client = http.DefaultClient
	}

	findings := make([]PackageFinding, len(input.Packages))
	queries := make([]osvBatchQuery, 0, len(input.Packages))
	queryIndexMap := make([]int, 0, len(input.Packages))

	for index, pkg := range input.Packages {
		query, ok, skippedReason := buildOSVQuery(pkg)
		findings[index] = PackageFinding{
			Package:       pkg,
			Query:         query,
			SkippedReason: skippedReason,
		}
		if !ok {
			continue
		}
		queries = append(queries, buildBatchQuery(query))
		queryIndexMap = append(queryIndexMap, index)
	}

	if len(queries) == 0 {
		return Assessment{Source: "osv", Packages: findings}, nil
	}

	baseURL := strings.TrimRight(strings.TrimSpace(c.BaseURL), "/")
	if baseURL == "" {
		baseURL = DefaultOSVBaseURL
	}

	pendingQueries := queries
	pendingIndices := queryIndexMap
	for len(pendingQueries) > 0 {
		response, err := executeOSVQueryBatch(ctx, client, baseURL+"/v1/querybatch", pendingQueries)
		if err != nil {
			return Assessment{}, err
		}
		if len(response.Results) != len(pendingQueries) {
			return Assessment{}, fmt.Errorf("osv querybatch returned %d results for %d queries", len(response.Results), len(pendingQueries))
		}

		nextQueries := make([]osvBatchQuery, 0)
		nextIndices := make([]int, 0)
		for resultIndex, result := range response.Results {
			findingIndex := pendingIndices[resultIndex]
			for _, vuln := range result.Vulns {
				findings[findingIndex].Advisories = append(findings[findingIndex].Advisories, AdvisoryRef{
					ID:       strings.TrimSpace(vuln.ID),
					Aliases:  uniqueSorted([]string{strings.TrimSpace(vuln.ID)}),
					Source:   "osv",
					Modified: strings.TrimSpace(vuln.Modified),
				})
			}
			if token := strings.TrimSpace(result.NextPageToken); token != "" {
				query := pendingQueries[resultIndex]
				query.PageToken = token
				nextQueries = append(nextQueries, query)
				nextIndices = append(nextIndices, findingIndex)
			}
		}
		pendingQueries = nextQueries
		pendingIndices = nextIndices
	}

	return Assessment{
		Source:   "osv",
		Packages: findings,
	}, nil
}

func buildOSVQuery(pkg PackageRef) (QueryRef, bool, string) {
	if strings.TrimSpace(pkg.PURL) != "" {
		return QueryRef{
			Method: "purl",
			PURL:   strings.TrimSpace(pkg.PURL),
		}, true, ""
	}

	ecosystem := normalizeOSVEcosystem(pkg.Ecosystem)
	if ecosystem == "" {
		return QueryRef{}, false, "unsupported-ecosystem"
	}
	if strings.TrimSpace(pkg.Name) == "" || strings.TrimSpace(pkg.Version) == "" {
		return QueryRef{}, false, "missing-package-version"
	}
	return QueryRef{
		Method:    "ecosystem-version",
		Ecosystem: ecosystem,
		Name:      strings.TrimSpace(pkg.Name),
		Version:   strings.TrimSpace(pkg.Version),
	}, true, ""
}

func buildBatchQuery(query QueryRef) osvBatchQuery {
	var result osvBatchQuery
	switch query.Method {
	case "purl":
		result.Package.PURL = query.PURL
	default:
		result.Package.Ecosystem = query.Ecosystem
		result.Package.Name = query.Name
		result.Version = query.Version
	}
	return result
}

func normalizeOSVEcosystem(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "node":
		return "npm"
	case "dotnet":
		return "NuGet"
	case "pypi":
		return "PyPI"
	case "maven":
		return "Maven"
	case "golang", "go":
		return "Go"
	default:
		return ""
	}
}

func executeOSVQueryBatch(ctx context.Context, client *http.Client, endpoint string, queries []osvBatchQuery) (osvQueryBatchResponse, error) {
	payload, err := json.Marshal(osvQueryBatchRequest{Queries: queries})
	if err != nil {
		return osvQueryBatchResponse{}, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(payload))
	if err != nil {
		return osvQueryBatchResponse{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "depaudit-license")

	resp, err := client.Do(req)
	if err != nil {
		return osvQueryBatchResponse{}, err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return osvQueryBatchResponse{}, fmt.Errorf("osv querybatch failed with status %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	var result osvQueryBatchResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return osvQueryBatchResponse{}, err
	}
	return result, nil
}
