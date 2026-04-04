package vuln

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

const DefaultNVDBaseURL = "https://services.nvd.nist.gov"

type NVDClient struct {
	BaseURL string
	Client  *http.Client
	APIKey  string
}

type nvdResponse struct {
	Vulnerabilities []struct {
		CVE struct {
			ID             string `json:"id"`
			LastModified   string `json:"lastModified"`
			VendorComments []struct {
				Organization string `json:"organization"`
				Comment      string `json:"comment"`
				LastModified string `json:"lastModified"`
			} `json:"vendorComments"`
			Metrics struct {
				CVSSMetricV40 []struct {
					Type     string `json:"type"`
					CVSSData struct {
						BaseScore    float64 `json:"baseScore"`
						BaseSeverity string  `json:"baseSeverity"`
						VectorString string  `json:"vectorString"`
					} `json:"cvssData"`
				} `json:"cvssMetricV40"`
				CVSSMetricV31 []struct {
					Type     string `json:"type"`
					CVSSData struct {
						BaseScore    float64 `json:"baseScore"`
						BaseSeverity string  `json:"baseSeverity"`
						VectorString string  `json:"vectorString"`
					} `json:"cvssData"`
				} `json:"cvssMetricV31"`
				CVSSMetricV30 []struct {
					Type     string `json:"type"`
					CVSSData struct {
						BaseScore    float64 `json:"baseScore"`
						BaseSeverity string  `json:"baseSeverity"`
						VectorString string  `json:"vectorString"`
					} `json:"cvssData"`
				} `json:"cvssMetricV30"`
				CVSSMetricV2 []struct {
					Type         string `json:"type"`
					BaseSeverity string `json:"baseSeverity"`
					CVSSData     struct {
						BaseScore    float64 `json:"baseScore"`
						VectorString string  `json:"vectorString"`
					} `json:"cvssData"`
				} `json:"cvssMetricV2"`
			} `json:"metrics"`
		} `json:"cve"`
	} `json:"vulnerabilities"`
}

func (c NVDClient) Enrich(ctx context.Context, findings []PackageFinding) ([]PackageFinding, PipelineStage, error) {
	client := c.Client
	if client == nil {
		client = http.DefaultClient
	}

	baseURL := strings.TrimRight(strings.TrimSpace(c.BaseURL), "/")
	if baseURL == "" {
		baseURL = DefaultNVDBaseURL
	}

	cache := map[string]AdvisoryRef{}
	enriched := append([]PackageFinding(nil), findings...)
	stage := PipelineStage{
		Name:   "nvd",
		Status: StageStatusSucceeded,
	}

	for packageIndex, finding := range enriched {
		advisories := append([]AdvisoryRef(nil), finding.Advisories...)
		packageTouched := false
		for advisoryIndex, advisory := range advisories {
			cves := extractCVEs(append(append([]string(nil), advisory.CVEs...), advisory.Aliases...))
			if len(cves) == 0 {
				continue
			}
			for _, cveID := range cves {
				enrichment, ok := cache[cveID]
				if !ok {
					var err error
					enrichment, err = c.fetchCVE(ctx, client, baseURL, cveID)
					if err != nil {
						return nil, PipelineStage{}, err
					}
					cache[cveID] = enrichment
				}
				advisories[advisoryIndex] = mergeAdvisoryRef(advisories[advisoryIndex], enrichment)
				packageTouched = true
			}
		}
		enriched[packageIndex].Advisories = dedupeAdvisories(advisories)
		if packageTouched {
			stage.AffectedPackage++
		}
		stage.AdvisoryCount += len(enriched[packageIndex].Advisories)
	}

	return enriched, stage, nil
}

func (c NVDClient) fetchCVE(ctx context.Context, client *http.Client, baseURL string, cveID string) (AdvisoryRef, error) {
	endpoint, err := url.Parse(baseURL + "/rest/json/cves/2.0")
	if err != nil {
		return AdvisoryRef{}, err
	}
	values := endpoint.Query()
	values.Set("cveId", cveID)
	endpoint.RawQuery = values.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.String(), nil)
	if err != nil {
		return AdvisoryRef{}, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "depaudit-license")
	if apiKey := strings.TrimSpace(c.APIKey); apiKey != "" {
		req.Header.Set("apiKey", apiKey)
	}

	resp, err := client.Do(req)
	if err != nil {
		return AdvisoryRef{}, err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return AdvisoryRef{}, fmt.Errorf("nvd cve query failed with status %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	var payload nvdResponse
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return AdvisoryRef{}, err
	}
	if len(payload.Vulnerabilities) == 0 {
		return AdvisoryRef{ID: cveID, Aliases: []string{cveID}, CVEs: []string{cveID}, Source: "nvd"}, nil
	}

	record := payload.Vulnerabilities[0].CVE
	result := AdvisoryRef{
		ID:       strings.TrimSpace(record.ID),
		Aliases:  uniqueSorted([]string{strings.TrimSpace(record.ID)}),
		CVEs:     uniqueSorted([]string{strings.TrimSpace(record.ID)}),
		Source:   "nvd",
		Modified: strings.TrimSpace(record.LastModified),
	}
	if metric, ok := selectNVDMetric(record.Metrics); ok {
		scoreCopy := metric.Score
		result.CVSSScore = &scoreCopy
		result.CVSSVector = metric.Vector
		result.Severity = strings.ToLower(metric.Severity)
	}
	for _, comment := range record.VendorComments {
		result.VendorComments = append(result.VendorComments, VendorCommentRef{
			Organization: comment.Organization,
			Comment:      comment.Comment,
			LastModified: comment.LastModified,
		})
	}
	return normalizeAdvisoryRef(result), nil
}

type nvdMetric struct {
	Score    float64
	Vector   string
	Severity string
}

func selectNVDMetric(metrics struct {
	CVSSMetricV40 []struct {
		Type     string `json:"type"`
		CVSSData struct {
			BaseScore    float64 `json:"baseScore"`
			BaseSeverity string  `json:"baseSeverity"`
			VectorString string  `json:"vectorString"`
		} `json:"cvssData"`
	} `json:"cvssMetricV40"`
	CVSSMetricV31 []struct {
		Type     string `json:"type"`
		CVSSData struct {
			BaseScore    float64 `json:"baseScore"`
			BaseSeverity string  `json:"baseSeverity"`
			VectorString string  `json:"vectorString"`
		} `json:"cvssData"`
	} `json:"cvssMetricV31"`
	CVSSMetricV30 []struct {
		Type     string `json:"type"`
		CVSSData struct {
			BaseScore    float64 `json:"baseScore"`
			BaseSeverity string  `json:"baseSeverity"`
			VectorString string  `json:"vectorString"`
		} `json:"cvssData"`
	} `json:"cvssMetricV30"`
	CVSSMetricV2 []struct {
		Type         string `json:"type"`
		BaseSeverity string `json:"baseSeverity"`
		CVSSData     struct {
			BaseScore    float64 `json:"baseScore"`
			VectorString string  `json:"vectorString"`
		} `json:"cvssData"`
	} `json:"cvssMetricV2"`
}) (nvdMetric, bool) {
	if metric, ok := selectTypedMetricV4(metrics.CVSSMetricV40); ok {
		return metric, true
	}
	if metric, ok := selectTypedMetricV3(metrics.CVSSMetricV31); ok {
		return metric, true
	}
	if metric, ok := selectTypedMetricV3(metrics.CVSSMetricV30); ok {
		return metric, true
	}
	if metric, ok := selectTypedMetricV2(metrics.CVSSMetricV2); ok {
		return metric, true
	}
	return nvdMetric{}, false
}

func selectTypedMetricV4(values []struct {
	Type     string `json:"type"`
	CVSSData struct {
		BaseScore    float64 `json:"baseScore"`
		BaseSeverity string  `json:"baseSeverity"`
		VectorString string  `json:"vectorString"`
	} `json:"cvssData"`
}) (nvdMetric, bool) {
	for _, value := range values {
		if strings.EqualFold(value.Type, "Primary") {
			return nvdMetric{Score: value.CVSSData.BaseScore, Vector: value.CVSSData.VectorString, Severity: value.CVSSData.BaseSeverity}, true
		}
	}
	if len(values) == 0 {
		return nvdMetric{}, false
	}
	return nvdMetric{Score: values[0].CVSSData.BaseScore, Vector: values[0].CVSSData.VectorString, Severity: values[0].CVSSData.BaseSeverity}, true
}

func selectTypedMetricV3(values []struct {
	Type     string `json:"type"`
	CVSSData struct {
		BaseScore    float64 `json:"baseScore"`
		BaseSeverity string  `json:"baseSeverity"`
		VectorString string  `json:"vectorString"`
	} `json:"cvssData"`
}) (nvdMetric, bool) {
	for _, value := range values {
		if strings.EqualFold(value.Type, "Primary") {
			return nvdMetric{Score: value.CVSSData.BaseScore, Vector: value.CVSSData.VectorString, Severity: value.CVSSData.BaseSeverity}, true
		}
	}
	if len(values) == 0 {
		return nvdMetric{}, false
	}
	return nvdMetric{Score: values[0].CVSSData.BaseScore, Vector: values[0].CVSSData.VectorString, Severity: values[0].CVSSData.BaseSeverity}, true
}

func selectTypedMetricV2(values []struct {
	Type         string `json:"type"`
	BaseSeverity string `json:"baseSeverity"`
	CVSSData     struct {
		BaseScore    float64 `json:"baseScore"`
		VectorString string  `json:"vectorString"`
	} `json:"cvssData"`
}) (nvdMetric, bool) {
	for _, value := range values {
		if strings.EqualFold(value.Type, "Primary") {
			return nvdMetric{Score: value.CVSSData.BaseScore, Vector: value.CVSSData.VectorString, Severity: value.BaseSeverity}, true
		}
	}
	if len(values) == 0 {
		return nvdMetric{}, false
	}
	return nvdMetric{Score: values[0].CVSSData.BaseScore, Vector: values[0].CVSSData.VectorString, Severity: values[0].BaseSeverity}, true
}
