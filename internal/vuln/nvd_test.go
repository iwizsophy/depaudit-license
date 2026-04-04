package vuln

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestNVDClientEnrichUsesCVEAliasesAndPrefersCVSSV40(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/rest/json/cves/2.0" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
		if got := r.URL.Query().Get("cveId"); got != "CVE-2026-0001" {
			t.Fatalf("cveId = %q", got)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
  "vulnerabilities": [
    {
      "cve": {
        "id": "CVE-2026-0001",
        "lastModified": "2026-04-02T00:00:00.000",
        "vendorComments": [
          {
            "organization": "vendor-a",
            "comment": "Patched in 1.2.3",
            "lastModified": "2026-04-03T00:00:00.000"
          }
        ],
        "metrics": {
          "cvssMetricV40": [
            {
              "type": "Primary",
              "cvssData": {
                "baseScore": 9.3,
                "baseSeverity": "CRITICAL",
                "vectorString": "CVSS:4.0/..."
              }
            }
          ],
          "cvssMetricV31": [
            {
              "type": "Primary",
              "cvssData": {
                "baseScore": 7.5,
                "baseSeverity": "HIGH",
                "vectorString": "CVSS:3.1/..."
              }
            }
          ]
        }
      }
    }
  ]
}`))
	}))
	defer server.Close()

	findings, stage, err := NVDClient{
		BaseURL: server.URL,
		Client:  server.Client(),
	}.Enrich(context.Background(), []PackageFinding{{
		Package: PackageRef{Key: "pkg:npm/react@19.2.4", Name: "react", Version: "19.2.4"},
		Advisories: []AdvisoryRef{{
			ID:      "GHSA-react-1",
			Aliases: []string{"GHSA-react-1", "CVE-2026-0001"},
			Source:  "github-advisory",
		}},
	}})
	if err != nil {
		t.Fatalf("enrich: %v", err)
	}
	if stage.Status != StageStatusSucceeded {
		t.Fatalf("stage = %#v", stage)
	}
	if len(findings) != 1 || len(findings[0].Advisories) != 1 {
		t.Fatalf("findings = %#v", findings)
	}
	advisory := findings[0].Advisories[0]
	if advisory.CVSSScore == nil || *advisory.CVSSScore != 9.3 {
		t.Fatalf("cvss score = %#v", advisory.CVSSScore)
	}
	if advisory.Severity != "critical" {
		t.Fatalf("severity = %q", advisory.Severity)
	}
	if advisory.CVSSVector != "CVSS:4.0/..." {
		t.Fatalf("vector = %q", advisory.CVSSVector)
	}
	if len(advisory.VendorComments) != 1 {
		t.Fatalf("vendor comments = %#v", advisory.VendorComments)
	}
}

func TestNVDClientEnrichFallsBackToCVSSV31(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
  "vulnerabilities": [
    {
      "cve": {
        "id": "CVE-2026-0002",
        "metrics": {
          "cvssMetricV31": [
            {
              "type": "Primary",
              "cvssData": {
                "baseScore": 8.1,
                "baseSeverity": "HIGH",
                "vectorString": "CVSS:3.1/..."
              }
            }
          ]
        }
      }
    }
  ]
}`))
	}))
	defer server.Close()

	findings, _, err := NVDClient{BaseURL: server.URL, Client: server.Client()}.Enrich(context.Background(), []PackageFinding{{
		Package:    PackageRef{Key: "pkg:npm/react@19.2.4"},
		Advisories: []AdvisoryRef{{ID: "CVE-2026-0002", Aliases: []string{"CVE-2026-0002"}}},
	}})
	if err != nil {
		t.Fatalf("enrich: %v", err)
	}
	if findings[0].Advisories[0].CVSSScore == nil || *findings[0].Advisories[0].CVSSScore != 8.1 {
		t.Fatalf("cvss = %#v", findings[0].Advisories[0].CVSSScore)
	}
	if findings[0].Advisories[0].CVSSVector != "CVSS:3.1/..." {
		t.Fatalf("vector = %q", findings[0].Advisories[0].CVSSVector)
	}
}

func TestNVDClientEnrichFallsBackToCVSSV2(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
  "vulnerabilities": [
    {
      "cve": {
        "id": "CVE-2026-0003",
        "metrics": {
          "cvssMetricV2": [
            {
              "type": "Primary",
              "baseSeverity": "MEDIUM",
              "cvssData": {
                "baseScore": 5.0,
                "vectorString": "AV:N/AC:L/..."
              }
            }
          ]
        }
      }
    }
  ]
}`))
	}))
	defer server.Close()

	findings, _, err := NVDClient{BaseURL: server.URL, Client: server.Client()}.Enrich(context.Background(), []PackageFinding{{
		Package:    PackageRef{Key: "pkg:npm/react@19.2.4"},
		Advisories: []AdvisoryRef{{ID: "CVE-2026-0003", Aliases: []string{"CVE-2026-0003"}}},
	}})
	if err != nil {
		t.Fatalf("enrich: %v", err)
	}
	if findings[0].Advisories[0].CVSSScore == nil || *findings[0].Advisories[0].CVSSScore != 5.0 {
		t.Fatalf("cvss = %#v", findings[0].Advisories[0].CVSSScore)
	}
	if findings[0].Advisories[0].Severity != "medium" {
		t.Fatalf("severity = %q", findings[0].Advisories[0].Severity)
	}
}

func TestNVDClientFetchCVEHandlesEdgeCases(t *testing.T) {
	t.Parallel()

	client := NVDClient{}
	if _, err := client.fetchCVE(context.Background(), http.DefaultClient, "://bad-base", "CVE-2026-0001"); err == nil {
		t.Fatal("expected invalid base URL error")
	}

	statusServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "down", http.StatusBadGateway)
	}))
	defer statusServer.Close()
	if _, err := client.fetchCVE(context.Background(), statusServer.Client(), statusServer.URL, "CVE-2026-0001"); err == nil {
		t.Fatal("expected status error")
	}

	invalidJSONServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte("{"))
	}))
	defer invalidJSONServer.Close()
	if _, err := client.fetchCVE(context.Background(), invalidJSONServer.Client(), invalidJSONServer.URL, "CVE-2026-0001"); err == nil {
		t.Fatal("expected invalid JSON error")
	}

	emptyServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"vulnerabilities":[]}`))
	}))
	defer emptyServer.Close()
	advisory, err := client.fetchCVE(context.Background(), emptyServer.Client(), emptyServer.URL, "CVE-2026-9999")
	if err != nil {
		t.Fatalf("fetchCVE empty response: %v", err)
	}
	if advisory.ID != "CVE-2026-9999" || len(advisory.CVEs) != 1 {
		t.Fatalf("empty response advisory = %#v", advisory)
	}
}

func TestNVDMetricSelectorHelpers(t *testing.T) {
	t.Parallel()

	if _, ok := selectTypedMetricV4(nil); ok {
		t.Fatal("expected empty v4 metrics to fail")
	}
	if metric, ok := selectTypedMetricV4([]struct {
		Type     string `json:"type"`
		CVSSData struct {
			BaseScore    float64 `json:"baseScore"`
			BaseSeverity string  `json:"baseSeverity"`
			VectorString string  `json:"vectorString"`
		} `json:"cvssData"`
	}{
		{Type: "Secondary", CVSSData: struct {
			BaseScore    float64 `json:"baseScore"`
			BaseSeverity string  `json:"baseSeverity"`
			VectorString string  `json:"vectorString"`
		}{BaseScore: 6.1, BaseSeverity: "MEDIUM", VectorString: "CVSS:4.0/fallback"}},
	}); !ok || metric.Score != 6.1 {
		t.Fatalf("v4 fallback metric = %#v, %v", metric, ok)
	}

	if _, ok := selectTypedMetricV3(nil); ok {
		t.Fatal("expected empty v3 metrics to fail")
	}
	if metric, ok := selectTypedMetricV3([]struct {
		Type     string `json:"type"`
		CVSSData struct {
			BaseScore    float64 `json:"baseScore"`
			BaseSeverity string  `json:"baseSeverity"`
			VectorString string  `json:"vectorString"`
		} `json:"cvssData"`
	}{
		{Type: "Secondary", CVSSData: struct {
			BaseScore    float64 `json:"baseScore"`
			BaseSeverity string  `json:"baseSeverity"`
			VectorString string  `json:"vectorString"`
		}{BaseScore: 7.2, BaseSeverity: "HIGH", VectorString: "CVSS:3.1/fallback"}},
	}); !ok || metric.Score != 7.2 {
		t.Fatalf("v3 fallback metric = %#v, %v", metric, ok)
	}

	if _, ok := selectTypedMetricV2(nil); ok {
		t.Fatal("expected empty v2 metrics to fail")
	}
	if metric, ok := selectTypedMetricV2([]struct {
		Type         string `json:"type"`
		BaseSeverity string `json:"baseSeverity"`
		CVSSData     struct {
			BaseScore    float64 `json:"baseScore"`
			VectorString string  `json:"vectorString"`
		} `json:"cvssData"`
	}{
		{Type: "Secondary", BaseSeverity: "LOW", CVSSData: struct {
			BaseScore    float64 `json:"baseScore"`
			VectorString string  `json:"vectorString"`
		}{BaseScore: 3.1, VectorString: "AV:N/AC:H/fallback"}},
	}); !ok || metric.Score != 3.1 {
		t.Fatalf("v2 fallback metric = %#v, %v", metric, ok)
	}

	if _, ok := selectNVDMetric(struct {
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
	}{}); ok {
		t.Fatal("expected empty metric set to fail")
	}
}

func TestNVDClientFetchCVEUsesHeadersAndMissingMetricsFallback(t *testing.T) {
	t.Parallel()

	var gotAccept string
	var gotUserAgent string
	var gotAPIKey string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAccept = r.Header.Get("Accept")
		gotUserAgent = r.Header.Get("User-Agent")
		gotAPIKey = r.Header.Get("apiKey")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
  "vulnerabilities": [
    {
      "cve": {
        "id": "CVE-2026-4242",
        "lastModified": "2026-04-02T00:00:00.000",
        "metrics": {}
      }
    }
  ]
}`))
	}))
	defer server.Close()

	advisory, err := NVDClient{BaseURL: server.URL, Client: server.Client(), APIKey: " secret-key "}.fetchCVE(context.Background(), server.Client(), server.URL, "CVE-2026-4242")
	if err != nil {
		t.Fatalf("fetchCVE: %v", err)
	}
	if gotAccept != "application/json" {
		t.Fatalf("accept = %q", gotAccept)
	}
	if gotUserAgent != "depaudit-license" {
		t.Fatalf("user agent = %q", gotUserAgent)
	}
	if gotAPIKey != "secret-key" {
		t.Fatalf("api key = %q", gotAPIKey)
	}
	if advisory.ID != "CVE-2026-4242" || advisory.Source != "nvd" {
		t.Fatalf("advisory = %#v", advisory)
	}
	if advisory.CVSSScore != nil || advisory.Severity != "" {
		t.Fatalf("unexpected metric enrichment = %#v", advisory)
	}
}
