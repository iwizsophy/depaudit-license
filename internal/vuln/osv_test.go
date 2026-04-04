package vuln

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"depaudit-license/internal/testutil"
)

func TestOSVHelperBranches(t *testing.T) {
	t.Parallel()

	if got := normalizeOSVEcosystem(" node "); got != "npm" {
		t.Fatalf("normalizeOSVEcosystem node = %q", got)
	}
	if got := normalizeOSVEcosystem("dotnet"); got != "NuGet" {
		t.Fatalf("normalizeOSVEcosystem dotnet = %q", got)
	}
	if got := normalizeOSVEcosystem("pypi"); got != "PyPI" {
		t.Fatalf("normalizeOSVEcosystem pypi = %q", got)
	}
	if got := normalizeOSVEcosystem("maven"); got != "Maven" {
		t.Fatalf("normalizeOSVEcosystem maven = %q", got)
	}

	query, ok, skipped := buildOSVQuery(PackageRef{Ecosystem: "node", Name: "react"})
	if ok || skipped != "missing-package-version" {
		t.Fatalf("buildOSVQuery missing version = (%+v, %t, %q)", query, ok, skipped)
	}

	query, ok, skipped = buildOSVQuery(PackageRef{Ecosystem: "node", Version: "19.2.4"})
	if ok || skipped != "missing-package-version" {
		t.Fatalf("buildOSVQuery missing name = (%+v, %t, %q)", query, ok, skipped)
	}

	query, ok, skipped = buildOSVQuery(PackageRef{Ecosystem: "node", Name: "react", Version: " 19.2.4 "})
	if !ok || skipped != "" {
		t.Fatalf("buildOSVQuery ecosystem-version = (%+v, %t, %q)", query, ok, skipped)
	}
	if query.Method != "ecosystem-version" || query.Ecosystem != "npm" || query.Name != "react" || query.Version != "19.2.4" {
		t.Fatalf("unexpected ecosystem-version query: %+v", query)
	}
}

func TestOSVClientQueryBatchUsesPURLAndHandlesPagination(t *testing.T) {
	t.Parallel()

	callCount := 0
	var gotUserAgent string
	var gotAccept string
	var gotContentType string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		if r.Method != http.MethodPost || r.URL.Path != "/v1/querybatch" {
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
		}
		gotUserAgent = r.Header.Get("User-Agent")
		gotAccept = r.Header.Get("Accept")
		gotContentType = r.Header.Get("Content-Type")

		var payload osvQueryBatchRequest
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Fatalf("decode request: %v", err)
		}

		w.Header().Set("Content-Type", "application/json")
		switch callCount {
		case 1:
			if len(payload.Queries) != 2 {
				t.Fatalf("query count = %d", len(payload.Queries))
			}
			if payload.Queries[0].Package.PURL != "pkg:npm/react@19.2.4" {
				t.Fatalf("first purl = %q", payload.Queries[0].Package.PURL)
			}
			if payload.Queries[1].Package.Ecosystem != "NuGet" || payload.Queries[1].Version != "13.0.3" {
				t.Fatalf("unexpected fallback query: %+v", payload.Queries[1])
			}
			_, _ = w.Write([]byte(`{
  "results": [
    {
      "vulns": [{"id":"GHSA-react-1","modified":"2026-04-02T00:00:00Z"}],
      "next_page_token": "next-react"
    },
    {
      "vulns": [{"id":"GHSA-json-1","modified":"2026-04-02T00:00:00Z"}]
    }
  ]
}`))
		case 2:
			if len(payload.Queries) != 1 || payload.Queries[0].PageToken != "next-react" {
				t.Fatalf("unexpected paged query: %+v", payload.Queries)
			}
			_, _ = w.Write([]byte(`{
  "results": [
    {
      "vulns": [{"id":"GHSA-react-2","modified":"2026-04-03T00:00:00Z"}]
    }
  ]
}`))
		default:
			t.Fatal("unexpected extra request")
		}
	}))
	defer server.Close()

	assessment, err := OSVClient{
		BaseURL: server.URL,
		Client:  server.Client(),
	}.QueryBatch(context.Background(), AssessmentInput{
		SchemaVersion: InputSchemaVersion,
		Packages: []PackageRef{
			{Key: "pkg:npm/react@19.2.4", PURL: "pkg:npm/react@19.2.4", Name: "react", Version: "19.2.4"},
			{Key: "pkg:nuget/newtonsoft.json@13.0.3", Ecosystem: "dotnet", Name: "Newtonsoft.Json", Version: "13.0.3"},
			{Key: "pkg:generic/custom-lib@1.0.0", Ecosystem: "generic", Name: "custom-lib", Version: "1.0.0"},
		},
	})
	if err != nil {
		t.Fatalf("query batch: %v", err)
	}

	if len(assessment.Packages) != 3 {
		t.Fatalf("package findings = %d", len(assessment.Packages))
	}
	if assessment.Packages[0].Query.Method != "purl" {
		t.Fatalf("first query method = %q", assessment.Packages[0].Query.Method)
	}
	if len(assessment.Packages[0].Advisories) != 2 {
		t.Fatalf("react advisories = %#v", assessment.Packages[0].Advisories)
	}
	if len(assessment.Packages[1].Advisories) != 1 {
		t.Fatalf("nuget advisories = %#v", assessment.Packages[1].Advisories)
	}
	if assessment.Packages[2].SkippedReason != "unsupported-ecosystem" {
		t.Fatalf("generic skipped reason = %q", assessment.Packages[2].SkippedReason)
	}
	if gotUserAgent != "depaudit-license" {
		t.Fatalf("user agent = %q", gotUserAgent)
	}
	if gotAccept != "application/json" {
		t.Fatalf("accept = %q", gotAccept)
	}
	if gotContentType != "application/json" {
		t.Fatalf("content type = %q", gotContentType)
	}
}

func TestOSVExecuteQueryBatchHandlesErrorBranches(t *testing.T) {
	t.Parallel()

	if _, err := executeOSVQueryBatch(context.Background(), http.DefaultClient, "://bad-endpoint", []osvBatchQuery{{}}); err == nil {
		t.Fatal("expected request build error")
	}

	statusServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "down", http.StatusBadGateway)
	}))
	defer statusServer.Close()
	if _, err := executeOSVQueryBatch(context.Background(), statusServer.Client(), statusServer.URL, []osvBatchQuery{{}}); err == nil {
		t.Fatal("expected status error")
	}

	bodyErrClient := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     http.Header{"Content-Type": []string{"application/json"}},
			Body:       testutil.ErrorBody(errors.New("boom")),
		}, nil
	})}
	if _, err := executeOSVQueryBatch(context.Background(), bodyErrClient, "https://example.test/v1/querybatch", []osvBatchQuery{{}}); err == nil {
		t.Fatal("expected body read/decode error")
	}
}
