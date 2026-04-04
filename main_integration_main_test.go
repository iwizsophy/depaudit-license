package main

import (
	"crypto/sha256"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestMainUsesRunWithoutExitingOnSuccess(t *testing.T) {
	dir := t.TempDir()
	outputs := newCLIOutputPaths(dir)
	_, exitCode := setMainHarness(t, []string{
		os.Args[0],
		"-input", "repository-scan=internal/ci/testdata/repo",
		"-output-html", outputs.HTML,
		"-output-json", outputs.JSON,
		"-output-legal-html", outputs.LegalHTML,
	})
	main()

	if *exitCode != -1 {
		t.Fatalf("unexpected exit code %d", *exitCode)
	}
}

func TestMainUsesDefaultRepositoryScanWithoutExitingOnSuccess(t *testing.T) {
	dir := t.TempDir()
	outputs := newCLIOutputPaths(dir)
	_, exitCode := setMainHarness(t, []string{
		os.Args[0],
		"-output-html", outputs.HTML,
		"-output-json", outputs.JSON,
		"-output-legal-html", outputs.LegalHTML,
	})
	main()

	if *exitCode != -1 {
		t.Fatalf("unexpected exit code %d", *exitCode)
	}
	for _, path := range []string{outputs.HTML, outputs.JSON, outputs.LegalHTML} {
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("expected output %s: %v", path, err)
		}
	}
}

func TestMainUsesRunWithoutExitingOnCustomizedSuccess(t *testing.T) {
	remoteBody := `{
  "licenses": [
    {
      "key": "MIT",
      "name": "MIT License (Main Smoke Remote)",
      "family": "MIT",
      "copyleft_strength": "none",
      "requires_manual_review": false,
      "spdx_ids": ["MIT"],
      "names": ["MIT License (Main Smoke Remote)"],
      "contains": ["mit"],
      "risk_level": "low",
      "notice_template": "main smoke remote notice"
    }
  ]
}`
	sum := sha256.Sum256([]byte(remoteBody))
	requestedSHA := strings.ToLower(fmt.Sprintf("%x", sum))

	catalogServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/licenses.json" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(remoteBody))
	}))
	defer catalogServer.Close()

	vulnServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/querybatch":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"results":[{"vulns":[{"id":"CVE-2026-5001"}]},{"vulns":[]},{"vulns":[]},{"vulns":[]}]} `))
		case "/advisories":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`[
  {
    "ghsa_id":"GHSA-react-main-smoke-1",
    "cve_id":"CVE-2026-5001",
    "html_url":"https://github.com/advisories/GHSA-react-main-smoke-1",
    "summary":"Main smoke advisory",
    "severity":"high",
    "updated_at":"2026-04-03T00:00:00Z"
  }
]`))
		case "/rest/json/cves/2.0":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{
  "vulnerabilities": [
    {
      "cve": {
        "id":"CVE-2026-5001",
        "metrics":{
          "cvssMetricV40":[{"type":"Primary","cvssData":{"baseScore":9.2,"baseSeverity":"CRITICAL","vectorString":"CVSS:4.0/..."}}]
        }
      }
    }
  ]
}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer vulnServer.Close()

	dir := t.TempDir()
	bundlePath := writeEnglishLicenseTextBundleFixtureWithMutation(t, dir, func(bundle map[string]any) {
		updateLicenseTextBundleEntry(bundle, "MIT", func(entry map[string]any) {
			entry["description"] = "Pinned multi-source MIT description"
			entry["obligations"] = []string{"Carry pinned multi-source MIT notice"}
		})
	})

	oldArgs := os.Args
	oldExit := exitFunc
	t.Cleanup(func() {
		os.Args = oldArgs
		exitFunc = oldExit
	})

	reportHTMLPath := filepath.Join(dir, "report.html")
	reportJSONPath := filepath.Join(dir, "report.json")
	legalHTMLPath := filepath.Join(dir, "legal.html")
	vulnHTMLPath := filepath.Join(dir, "vuln.html")
	vulnJSONPath := filepath.Join(dir, "vuln.json")

	exitCode := -1
	exitFunc = func(code int) { exitCode = code }
	os.Args = []string{
		oldArgs[0],
		"-input", "repository-scan=internal/ci/testdata/repo",
		"-license-catalog", "configs/licenses.json",
		"-license-catalog", catalogServer.URL + "/licenses.json#sha256=" + requestedSHA,
		"-license-text-bundle", bundlePath,
		"-output-html", reportHTMLPath,
		"-output-json", reportJSONPath,
		"-output-legal-html", legalHTMLPath,
		"-output-vuln-html", vulnHTMLPath,
		"-output-vuln-json", vulnJSONPath,
		"-vuln-mode", "full",
		"-osv-base-url", vulnServer.URL,
		"-github-advisory-base-url", vulnServer.URL,
		"-nvd-base-url", vulnServer.URL,
	}

	main()

	if exitCode != -1 {
		t.Fatalf("unexpected exit code %d", exitCode)
	}
	for _, path := range []string{reportHTMLPath, reportJSONPath, legalHTMLPath, vulnHTMLPath, vulnJSONPath} {
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("expected output %s: %v", path, err)
		}
	}
}

func TestMainUsesRunWithoutExitingOnSPDXCustomizedSuccess(t *testing.T) {
	remoteBody := `{
  "licenses": [
    {
      "key": "MIT",
      "name": "MIT License (Main SPDX Smoke Remote)",
      "family": "MIT",
      "copyleft_strength": "none",
      "requires_manual_review": false,
      "spdx_ids": ["MIT"],
      "names": ["MIT License (Main SPDX Smoke Remote)"],
      "contains": ["mit"],
      "risk_level": "low",
      "notice_template": "main spdx smoke remote notice"
    }
  ]
}`
	sum := sha256.Sum256([]byte(remoteBody))
	requestedSHA := strings.ToLower(fmt.Sprintf("%x", sum))

	catalogServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/licenses.json" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(remoteBody))
	}))
	defer catalogServer.Close()

	vulnServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/querybatch":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"results":[{"vulns":[{"id":"CVE-2026-5002"}]},{"vulns":[]},{"vulns":[]},{"vulns":[]},{"vulns":[]},{"vulns":[]}]} `))
		case "/advisories":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`[
  {
    "ghsa_id":"GHSA-react-main-spdx-smoke-1",
    "cve_id":"CVE-2026-5002",
    "html_url":"https://github.com/advisories/GHSA-react-main-spdx-smoke-1",
    "summary":"Main SPDX smoke advisory",
    "severity":"high",
    "updated_at":"2026-04-03T00:00:00Z"
  }
]`))
		case "/rest/json/cves/2.0":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{
  "vulnerabilities": [
    {
      "cve": {
        "id":"CVE-2026-5002",
        "metrics":{
          "cvssMetricV40":[{"type":"Primary","cvssData":{"baseScore":9.2,"baseSeverity":"CRITICAL","vectorString":"CVSS:4.0/..."}}]
        }
      }
    }
  ]
}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer vulnServer.Close()

	dir := t.TempDir()
	bundlePath := writeEnglishLicenseTextBundleFixtureWithMutation(t, dir, func(bundle map[string]any) {
		updateLicenseTextBundleEntry(bundle, "MIT", func(entry map[string]any) {
			entry["description"] = "Pinned SPDX MIT description"
			entry["obligations"] = []string{"Carry pinned SPDX MIT notice"}
		})
	})

	oldArgs := os.Args
	oldExit := exitFunc
	t.Cleanup(func() {
		os.Args = oldArgs
		exitFunc = oldExit
	})

	reportHTMLPath := filepath.Join(dir, "report.html")
	reportJSONPath := filepath.Join(dir, "report.json")
	legalHTMLPath := filepath.Join(dir, "legal.html")
	vulnHTMLPath := filepath.Join(dir, "vuln.html")
	vulnJSONPath := filepath.Join(dir, "vuln.json")

	exitCode := -1
	exitFunc = func(code int) { exitCode = code }
	os.Args = []string{
		oldArgs[0],
		"-input", "spdx-json=internal/sbom/testdata/spdx/app.json",
		"-license-catalog", "configs/licenses.json",
		"-license-catalog", catalogServer.URL + "/licenses.json#sha256=" + requestedSHA,
		"-license-text-bundle", bundlePath,
		"-output-html", reportHTMLPath,
		"-output-json", reportJSONPath,
		"-output-legal-html", legalHTMLPath,
		"-output-vuln-html", vulnHTMLPath,
		"-output-vuln-json", vulnJSONPath,
		"-vuln-mode", "full",
		"-osv-base-url", vulnServer.URL,
		"-github-advisory-base-url", vulnServer.URL,
		"-nvd-base-url", vulnServer.URL,
	}

	main()

	if exitCode != -1 {
		t.Fatalf("unexpected exit code %d", exitCode)
	}
	for _, path := range []string{reportHTMLPath, reportJSONPath, legalHTMLPath, vulnHTMLPath, vulnJSONPath} {
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("expected output %s: %v", path, err)
		}
	}
}

func TestMainUsesRunWithoutExitingOnMultiSourceCustomizedSuccess(t *testing.T) {
	remoteBody := `{
  "licenses": [
    {
      "key": "MIT",
      "name": "MIT License (Main Multi Source Smoke Remote)",
      "family": "MIT",
      "copyleft_strength": "none",
      "requires_manual_review": false,
      "spdx_ids": ["MIT"],
      "names": ["MIT License (Main Multi Source Smoke Remote)"],
      "contains": ["mit"],
      "risk_level": "low",
      "notice_template": "main multi source smoke remote notice"
    }
  ]
}`
	sum := sha256.Sum256([]byte(remoteBody))
	requestedSHA := strings.ToLower(fmt.Sprintf("%x", sum))

	catalogServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/licenses.json" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(remoteBody))
	}))
	defer catalogServer.Close()

	vulnServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/querybatch":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"results":[{"vulns":[{"id":"CVE-2026-5003"}]},{"vulns":[]},{"vulns":[]},{"vulns":[]},{"vulns":[]},{"vulns":[]}]} `))
		case "/advisories":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`[
  {
    "ghsa_id":"GHSA-react-main-multi-smoke-1",
    "cve_id":"CVE-2026-5003",
    "html_url":"https://github.com/advisories/GHSA-react-main-multi-smoke-1",
    "summary":"Main multi-source smoke advisory",
    "severity":"high",
    "updated_at":"2026-04-03T00:00:00Z"
  }
]`))
		case "/rest/json/cves/2.0":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{
  "vulnerabilities": [
    {
      "cve": {
        "id":"CVE-2026-5003",
        "metrics":{
          "cvssMetricV40":[{"type":"Primary","cvssData":{"baseScore":9.2,"baseSeverity":"CRITICAL","vectorString":"CVSS:4.0/..."}}]
        }
      }
    }
  ]
}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer vulnServer.Close()

	dir := t.TempDir()
	bundlePath := writeEnglishLicenseTextBundleFixtureWithMutation(t, dir, func(bundle map[string]any) {
		updateLicenseTextBundleEntry(bundle, "MIT", func(entry map[string]any) {
			entry["description"] = "Layered bundle MIT description"
			entry["obligations"] = []string{"Carry layered MIT notice"}
		})
	})

	oldArgs := os.Args
	oldExit := exitFunc
	t.Cleanup(func() {
		os.Args = oldArgs
		exitFunc = oldExit
	})

	reportHTMLPath := filepath.Join(dir, "report.html")
	reportJSONPath := filepath.Join(dir, "report.json")
	legalHTMLPath := filepath.Join(dir, "legal.html")
	vulnHTMLPath := filepath.Join(dir, "vuln.html")
	vulnJSONPath := filepath.Join(dir, "vuln.json")

	exitCode := -1
	exitFunc = func(code int) { exitCode = code }
	os.Args = []string{
		oldArgs[0],
		"-input", "repository-scan=internal/ci/testdata/repo",
		"-input", "cyclonedx-json=internal/sbom/testdata/cyclonedx/app.json",
		"-license-catalog", "configs/licenses.json",
		"-license-catalog", catalogServer.URL + "/licenses.json#sha256=" + requestedSHA,
		"-license-text-bundle", bundlePath,
		"-output-html", reportHTMLPath,
		"-output-json", reportJSONPath,
		"-output-legal-html", legalHTMLPath,
		"-output-vuln-html", vulnHTMLPath,
		"-output-vuln-json", vulnJSONPath,
		"-vuln-mode", "full",
		"-osv-base-url", vulnServer.URL,
		"-github-advisory-base-url", vulnServer.URL,
		"-nvd-base-url", vulnServer.URL,
	}

	main()

	if exitCode != -1 {
		t.Fatalf("unexpected exit code %d", exitCode)
	}
	for _, path := range []string{reportHTMLPath, reportJSONPath, legalHTMLPath, vulnHTMLPath, vulnJSONPath} {
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("expected output %s: %v", path, err)
		}
	}
}

func TestMainUsesRunWithoutExitingOnSPDXMultiSourceCustomizedSuccess(t *testing.T) {
	remoteBody := `{
  "licenses": [
    {
      "key": "MIT",
      "name": "MIT License (Main SPDX Multi Source Smoke Remote)",
      "family": "MIT",
      "copyleft_strength": "none",
      "requires_manual_review": false,
      "spdx_ids": ["MIT"],
      "names": ["MIT License (Main SPDX Multi Source Smoke Remote)"],
      "contains": ["mit"],
      "risk_level": "low",
      "notice_template": "main spdx multi source smoke remote notice"
    }
  ]
}`
	sum := sha256.Sum256([]byte(remoteBody))
	requestedSHA := strings.ToLower(fmt.Sprintf("%x", sum))

	catalogServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/licenses.json" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(remoteBody))
	}))
	defer catalogServer.Close()

	vulnServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/querybatch":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"results":[{"vulns":[{"id":"CVE-2026-5004"}]},{"vulns":[]},{"vulns":[]},{"vulns":[]},{"vulns":[]},{"vulns":[]}]} `))
		case "/advisories":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`[
  {
    "ghsa_id":"GHSA-react-main-spdx-multi-smoke-1",
    "cve_id":"CVE-2026-5004",
    "html_url":"https://github.com/advisories/GHSA-react-main-spdx-multi-smoke-1",
    "summary":"Main SPDX multi-source smoke advisory",
    "severity":"high",
    "updated_at":"2026-04-03T00:00:00Z"
  }
]`))
		case "/rest/json/cves/2.0":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{
  "vulnerabilities": [
    {
      "cve": {
        "id":"CVE-2026-5004",
        "metrics":{
          "cvssMetricV40":[{"type":"Primary","cvssData":{"baseScore":9.2,"baseSeverity":"CRITICAL","vectorString":"CVSS:4.0/..."}}]
        }
      }
    }
  ]
}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer vulnServer.Close()

	dir := t.TempDir()
	bundlePath := writeEnglishLicenseTextBundleFixtureWithMutation(t, dir, func(bundle map[string]any) {
		updateLicenseTextBundleEntry(bundle, "MIT", func(entry map[string]any) {
			entry["description"] = "Pinned layered MIT description"
			entry["obligations"] = []string{"Carry pinned layered MIT notice"}
		})
	})

	oldArgs := os.Args
	oldExit := exitFunc
	t.Cleanup(func() {
		os.Args = oldArgs
		exitFunc = oldExit
	})

	reportHTMLPath := filepath.Join(dir, "report.html")
	reportJSONPath := filepath.Join(dir, "report.json")
	legalHTMLPath := filepath.Join(dir, "legal.html")
	vulnHTMLPath := filepath.Join(dir, "vuln.html")
	vulnJSONPath := filepath.Join(dir, "vuln.json")

	exitCode := -1
	exitFunc = func(code int) { exitCode = code }
	os.Args = []string{
		oldArgs[0],
		"-input", "repository-scan=internal/ci/testdata/repo",
		"-input", "spdx-json=internal/sbom/testdata/spdx/app.json",
		"-license-catalog", "configs/licenses.json",
		"-license-catalog", catalogServer.URL + "/licenses.json#sha256=" + requestedSHA,
		"-license-text-bundle", bundlePath,
		"-output-html", reportHTMLPath,
		"-output-json", reportJSONPath,
		"-output-legal-html", legalHTMLPath,
		"-output-vuln-html", vulnHTMLPath,
		"-output-vuln-json", vulnJSONPath,
		"-vuln-mode", "full",
		"-osv-base-url", vulnServer.URL,
		"-github-advisory-base-url", vulnServer.URL,
		"-nvd-base-url", vulnServer.URL,
	}

	main()

	if exitCode != -1 {
		t.Fatalf("unexpected exit code %d", exitCode)
	}
	for _, path := range []string{reportHTMLPath, reportJSONPath, legalHTMLPath, vulnHTMLPath, vulnJSONPath} {
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("expected output %s: %v", path, err)
		}
	}
}

func TestMainAnnouncesCustomizedOutputsOnStdout(t *testing.T) {
	remoteBody := `{
  "licenses": [
    {
      "key": "MIT",
      "name": "MIT License (Main Stdout Remote)",
      "family": "MIT",
      "copyleft_strength": "none",
      "requires_manual_review": false,
      "spdx_ids": ["MIT"],
      "names": ["MIT License (Main Stdout Remote)"],
      "contains": ["mit"],
      "risk_level": "low",
      "notice_template": "main stdout remote notice"
    }
  ]
}`
	sum := sha256.Sum256([]byte(remoteBody))
	requestedSHA := strings.ToLower(fmt.Sprintf("%x", sum))

	catalogServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/licenses.json" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(remoteBody))
	}))
	defer catalogServer.Close()

	vulnServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/querybatch":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"results":[{"vulns":[{"id":"CVE-2026-5005"}]},{"vulns":[]},{"vulns":[]},{"vulns":[]}]} `))
		case "/advisories":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`[
  {
    "ghsa_id":"GHSA-react-main-stdout-1",
    "cve_id":"CVE-2026-5005",
    "html_url":"https://github.com/advisories/GHSA-react-main-stdout-1",
    "summary":"Main stdout advisory",
    "severity":"high",
    "updated_at":"2026-04-03T00:00:00Z"
  }
]`))
		case "/rest/json/cves/2.0":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{
  "vulnerabilities": [
    {
      "cve": {
        "id":"CVE-2026-5005",
        "metrics":{
          "cvssMetricV40":[{"type":"Primary","cvssData":{"baseScore":9.2,"baseSeverity":"CRITICAL","vectorString":"CVSS:4.0/..."}}]
        }
      }
    }
  ]
}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer vulnServer.Close()

	dir := t.TempDir()
	bundlePath := writeEnglishLicenseTextBundleFixtureWithMutation(t, dir, func(bundle map[string]any) {
		updateLicenseTextBundleEntry(bundle, "MIT", func(entry map[string]any) {
			entry["description"] = "Layered bundle MIT description"
			entry["obligations"] = []string{"Carry layered MIT notice"}
		})
	})

	oldArgs := os.Args
	oldExit := exitFunc
	oldStdout := os.Stdout
	t.Cleanup(func() {
		os.Args = oldArgs
		exitFunc = oldExit
		os.Stdout = oldStdout
	})

	reportHTMLPath := filepath.Join(dir, "report.html")
	reportJSONPath := filepath.Join(dir, "report.json")
	legalHTMLPath := filepath.Join(dir, "legal.html")
	vulnHTMLPath := filepath.Join(dir, "vuln.html")
	vulnJSONPath := filepath.Join(dir, "vuln.json")

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe stdout: %v", err)
	}
	defer r.Close()

	exitCode := -1
	exitFunc = func(code int) { exitCode = code }
	os.Stdout = w
	os.Args = []string{
		oldArgs[0],
		"-input", "repository-scan=internal/ci/testdata/repo",
		"-license-catalog", "configs/licenses.json",
		"-license-catalog", catalogServer.URL + "/licenses.json#sha256=" + requestedSHA,
		"-license-text-bundle", bundlePath,
		"-output-html", reportHTMLPath,
		"-output-json", reportJSONPath,
		"-output-legal-html", legalHTMLPath,
		"-output-vuln-html", vulnHTMLPath,
		"-output-vuln-json", vulnJSONPath,
		"-vuln-mode", "full",
		"-osv-base-url", vulnServer.URL,
		"-github-advisory-base-url", vulnServer.URL,
		"-nvd-base-url", vulnServer.URL,
	}

	main()
	_ = w.Close()
	stdoutBytes, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("read stdout: %v", err)
	}

	if exitCode != -1 {
		t.Fatalf("unexpected exit code %d", exitCode)
	}
	stdout := string(stdoutBytes)
	assertContainsAll(t, "stdout", stdout, expectedOutputAnnouncements(true, true)...)
}

func TestMainAnnouncesSPDXCustomizedOutputsOnStdout(t *testing.T) {
	remoteBody := `{
  "licenses": [
    {
      "key": "MIT",
      "name": "MIT License (Main SPDX Stdout Remote)",
      "family": "MIT",
      "copyleft_strength": "none",
      "requires_manual_review": false,
      "spdx_ids": ["MIT"],
      "names": ["MIT License (Main SPDX Stdout Remote)"],
      "contains": ["mit"],
      "risk_level": "low",
      "notice_template": "main spdx stdout remote notice"
    }
  ]
}`
	sum := sha256.Sum256([]byte(remoteBody))
	requestedSHA := strings.ToLower(fmt.Sprintf("%x", sum))

	catalogServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/licenses.json" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(remoteBody))
	}))
	defer catalogServer.Close()

	vulnServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/querybatch":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"results":[{"vulns":[{"id":"CVE-2026-5006"}]},{"vulns":[]},{"vulns":[]},{"vulns":[]}]} `))
		case "/advisories":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`[
  {
    "ghsa_id":"GHSA-react-main-spdx-stdout-1",
    "cve_id":"CVE-2026-5006",
    "html_url":"https://github.com/advisories/GHSA-react-main-spdx-stdout-1",
    "summary":"Main SPDX stdout advisory",
    "severity":"high",
    "updated_at":"2026-04-03T00:00:00Z"
  }
]`))
		case "/rest/json/cves/2.0":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{
  "vulnerabilities": [
    {
      "cve": {
        "id":"CVE-2026-5006",
        "metrics":{
          "cvssMetricV40":[{"type":"Primary","cvssData":{"baseScore":9.2,"baseSeverity":"CRITICAL","vectorString":"CVSS:4.0/..."}}]
        }
      }
    }
  ]
}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer vulnServer.Close()

	dir := t.TempDir()
	bundlePath := writeEnglishLicenseTextBundleFixtureWithMutation(t, dir, func(bundle map[string]any) {
		updateLicenseTextBundleEntry(bundle, "MIT", func(entry map[string]any) {
			entry["description"] = "Pinned layered MIT description"
			entry["obligations"] = []string{"Carry pinned layered MIT notice"}
		})
	})

	oldArgs := os.Args
	oldExit := exitFunc
	oldStdout := os.Stdout
	t.Cleanup(func() {
		os.Args = oldArgs
		exitFunc = oldExit
		os.Stdout = oldStdout
	})

	reportHTMLPath := filepath.Join(dir, "report.html")
	reportJSONPath := filepath.Join(dir, "report.json")
	legalHTMLPath := filepath.Join(dir, "legal.html")
	vulnHTMLPath := filepath.Join(dir, "vuln.html")
	vulnJSONPath := filepath.Join(dir, "vuln.json")

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe stdout: %v", err)
	}
	defer r.Close()

	exitCode := -1
	exitFunc = func(code int) { exitCode = code }
	os.Stdout = w
	os.Args = []string{
		oldArgs[0],
		"-input", "spdx-json=internal/sbom/testdata/spdx/app.json",
		"-license-catalog", "configs/licenses.json",
		"-license-catalog", catalogServer.URL + "/licenses.json#sha256=" + requestedSHA,
		"-license-text-bundle", bundlePath,
		"-output-html", reportHTMLPath,
		"-output-json", reportJSONPath,
		"-output-legal-html", legalHTMLPath,
		"-output-vuln-html", vulnHTMLPath,
		"-output-vuln-json", vulnJSONPath,
		"-vuln-mode", "full",
		"-osv-base-url", vulnServer.URL,
		"-github-advisory-base-url", vulnServer.URL,
		"-nvd-base-url", vulnServer.URL,
	}

	main()
	_ = w.Close()
	stdoutBytes, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("read stdout: %v", err)
	}

	if exitCode != -1 {
		t.Fatalf("unexpected exit code %d", exitCode)
	}
	stdout := string(stdoutBytes)
	assertContainsAll(t, "stdout", stdout, expectedOutputAnnouncements(true, true)...)
}

func TestMainAnnouncesMultiSourceCustomizedOutputsOnStdout(t *testing.T) {
	remoteBody := `{
  "licenses": [
    {
      "key": "MIT",
      "name": "MIT License (Main Multi Source Stdout Remote)",
      "family": "MIT",
      "copyleft_strength": "none",
      "requires_manual_review": false,
      "spdx_ids": ["MIT"],
      "names": ["MIT License (Main Multi Source Stdout Remote)"],
      "contains": ["mit"],
      "risk_level": "low",
      "notice_template": "main multi source stdout remote notice"
    }
  ]
}`
	sum := sha256.Sum256([]byte(remoteBody))
	requestedSHA := strings.ToLower(fmt.Sprintf("%x", sum))

	catalogServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/licenses.json" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(remoteBody))
	}))
	defer catalogServer.Close()

	vulnServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/querybatch":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"results":[{"vulns":[{"id":"CVE-2026-5007"}]},{"vulns":[]},{"vulns":[]},{"vulns":[]},{"vulns":[]},{"vulns":[]}]} `))
		case "/advisories":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`[
  {
    "ghsa_id":"GHSA-react-main-multi-stdout-1",
    "cve_id":"CVE-2026-5007",
    "html_url":"https://github.com/advisories/GHSA-react-main-multi-stdout-1",
    "summary":"Main multi-source stdout advisory",
    "severity":"high",
    "updated_at":"2026-04-03T00:00:00Z"
  }
]`))
		case "/rest/json/cves/2.0":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{
  "vulnerabilities": [
    {
      "cve": {
        "id":"CVE-2026-5007",
        "metrics":{
          "cvssMetricV40":[{"type":"Primary","cvssData":{"baseScore":9.2,"baseSeverity":"CRITICAL","vectorString":"CVSS:4.0/..."}}]
        }
      }
    }
  ]
}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer vulnServer.Close()

	dir := t.TempDir()
	bundlePath := writeEnglishLicenseTextBundleFixtureWithMutation(t, dir, func(bundle map[string]any) {
		updateLicenseTextBundleEntry(bundle, "MIT", func(entry map[string]any) {
			entry["description"] = "Pinned multi-source MIT description"
			entry["obligations"] = []string{"Carry pinned multi-source MIT notice"}
		})
	})

	oldArgs := os.Args
	oldExit := exitFunc
	oldStdout := os.Stdout
	t.Cleanup(func() {
		os.Args = oldArgs
		exitFunc = oldExit
		os.Stdout = oldStdout
	})

	reportHTMLPath := filepath.Join(dir, "report.html")
	reportJSONPath := filepath.Join(dir, "report.json")
	legalHTMLPath := filepath.Join(dir, "legal.html")
	vulnHTMLPath := filepath.Join(dir, "vuln.html")
	vulnJSONPath := filepath.Join(dir, "vuln.json")

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe stdout: %v", err)
	}
	defer r.Close()

	exitCode := -1
	exitFunc = func(code int) { exitCode = code }
	os.Stdout = w
	os.Args = []string{
		oldArgs[0],
		"-input", "repository-scan=internal/ci/testdata/repo",
		"-input", "cyclonedx-json=internal/sbom/testdata/cyclonedx/app.json",
		"-license-catalog", "configs/licenses.json",
		"-license-catalog", catalogServer.URL + "/licenses.json#sha256=" + requestedSHA,
		"-license-text-bundle", bundlePath,
		"-output-html", reportHTMLPath,
		"-output-json", reportJSONPath,
		"-output-legal-html", legalHTMLPath,
		"-output-vuln-html", vulnHTMLPath,
		"-output-vuln-json", vulnJSONPath,
		"-vuln-mode", "full",
		"-osv-base-url", vulnServer.URL,
		"-github-advisory-base-url", vulnServer.URL,
		"-nvd-base-url", vulnServer.URL,
	}

	main()
	_ = w.Close()
	stdoutBytes, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("read stdout: %v", err)
	}

	if exitCode != -1 {
		t.Fatalf("unexpected exit code %d", exitCode)
	}
	stdout := string(stdoutBytes)
	for _, want := range []string{
		"generated HTML",
		"generated legal notice HTML",
		"generated JSON",
		"generated vulnerability HTML",
		"generated vulnerability JSON",
	} {
		if !strings.Contains(stdout, want) {
			t.Fatalf("stdout missing %q\n%s", want, stdout)
		}
	}
}

func TestMainAnnouncesSPDXMultiSourceCustomizedOutputsOnStdout(t *testing.T) {
	remoteBody := `{
  "licenses": [
    {
      "key": "MIT",
      "name": "MIT License (Main SPDX Multi Source Stdout Remote)",
      "family": "MIT",
      "copyleft_strength": "none",
      "requires_manual_review": false,
      "spdx_ids": ["MIT"],
      "names": ["MIT License (Main SPDX Multi Source Stdout Remote)"],
      "contains": ["mit"],
      "risk_level": "low",
      "notice_template": "main spdx multi source stdout remote notice"
    }
  ]
}`
	sum := sha256.Sum256([]byte(remoteBody))
	requestedSHA := strings.ToLower(fmt.Sprintf("%x", sum))

	catalogServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/licenses.json" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(remoteBody))
	}))
	defer catalogServer.Close()

	vulnServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/querybatch":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"results":[{"vulns":[{"id":"CVE-2026-5008"}]},{"vulns":[]},{"vulns":[]},{"vulns":[]},{"vulns":[]},{"vulns":[]}]} `))
		case "/advisories":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`[
  {
    "ghsa_id":"GHSA-react-main-spdx-multi-stdout-1",
    "cve_id":"CVE-2026-5008",
    "html_url":"https://github.com/advisories/GHSA-react-main-spdx-multi-stdout-1",
    "summary":"Main SPDX multi-source stdout advisory",
    "severity":"high",
    "updated_at":"2026-04-03T00:00:00Z"
  }
]`))
		case "/rest/json/cves/2.0":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{
  "vulnerabilities": [
    {
      "cve": {
        "id":"CVE-2026-5008",
        "metrics":{
          "cvssMetricV40":[{"type":"Primary","cvssData":{"baseScore":9.2,"baseSeverity":"CRITICAL","vectorString":"CVSS:4.0/..."}}]
        }
      }
    }
  ]
}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer vulnServer.Close()

	dir := t.TempDir()
	bundlePath := writeEnglishLicenseTextBundleFixtureWithMutation(t, dir, func(bundle map[string]any) {
		updateLicenseTextBundleEntry(bundle, "MIT", func(entry map[string]any) {
			entry["description"] = "Pinned SPDX MIT description"
			entry["obligations"] = []string{"Carry pinned SPDX MIT notice"}
		})
	})

	oldArgs := os.Args
	oldExit := exitFunc
	oldStdout := os.Stdout
	t.Cleanup(func() {
		os.Args = oldArgs
		exitFunc = oldExit
		os.Stdout = oldStdout
	})

	reportHTMLPath := filepath.Join(dir, "report.html")
	reportJSONPath := filepath.Join(dir, "report.json")
	legalHTMLPath := filepath.Join(dir, "legal.html")
	vulnHTMLPath := filepath.Join(dir, "vuln.html")
	vulnJSONPath := filepath.Join(dir, "vuln.json")

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe stdout: %v", err)
	}
	defer r.Close()

	exitCode := -1
	exitFunc = func(code int) { exitCode = code }
	os.Stdout = w
	os.Args = []string{
		oldArgs[0],
		"-input", "repository-scan=internal/ci/testdata/repo",
		"-input", "spdx-json=internal/sbom/testdata/spdx/app.json",
		"-license-catalog", "configs/licenses.json",
		"-license-catalog", catalogServer.URL + "/licenses.json#sha256=" + requestedSHA,
		"-license-text-bundle", bundlePath,
		"-output-html", reportHTMLPath,
		"-output-json", reportJSONPath,
		"-output-legal-html", legalHTMLPath,
		"-output-vuln-html", vulnHTMLPath,
		"-output-vuln-json", vulnJSONPath,
		"-vuln-mode", "full",
		"-osv-base-url", vulnServer.URL,
		"-github-advisory-base-url", vulnServer.URL,
		"-nvd-base-url", vulnServer.URL,
	}

	main()
	_ = w.Close()
	stdoutBytes, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("read stdout: %v", err)
	}

	if exitCode != -1 {
		t.Fatalf("unexpected exit code %d", exitCode)
	}
	stdout := string(stdoutBytes)
	for _, want := range []string{
		"generated HTML",
		"generated legal notice HTML",
		"generated JSON",
		"generated vulnerability HTML",
		"generated vulnerability JSON",
	} {
		if !strings.Contains(stdout, want) {
			t.Fatalf("stdout missing %q\n%s", want, stdout)
		}
	}
}
