package main

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"depaudit-license/internal/testutil"
)

func writeEnglishLicenseTextBundleFixture(t *testing.T, dir string) string {
	return writeEnglishLicenseTextBundleFixtureWithMutation(t, dir, nil)
}

func writeEnglishLicenseTextBundleFixtureWithMutation(t *testing.T, dir string, mutate func(map[string]any)) string {
	t.Helper()

	baseBundlePayload, err := os.ReadFile(filepath.Join("configs", "license-texts.ja.json"))
	if err != nil {
		t.Fatalf("read base bundle: %v", err)
	}

	var bundle map[string]any
	if err := json.Unmarshal(baseBundlePayload, &bundle); err != nil {
		t.Fatalf("parse base bundle: %v", err)
	}
	bundle["locale"] = "en-US"
	if mutate != nil {
		mutate(bundle)
	}

	bundlePath := filepath.Join(dir, "license-texts.en.json")
	testutil.WriteIndentedJSONFixture(t, bundlePath, bundle)
	return bundlePath
}

func updateLicenseTextBundleEntry(bundle map[string]any, key string, mutate func(map[string]any)) {
	licenses, ok := bundle["licenses"].([]any)
	if !ok {
		return
	}
	for _, raw := range licenses {
		entry, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		if entryKey, _ := entry["key"].(string); entryKey == key {
			mutate(entry)
		}
	}
}

func TestRunGeneratesOutputs(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	outputs := newCLIOutputPaths(dir)

	var stdout bytes.Buffer
	args := append([]string{"-input", "repository-scan=internal/ci/testdata/repo"}, outputs.baseArgs()...)
	err := run(args, &stdout)
	if err != nil {
		t.Fatalf("run failed: %v", err)
	}
	for _, path := range []string{outputs.HTML, outputs.JSON, outputs.LegalHTML} {
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("expected output %s: %v", path, err)
		}
	}
	if !strings.Contains(stdout.String(), "generated HTML") {
		t.Fatalf("unexpected stdout: %s", stdout.String())
	}
}

func TestRunCopiesEmbeddedLicenseFiles(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	repo := filepath.Join(dir, "repo")
	packageDir := filepath.Join(repo, "node_modules", "file-licensed")
	if err := os.MkdirAll(packageDir, 0o755); err != nil {
		t.Fatalf("mkdir package dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(repo, "package.json"), []byte(`{
  "name": "app",
  "dependencies": {
    "file-licensed": "1.0.0"
  }
}`), 0o644); err != nil {
		t.Fatalf("write app package.json: %v", err)
	}
	if err := os.WriteFile(filepath.Join(packageDir, "package.json"), []byte(`{
  "name": "file-licensed",
  "version": "1.0.0",
  "license": "LICENSE.txt"
}`), 0o644); err != nil {
		t.Fatalf("write dependency package.json: %v", err)
	}
	if err := os.WriteFile(filepath.Join(packageDir, "LICENSE.txt"), []byte("MIT License\n\nPermission is hereby granted"), 0o644); err != nil {
		t.Fatalf("write license file: %v", err)
	}

	outputs := newCLIOutputPaths(filepath.Join(dir, "out"))
	var stdout bytes.Buffer
	args := append([]string{"-input", "repository-scan=" + repo}, outputs.baseArgs()...)
	if err := run(args, &stdout); err != nil {
		t.Fatalf("run failed: %v", err)
	}

	legalHTML, err := os.ReadFile(outputs.LegalHTML)
	if err != nil {
		t.Fatalf("read legal html: %v", err)
	}
	if !strings.Contains(string(legalHTML), "Copied license text") {
		t.Fatalf("expected copied license link in legal html: %s", string(legalHTML))
	}

	copiedFiles, err := filepath.Glob(filepath.Join(filepath.Dir(outputs.LegalHTML), "license-texts", "node", "app", "file-licensed", "1-0-0", "license-*.txt"))
	if err != nil {
		t.Fatalf("glob copied licenses: %v", err)
	}
	if len(copiedFiles) != 1 {
		t.Fatalf("copied files = %#v", copiedFiles)
	}
	copiedText, err := os.ReadFile(copiedFiles[0])
	if err != nil {
		t.Fatalf("read copied license: %v", err)
	}
	if string(copiedText) != "MIT License\n\nPermission is hereby granted" {
		t.Fatalf("copied text = %q", string(copiedText))
	}
}

func TestRunStdoutAnnouncesGeneratedOutputs(t *testing.T) {
	t.Parallel()

	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/querybatch" {
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"results":[{"vulns":[]},{"vulns":[]},{"vulns":[]},{"vulns":[]}]}`))
	}))
	defer server.Close()

	dir := t.TempDir()
	outputs := newCLIOutputPaths(dir)
	var stdout bytes.Buffer
	args := append([]string{
		"-input", "repository-scan=internal/ci/testdata/repo",
		"-output-vuln-json", outputs.VulnJSON,
		"-osv-base-url", server.URL,
	}, outputs.baseArgs()...)
	if err := run(args, &stdout); err != nil {
		t.Fatalf("run with stdout contract outputs failed: %v", err)
	}

	assertContainsAll(t, "stdout", stdout.String(), expectedOutputAnnouncements(false, true)...)
	if strings.Contains(stdout.String(), "generated vulnerability HTML") {
		t.Fatalf("unexpected vulnerability html announcement in stdout: %s", stdout.String())
	}
}

func TestRunStdoutAnnouncesFullOutputs(t *testing.T) {
	t.Parallel()

	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/querybatch":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"results":[{"vulns":[{"id":"CVE-2026-0002"}]},{"vulns":[]},{"vulns":[]},{"vulns":[]}]} `))
		case "/advisories":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`[
  {
    "ghsa_id":"GHSA-react-stdout-1",
    "cve_id":"CVE-2026-0002",
    "html_url":"https://github.com/advisories/GHSA-react-stdout-1",
    "summary":"Stdout advisory",
    "severity":"high",
    "updated_at":"2026-04-02T00:00:00Z"
  }
]`))
		case "/rest/json/cves/2.0":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{
  "vulnerabilities": [
    {
      "cve": {
        "id":"CVE-2026-0002",
        "metrics":{
          "cvssMetricV40":[{"type":"Primary","cvssData":{"baseScore":9.1,"baseSeverity":"CRITICAL","vectorString":"CVSS:4.0/..."}}]
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

	dir := t.TempDir()
	var stdout bytes.Buffer
	if err := run([]string{
		"-input", "repository-scan=internal/ci/testdata/repo",
		"-output-html", filepath.Join(dir, "report.html"),
		"-output-json", filepath.Join(dir, "report.json"),
		"-output-legal-html", filepath.Join(dir, "legal.html"),
		"-output-vuln-html", filepath.Join(dir, "vuln.html"),
		"-output-vuln-json", filepath.Join(dir, "vuln.json"),
		"-vuln-mode", "full",
		"-osv-base-url", server.URL,
		"-github-advisory-base-url", server.URL,
		"-nvd-base-url", server.URL,
	}, &stdout); err != nil {
		t.Fatalf("run with full stdout contract outputs failed: %v", err)
	}

	assertContainsAll(t, "stdout", stdout.String(),
		append(expectedOutputAnnouncements(true, true), "vulnerability advisories:", "packages:", "licenses:")...,
	)
}

func TestRunReleaseSmokeMatrix(t *testing.T) {
	t.Parallel()

	osvServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/querybatch" {
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"results":[{"vulns":[]},{"vulns":[]},{"vulns":[]},{"vulns":[]},{"vulns":[]},{"vulns":[]} ]}`))
	}))
	defer osvServer.Close()

	cases := []struct {
		name       string
		args       []string
		checkPaths []string
	}{
		{
			name: "repository-scan",
			args: []string{
				"-input", "repository-scan=internal/ci/testdata/repo",
			},
			checkPaths: []string{"report.html", "report.json", "legal.html"},
		},
		{
			name: "cyclonedx",
			args: []string{
				"-input", "cyclonedx-json=internal/sbom/testdata/cyclonedx/app.json",
			},
			checkPaths: []string{"report.html", "report.json", "legal.html"},
		},
		{
			name: "spdx",
			args: []string{
				"-input", "spdx-json=internal/sbom/testdata/spdx/app.json",
			},
			checkPaths: []string{"report.html", "report.json", "legal.html"},
		},
		{
			name: "multi-source-vulnerability",
			args: []string{
				"-input", "repository-scan=internal/ci/testdata/repo",
				"-input", "cyclonedx-json=internal/sbom/testdata/cyclonedx/app.json",
				"-output-vuln-json", "vuln.json",
				"-osv-base-url", osvServer.URL,
			},
			checkPaths: []string{"report.html", "report.json", "legal.html", "vuln.json"},
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			args := append([]string{}, tc.args...)
			args = append(args,
				"-output-html", filepath.Join(dir, "report.html"),
				"-output-json", filepath.Join(dir, "report.json"),
				"-output-legal-html", filepath.Join(dir, "legal.html"),
			)

			for i := 0; i < len(args)-1; i += 2 {
				if strings.HasPrefix(args[i], "-output-") && !filepath.IsAbs(args[i+1]) {
					args[i+1] = filepath.Join(dir, args[i+1])
				}
			}

			if err := run(args, &bytes.Buffer{}); err != nil {
				t.Fatalf("run failed: %v", err)
			}
			for _, rel := range tc.checkPaths {
				if _, err := os.Stat(filepath.Join(dir, rel)); err != nil {
					t.Fatalf("expected output %s: %v", rel, err)
				}
			}
		})
	}
}

func TestRunCustomizedFullPipelineSmoke(t *testing.T) {
	t.Parallel()

	remoteBody := `{
  "licenses": [
    {
      "key": "MIT",
      "name": "MIT License (Smoke Remote)",
      "family": "MIT",
      "copyleft_strength": "none",
      "requires_manual_review": false,
      "spdx_ids": ["MIT"],
      "names": ["MIT License (Smoke Remote)"],
      "contains": ["mit"],
      "risk_level": "low",
      "notice_template": "smoke remote notice"
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
			_, _ = w.Write([]byte(`{"results":[{"vulns":[{"id":"CVE-2026-4001"}]},{"vulns":[]},{"vulns":[]},{"vulns":[]}]} `))
		case "/advisories":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`[
  {
    "ghsa_id":"GHSA-react-smoke-1",
    "cve_id":"CVE-2026-4001",
    "html_url":"https://github.com/advisories/GHSA-react-smoke-1",
    "summary":"Smoke advisory",
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
        "id":"CVE-2026-4001",
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

	reportHTMLPath := filepath.Join(dir, "report.html")
	reportJSONPath := filepath.Join(dir, "report.json")
	legalHTMLPath := filepath.Join(dir, "legal.html")
	vulnHTMLPath := filepath.Join(dir, "vuln.html")
	vulnJSONPath := filepath.Join(dir, "vuln.json")

	if err := run([]string{
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
	}, &bytes.Buffer{}); err != nil {
		t.Fatalf("run customized full pipeline smoke failed: %v", err)
	}

	for _, path := range []string{reportHTMLPath, reportJSONPath, legalHTMLPath, vulnHTMLPath, vulnJSONPath} {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatalf("stat %s: %v", path, err)
		}
		if info.Size() == 0 {
			t.Fatalf("empty output: %s", path)
		}
	}
}

func TestRunSPDXCustomizedFullPipelineSmoke(t *testing.T) {
	t.Parallel()

	remoteBody := `{
  "licenses": [
    {
      "key": "MIT",
      "name": "MIT License (SPDX Smoke Remote)",
      "family": "MIT",
      "copyleft_strength": "none",
      "requires_manual_review": false,
      "spdx_ids": ["MIT"],
      "names": ["MIT License (SPDX Smoke Remote)"],
      "contains": ["mit"],
      "risk_level": "low",
      "notice_template": "spdx smoke remote notice"
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
			_, _ = w.Write([]byte(`{"results":[{"vulns":[{"id":"CVE-2026-4002"}]},{"vulns":[]},{"vulns":[]},{"vulns":[]},{"vulns":[]},{"vulns":[]}]} `))
		case "/advisories":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`[
  {
    "ghsa_id":"GHSA-react-spdx-smoke-1",
    "cve_id":"CVE-2026-4002",
    "html_url":"https://github.com/advisories/GHSA-react-spdx-smoke-1",
    "summary":"SPDX smoke advisory",
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
        "id":"CVE-2026-4002",
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

	reportHTMLPath := filepath.Join(dir, "report.html")
	reportJSONPath := filepath.Join(dir, "report.json")
	legalHTMLPath := filepath.Join(dir, "legal.html")
	vulnHTMLPath := filepath.Join(dir, "vuln.html")
	vulnJSONPath := filepath.Join(dir, "vuln.json")

	if err := run([]string{
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
	}, &bytes.Buffer{}); err != nil {
		t.Fatalf("run SPDX customized full pipeline smoke failed: %v", err)
	}

	for _, path := range []string{reportHTMLPath, reportJSONPath, legalHTMLPath, vulnHTMLPath, vulnJSONPath} {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatalf("stat %s: %v", path, err)
		}
		if info.Size() == 0 {
			t.Fatalf("empty output: %s", path)
		}
	}
}

func TestExitOnErrorWritesMessageAndExits(t *testing.T) {
	oldExit := exitFunc
	oldStderr := stderrOut
	t.Cleanup(func() {
		exitFunc = oldExit
		stderrOut = oldStderr
	})

	var stderr bytes.Buffer
	exitCode := -1
	exitFunc = func(code int) { exitCode = code }
	stderrOut = &stderr

	exitOnError(assertBoom())

	if exitCode != 1 {
		t.Fatalf("exit code = %d", exitCode)
	}
	if !strings.Contains(stderr.String(), "error: boom") {
		t.Fatalf("stderr = %q", stderr.String())
	}
}

func TestMainWritesErrorAndExitsForInvalidCatalog(t *testing.T) {
	dir := t.TempDir()
	invalidCatalog := filepath.Join(dir, "invalid-catalog.json")
	if err := os.WriteFile(invalidCatalog, []byte(`{invalid`), 0o644); err != nil {
		t.Fatalf("write invalid catalog: %v", err)
	}

	oldArgs := os.Args
	oldExit := exitFunc
	oldStderr := stderrOut
	t.Cleanup(func() {
		os.Args = oldArgs
		exitFunc = oldExit
		stderrOut = oldStderr
	})

	var stderr bytes.Buffer
	exitCode := -1
	exitFunc = func(code int) { exitCode = code }
	stderrOut = &stderr
	os.Args = []string{
		oldArgs[0],
		"-input", "repository-scan=internal/ci/testdata/repo",
		"-license-catalog", invalidCatalog,
	}

	main()

	if exitCode != 1 {
		t.Fatalf("exit code = %d", exitCode)
	}
	if !strings.Contains(stderr.String(), "error:") || !strings.Contains(stderr.String(), "invalid") {
		t.Fatalf("stderr = %q", stderr.String())
	}
}

func TestMainWritesErrorAndExitsForRemoteCatalogFailFastWithStaleCache(t *testing.T) {
	cacheDir := t.TempDir()
	remoteBody := `{
  "licenses":[
    {
      "key":"MIT",
      "name":"MIT License (Main Fail Fast Remote)",
      "family":"Permissive",
      "version":"",
      "copyleft_strength":"none",
      "requires_manual_review":false,
      "spdx_ids":["MIT"],
      "names":["MIT License","MIT License (Main Fail Fast Remote)"],
      "exact_urls":[],
      "url_prefixes":[],
      "contains":["mit license"],
      "color":"#22c55e",
      "risk_level":"low",
      "notice_template":"main fail fast remote notice"
    }
  ]
}`
	catalogServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(remoteBody))
	}))
	source := catalogServer.URL + "/licenses.json"

	primeDir := t.TempDir()
	if err := run([]string{
		"-input", "repository-scan=internal/ci/testdata/repo",
		"-license-catalog", "configs/licenses.json",
		"-license-catalog", source,
		"-remote-catalog-mode", "stale-fallback",
		"-remote-catalog-cache-dir", cacheDir,
		"-output-html", filepath.Join(primeDir, "report.html"),
		"-output-json", filepath.Join(primeDir, "report.json"),
		"-output-legal-html", filepath.Join(primeDir, "legal.html"),
	}, io.Discard); err != nil {
		t.Fatalf("prime remote catalog cache: %v", err)
	}
	catalogServer.Close()

	oldArgs := os.Args
	oldExit := exitFunc
	oldStderr := stderrOut
	t.Cleanup(func() {
		os.Args = oldArgs
		exitFunc = oldExit
		stderrOut = oldStderr
	})

	var stderr bytes.Buffer
	exitCode := -1
	exitFunc = func(code int) { exitCode = code }
	stderrOut = &stderr
	os.Args = []string{
		oldArgs[0],
		"-input", "repository-scan=internal/ci/testdata/repo",
		"-license-catalog", "configs/licenses.json",
		"-license-catalog", source,
		"-remote-catalog-mode", "fail-fast",
		"-remote-catalog-cache-dir", cacheDir,
		"-output-html", filepath.Join(t.TempDir(), "report.html"),
		"-output-json", filepath.Join(t.TempDir(), "report.json"),
		"-output-legal-html", filepath.Join(t.TempDir(), "legal.html"),
	}

	main()

	if exitCode != 1 {
		t.Fatalf("exit code = %d", exitCode)
	}
	if !strings.Contains(stderr.String(), "error:") || !strings.Contains(stderr.String(), source) {
		t.Fatalf("stderr = %q", stderr.String())
	}
}

func TestMainWritesErrorAndExitsForInvalidBundle(t *testing.T) {
	dir := t.TempDir()
	invalidBundle := filepath.Join(dir, "invalid-bundle.json")
	if err := os.WriteFile(invalidBundle, []byte(`{invalid`), 0o644); err != nil {
		t.Fatalf("write invalid bundle: %v", err)
	}

	oldArgs := os.Args
	oldExit := exitFunc
	oldStderr := stderrOut
	t.Cleanup(func() {
		os.Args = oldArgs
		exitFunc = oldExit
		stderrOut = oldStderr
	})

	var stderr bytes.Buffer
	exitCode := -1
	exitFunc = func(code int) { exitCode = code }
	stderrOut = &stderr
	os.Args = []string{
		oldArgs[0],
		"-input", "repository-scan=internal/ci/testdata/repo",
		"-license-text-bundle", invalidBundle,
	}

	main()

	if exitCode != 1 {
		t.Fatalf("exit code = %d", exitCode)
	}
	if !strings.Contains(stderr.String(), "error:") || !strings.Contains(stderr.String(), "invalid") {
		t.Fatalf("stderr = %q", stderr.String())
	}
}

func TestMainWritesErrorAndExitsForInvalidVulnerabilityMode(t *testing.T) {
	oldArgs := os.Args
	oldExit := exitFunc
	oldStderr := stderrOut
	t.Cleanup(func() {
		os.Args = oldArgs
		exitFunc = oldExit
		stderrOut = oldStderr
	})

	var stderr bytes.Buffer
	exitCode := -1
	exitFunc = func(code int) { exitCode = code }
	stderrOut = &stderr
	os.Args = []string{
		oldArgs[0],
		"-input", "repository-scan=internal/ci/testdata/repo",
		"-vuln-mode", "weird",
	}

	main()

	if exitCode != 1 {
		t.Fatalf("exit code = %d", exitCode)
	}
	if !strings.Contains(stderr.String(), "error: unsupported vulnerability mode") {
		t.Fatalf("stderr = %q", stderr.String())
	}
}

func TestMainWritesErrorAndExitsWhenVulnerabilityModeLacksOutputs(t *testing.T) {
	oldArgs := os.Args
	oldExit := exitFunc
	oldStderr := stderrOut
	t.Cleanup(func() {
		os.Args = oldArgs
		exitFunc = oldExit
		stderrOut = oldStderr
	})

	var stderr bytes.Buffer
	exitCode := -1
	exitFunc = func(code int) { exitCode = code }
	stderrOut = &stderr
	os.Args = []string{
		oldArgs[0],
		"-input", "repository-scan=internal/ci/testdata/repo",
		"-vuln-mode", "full",
	}

	main()

	if exitCode != 1 {
		t.Fatalf("exit code = %d", exitCode)
	}
	if !strings.Contains(stderr.String(), "error: vulnerability outputs must be configured") {
		t.Fatalf("stderr = %q", stderr.String())
	}
}

func TestMainWritesErrorAndExitsForInvalidInputSyntax(t *testing.T) {
	oldArgs := os.Args
	oldExit := exitFunc
	oldStderr := stderrOut
	t.Cleanup(func() {
		os.Args = oldArgs
		exitFunc = oldExit
		stderrOut = oldStderr
	})

	var stderr bytes.Buffer
	exitCode := -1
	exitFunc = func(code int) { exitCode = code }
	stderrOut = &stderr
	os.Args = []string{
		oldArgs[0],
		"-input", "cyclonedx-json",
	}

	main()

	if exitCode != 1 {
		t.Fatalf("exit code = %d", exitCode)
	}
	if !strings.Contains(stderr.String(), "error: invalid -input") {
		t.Fatalf("stderr = %q", stderr.String())
	}
}

func TestMainWritesErrorAndExitsForUnsupportedInputKind(t *testing.T) {
	oldArgs := os.Args
	oldExit := exitFunc
	oldStderr := stderrOut
	t.Cleanup(func() {
		os.Args = oldArgs
		exitFunc = oldExit
		stderrOut = oldStderr
	})

	var stderr bytes.Buffer
	exitCode := -1
	exitFunc = func(code int) { exitCode = code }
	stderrOut = &stderr
	os.Args = []string{
		oldArgs[0],
		"-input", "unknown=.",
	}

	main()

	if exitCode != 1 {
		t.Fatalf("exit code = %d", exitCode)
	}
	if !strings.Contains(stderr.String(), `error: unsupported input kind "unknown"`) {
		t.Fatalf("stderr = %q", stderr.String())
	}
}

func TestMainWritesErrorAndExitsForMissingCycloneDXInput(t *testing.T) {
	oldArgs := os.Args
	oldExit := exitFunc
	oldStderr := stderrOut
	t.Cleanup(func() {
		os.Args = oldArgs
		exitFunc = oldExit
		stderrOut = oldStderr
	})

	var stderr bytes.Buffer
	exitCode := -1
	exitFunc = func(code int) { exitCode = code }
	stderrOut = &stderr
	os.Args = []string{
		oldArgs[0],
		"-input", "cyclonedx-json=missing-cdx.json",
	}

	main()

	if exitCode != 1 {
		t.Fatalf("exit code = %d", exitCode)
	}
	if !strings.Contains(stderr.String(), "error:") || !strings.Contains(stderr.String(), "missing-cdx.json") {
		t.Fatalf("stderr = %q", stderr.String())
	}
}

func TestMainWritesErrorAndExitsForMissingSPDXInput(t *testing.T) {
	oldArgs := os.Args
	oldExit := exitFunc
	oldStderr := stderrOut
	t.Cleanup(func() {
		os.Args = oldArgs
		exitFunc = oldExit
		stderrOut = oldStderr
	})

	var stderr bytes.Buffer
	exitCode := -1
	exitFunc = func(code int) { exitCode = code }
	stderrOut = &stderr
	os.Args = []string{
		oldArgs[0],
		"-input", "spdx-json=missing-spdx.json",
	}

	main()

	if exitCode != 1 {
		t.Fatalf("exit code = %d", exitCode)
	}
	if !strings.Contains(stderr.String(), "error:") || !strings.Contains(stderr.String(), "missing-spdx.json") {
		t.Fatalf("stderr = %q", stderr.String())
	}
}

func TestMainWritesErrorAndExitsForMissingRepositoryScanInput(t *testing.T) {
	oldArgs := os.Args
	oldExit := exitFunc
	oldStderr := stderrOut
	t.Cleanup(func() {
		os.Args = oldArgs
		exitFunc = oldExit
		stderrOut = oldStderr
	})

	var stderr bytes.Buffer
	exitCode := -1
	exitFunc = func(code int) { exitCode = code }
	stderrOut = &stderr
	os.Args = []string{
		oldArgs[0],
		"-input", "repository-scan=missing-repo",
	}

	main()

	if exitCode != 1 {
		t.Fatalf("exit code = %d", exitCode)
	}
	if !strings.Contains(stderr.String(), "error:") || !strings.Contains(stderr.String(), "missing-repo") {
		t.Fatalf("stderr = %q", stderr.String())
	}
}

func TestMainWritesErrorAndExitsForUnknownFlag(t *testing.T) {
	oldArgs := os.Args
	oldExit := exitFunc
	oldStderr := stderrOut
	t.Cleanup(func() {
		os.Args = oldArgs
		exitFunc = oldExit
		stderrOut = oldStderr
	})

	var stderr bytes.Buffer
	exitCode := -1
	exitFunc = func(code int) { exitCode = code }
	stderrOut = &stderr
	os.Args = []string{
		oldArgs[0],
		"-unknown-flag",
	}

	main()

	if exitCode != 1 {
		t.Fatalf("exit code = %d", exitCode)
	}
	if !strings.Contains(stderr.String(), `error: flag provided but not defined: -unknown-flag`) {
		t.Fatalf("stderr = %q", stderr.String())
	}
}

func TestMainWritesErrorAndExitsForMissingTemplateAsset(t *testing.T) {
	oldArgs := os.Args
	oldExit := exitFunc
	oldStderr := stderrOut
	t.Cleanup(func() {
		os.Args = oldArgs
		exitFunc = oldExit
		stderrOut = oldStderr
	})

	var stderr bytes.Buffer
	exitCode := -1
	exitFunc = func(code int) { exitCode = code }
	stderrOut = &stderr
	os.Args = []string{
		oldArgs[0],
		"-input", "repository-scan=internal/ci/testdata/repo",
		"-template", filepath.Join(t.TempDir(), "missing-report.html.tmpl"),
	}

	main()

	if exitCode != 1 {
		t.Fatalf("exit code = %d", exitCode)
	}
	if !strings.Contains(stderr.String(), "error:") || !strings.Contains(stderr.String(), "asset not found") {
		t.Fatalf("stderr = %q", stderr.String())
	}
}

func TestMainWritesErrorAndExitsForMissingThemeAsset(t *testing.T) {
	oldArgs := os.Args
	oldExit := exitFunc
	oldStderr := stderrOut
	t.Cleanup(func() {
		os.Args = oldArgs
		exitFunc = oldExit
		stderrOut = oldStderr
	})

	var stderr bytes.Buffer
	exitCode := -1
	exitFunc = func(code int) { exitCode = code }
	stderrOut = &stderr
	os.Args = []string{
		oldArgs[0],
		"-input", "repository-scan=internal/ci/testdata/repo",
		"-output-html", filepath.Join(t.TempDir(), "report.html"),
		"-output-json", filepath.Join(t.TempDir(), "report.json"),
		"-output-legal-html", filepath.Join(t.TempDir(), "legal.html"),
		"-theme-css", filepath.Join(t.TempDir(), "missing-report.css"),
	}

	main()

	if exitCode != 1 {
		t.Fatalf("exit code = %d", exitCode)
	}
	if !strings.Contains(stderr.String(), "error:") || !strings.Contains(stderr.String(), "asset not found") {
		t.Fatalf("stderr = %q", stderr.String())
	}
}

func TestMainWritesErrorAndExitsForMissingVulnerabilityTemplateAsset(t *testing.T) {
	oldArgs := os.Args
	oldExit := exitFunc
	oldStderr := stderrOut
	t.Cleanup(func() {
		os.Args = oldArgs
		exitFunc = oldExit
		stderrOut = oldStderr
	})

	var stderr bytes.Buffer
	exitCode := -1
	exitFunc = func(code int) { exitCode = code }
	stderrOut = &stderr
	os.Args = []string{
		oldArgs[0],
		"-input", "repository-scan=internal/ci/testdata/repo",
		"-output-vuln-html", filepath.Join(t.TempDir(), "vuln.html"),
		"-vuln-template", filepath.Join(t.TempDir(), "missing-vulnerability.html.tmpl"),
	}

	main()

	if exitCode != 1 {
		t.Fatalf("exit code = %d", exitCode)
	}
	if !strings.Contains(stderr.String(), "error:") || !strings.Contains(stderr.String(), "asset not found") {
		t.Fatalf("stderr = %q", stderr.String())
	}
}

func TestMainWritesErrorAndExitsForMissingVulnerabilityThemeAsset(t *testing.T) {
	oldArgs := os.Args
	oldExit := exitFunc
	oldStderr := stderrOut
	t.Cleanup(func() {
		os.Args = oldArgs
		exitFunc = oldExit
		stderrOut = oldStderr
	})

	var stderr bytes.Buffer
	exitCode := -1
	exitFunc = func(code int) { exitCode = code }
	stderrOut = &stderr
	os.Args = []string{
		oldArgs[0],
		"-input", "repository-scan=internal/ci/testdata/repo",
		"-output-vuln-html", filepath.Join(t.TempDir(), "vuln.html"),
		"-vuln-theme-css", filepath.Join(t.TempDir(), "missing-vuln.css"),
	}

	main()

	if exitCode != 1 {
		t.Fatalf("exit code = %d", exitCode)
	}
	if !strings.Contains(stderr.String(), "error:") || !strings.Contains(stderr.String(), "asset not found") {
		t.Fatalf("stderr = %q", stderr.String())
	}
}

func TestMainWritesErrorAndExitsForMissingLegalTemplateAsset(t *testing.T) {
	oldArgs := os.Args
	oldExit := exitFunc
	oldStderr := stderrOut
	t.Cleanup(func() {
		os.Args = oldArgs
		exitFunc = oldExit
		stderrOut = oldStderr
	})

	var stderr bytes.Buffer
	exitCode := -1
	exitFunc = func(code int) { exitCode = code }
	stderrOut = &stderr
	os.Args = []string{
		oldArgs[0],
		"-input", "repository-scan=internal/ci/testdata/repo",
		"-output-html", filepath.Join(t.TempDir(), "report.html"),
		"-output-json", filepath.Join(t.TempDir(), "report.json"),
		"-output-legal-html", filepath.Join(t.TempDir(), "legal.html"),
		"-legal-template", filepath.Join(t.TempDir(), "missing-legal.html.tmpl"),
	}

	main()

	if exitCode != 1 {
		t.Fatalf("exit code = %d", exitCode)
	}
	if !strings.Contains(stderr.String(), "error:") || !strings.Contains(stderr.String(), "asset not found") {
		t.Fatalf("stderr = %q", stderr.String())
	}
}

func TestMainWritesErrorAndExitsForPrimaryJSONWriteFailure(t *testing.T) {
	mainSeamMu.Lock()
	defer mainSeamMu.Unlock()

	oldArgs := os.Args
	oldExit := exitFunc
	oldStderr := stderrOut
	oldMkdirAll := mkdirAllFunc
	oldWriteFile := writeFileFunc
	t.Cleanup(func() {
		os.Args = oldArgs
		exitFunc = oldExit
		stderrOut = oldStderr
		mkdirAllFunc = oldMkdirAll
		writeFileFunc = oldWriteFile
	})

	dir := t.TempDir()
	jsonPath := filepath.Join(dir, "report.json")

	var stderr bytes.Buffer
	exitCode := -1
	exitFunc = func(code int) { exitCode = code }
	stderrOut = &stderr
	mkdirAllFunc = func(string, os.FileMode) error { return nil }
	writeFileFunc = func(path string, data []byte, perm os.FileMode) error {
		if path == jsonPath {
			return errors.New("json-write-failed")
		}
		return oldWriteFile(path, data, perm)
	}
	os.Args = []string{
		oldArgs[0],
		"-input", "repository-scan=internal/ci/testdata/repo",
		"-output-html", filepath.Join(dir, "report.html"),
		"-output-json", jsonPath,
		"-output-legal-html", filepath.Join(dir, "legal.html"),
	}

	main()

	if exitCode != 1 {
		t.Fatalf("exit code = %d", exitCode)
	}
	if !strings.Contains(stderr.String(), "error: json-write-failed") {
		t.Fatalf("stderr = %q", stderr.String())
	}
}

func TestMainWritesErrorAndExitsForOutputDirectoryCreationFailure(t *testing.T) {
	mainSeamMu.Lock()
	defer mainSeamMu.Unlock()

	oldArgs := os.Args
	oldExit := exitFunc
	oldStderr := stderrOut
	oldMkdirAll := mkdirAllFunc
	oldWriteFile := writeFileFunc
	t.Cleanup(func() {
		os.Args = oldArgs
		exitFunc = oldExit
		stderrOut = oldStderr
		mkdirAllFunc = oldMkdirAll
		writeFileFunc = oldWriteFile
	})

	dir := t.TempDir()
	htmlPath := filepath.Join(dir, "report.html")

	var stderr bytes.Buffer
	exitCode := -1
	exitFunc = func(code int) { exitCode = code }
	stderrOut = &stderr
	mkdirAllFunc = func(path string, perm os.FileMode) error {
		if path == filepath.Dir(htmlPath) {
			return errors.New("mkdir-failed")
		}
		return nil
	}
	writeFileFunc = oldWriteFile
	os.Args = []string{
		oldArgs[0],
		"-input", "repository-scan=internal/ci/testdata/repo",
		"-output-html", htmlPath,
		"-output-json", filepath.Join(dir, "report.json"),
		"-output-legal-html", filepath.Join(dir, "legal.html"),
	}

	main()

	if exitCode != 1 {
		t.Fatalf("exit code = %d", exitCode)
	}
	if !strings.Contains(stderr.String(), "error: mkdir-failed") {
		t.Fatalf("stderr = %q", stderr.String())
	}
}

func TestMainWritesErrorAndExitsForVulnerabilityJSONWriteFailure(t *testing.T) {
	mainSeamMu.Lock()
	defer mainSeamMu.Unlock()

	oldArgs := os.Args
	oldExit := exitFunc
	oldStderr := stderrOut
	oldMkdirAll := mkdirAllFunc
	oldWriteFile := writeFileFunc
	t.Cleanup(func() {
		os.Args = oldArgs
		exitFunc = oldExit
		stderrOut = oldStderr
		mkdirAllFunc = oldMkdirAll
		writeFileFunc = oldWriteFile
	})

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/querybatch" {
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"results":[{"vulns":[]},{"vulns":[]},{"vulns":[]},{"vulns":[]}]}`))
	}))
	defer server.Close()

	dir := t.TempDir()
	vulnJSONPath := filepath.Join(dir, "vuln.json")

	var stderr bytes.Buffer
	exitCode := -1
	exitFunc = func(code int) { exitCode = code }
	stderrOut = &stderr
	mkdirAllFunc = func(string, os.FileMode) error { return nil }
	writeFileFunc = func(path string, data []byte, perm os.FileMode) error {
		if path == vulnJSONPath {
			return errors.New("vuln-json-write-failed")
		}
		return oldWriteFile(path, data, perm)
	}
	os.Args = []string{
		oldArgs[0],
		"-input", "repository-scan=internal/ci/testdata/repo",
		"-output-html", filepath.Join(dir, "report.html"),
		"-output-json", filepath.Join(dir, "report.json"),
		"-output-legal-html", filepath.Join(dir, "legal.html"),
		"-output-vuln-json", vulnJSONPath,
		"-osv-base-url", server.URL,
	}

	main()

	if exitCode != 1 {
		t.Fatalf("exit code = %d", exitCode)
	}
	if !strings.Contains(stderr.String(), "error: vuln-json-write-failed") {
		t.Fatalf("stderr = %q", stderr.String())
	}
}

func TestMainWritesErrorAndExitsForHTMLWriteFailure(t *testing.T) {
	mainSeamMu.Lock()
	defer mainSeamMu.Unlock()

	oldArgs := os.Args
	oldExit := exitFunc
	oldStderr := stderrOut
	oldMkdirAll := mkdirAllFunc
	oldWriteFile := writeFileFunc
	t.Cleanup(func() {
		os.Args = oldArgs
		exitFunc = oldExit
		stderrOut = oldStderr
		mkdirAllFunc = oldMkdirAll
		writeFileFunc = oldWriteFile
	})

	dir := t.TempDir()
	htmlPath := filepath.Join(dir, "report.html")

	var stderr bytes.Buffer
	exitCode := -1
	exitFunc = func(code int) { exitCode = code }
	stderrOut = &stderr
	mkdirAllFunc = func(string, os.FileMode) error { return nil }
	writeFileFunc = func(path string, data []byte, perm os.FileMode) error {
		if path == htmlPath {
			return errors.New("html-write-failed")
		}
		return oldWriteFile(path, data, perm)
	}
	os.Args = []string{
		oldArgs[0],
		"-input", "repository-scan=internal/ci/testdata/repo",
		"-output-html", htmlPath,
		"-output-json", filepath.Join(dir, "report.json"),
		"-output-legal-html", filepath.Join(dir, "legal.html"),
	}

	main()

	if exitCode != 1 {
		t.Fatalf("exit code = %d", exitCode)
	}
	if !strings.Contains(stderr.String(), "error: html-write-failed") {
		t.Fatalf("stderr = %q", stderr.String())
	}
}

func TestMainWritesErrorAndExitsForLegalHTMLWriteFailure(t *testing.T) {
	mainSeamMu.Lock()
	defer mainSeamMu.Unlock()

	oldArgs := os.Args
	oldExit := exitFunc
	oldStderr := stderrOut
	oldMkdirAll := mkdirAllFunc
	oldWriteFile := writeFileFunc
	t.Cleanup(func() {
		os.Args = oldArgs
		exitFunc = oldExit
		stderrOut = oldStderr
		mkdirAllFunc = oldMkdirAll
		writeFileFunc = oldWriteFile
	})

	dir := t.TempDir()
	legalPath := filepath.Join(dir, "legal.html")

	var stderr bytes.Buffer
	exitCode := -1
	exitFunc = func(code int) { exitCode = code }
	stderrOut = &stderr
	mkdirAllFunc = func(string, os.FileMode) error { return nil }
	writeFileFunc = func(path string, data []byte, perm os.FileMode) error {
		if path == legalPath {
			return errors.New("legal-write-failed")
		}
		return oldWriteFile(path, data, perm)
	}
	os.Args = []string{
		oldArgs[0],
		"-input", "repository-scan=internal/ci/testdata/repo",
		"-output-html", filepath.Join(dir, "report.html"),
		"-output-json", filepath.Join(dir, "report.json"),
		"-output-legal-html", legalPath,
	}

	main()

	if exitCode != 1 {
		t.Fatalf("exit code = %d", exitCode)
	}
	if !strings.Contains(stderr.String(), "error: legal-write-failed") {
		t.Fatalf("stderr = %q", stderr.String())
	}
}

func TestMainWritesErrorAndExitsForVulnerabilityHTMLWriteFailure(t *testing.T) {
	mainSeamMu.Lock()
	defer mainSeamMu.Unlock()

	oldArgs := os.Args
	oldExit := exitFunc
	oldStderr := stderrOut
	oldMkdirAll := mkdirAllFunc
	oldWriteFile := writeFileFunc
	t.Cleanup(func() {
		os.Args = oldArgs
		exitFunc = oldExit
		stderrOut = oldStderr
		mkdirAllFunc = oldMkdirAll
		writeFileFunc = oldWriteFile
	})

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/querybatch" {
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"results":[{"vulns":[]},{"vulns":[]},{"vulns":[]},{"vulns":[]}]}`))
	}))
	defer server.Close()

	dir := t.TempDir()
	vulnHTMLPath := filepath.Join(dir, "vuln.html")

	var stderr bytes.Buffer
	exitCode := -1
	exitFunc = func(code int) { exitCode = code }
	stderrOut = &stderr
	mkdirAllFunc = func(string, os.FileMode) error { return nil }
	writeFileFunc = func(path string, data []byte, perm os.FileMode) error {
		if path == vulnHTMLPath {
			return errors.New("vuln-html-write-failed")
		}
		return oldWriteFile(path, data, perm)
	}
	os.Args = []string{
		oldArgs[0],
		"-input", "repository-scan=internal/ci/testdata/repo",
		"-output-html", filepath.Join(dir, "report.html"),
		"-output-json", filepath.Join(dir, "report.json"),
		"-output-legal-html", filepath.Join(dir, "legal.html"),
		"-output-vuln-html", vulnHTMLPath,
		"-osv-base-url", server.URL,
	}

	main()

	if exitCode != 1 {
		t.Fatalf("exit code = %d", exitCode)
	}
	if !strings.Contains(stderr.String(), "error: vuln-html-write-failed") {
		t.Fatalf("stderr = %q", stderr.String())
	}
}

func TestRunGeneratesVulnerabilityOutputs(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/querybatch" {
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"results":[{"vulns":[]},{"vulns":[]},{"vulns":[]},{"vulns":[]}]}`))
	}))
	defer server.Close()

	dir := t.TempDir()
	htmlPath := filepath.Join(dir, "report.html")
	jsonPath := filepath.Join(dir, "report.json")
	legalPath := filepath.Join(dir, "legal.html")
	vulnHTMLPath := filepath.Join(dir, "vuln.html")
	vulnJSONPath := filepath.Join(dir, "vuln.json")

	var stdout bytes.Buffer
	err := run([]string{
		"-input", "repository-scan=internal/ci/testdata/repo",
		"-output-html", htmlPath,
		"-output-json", jsonPath,
		"-output-legal-html", legalPath,
		"-output-vuln-html", vulnHTMLPath,
		"-output-vuln-json", vulnJSONPath,
		"-osv-base-url", server.URL,
	}, &stdout)
	if err != nil {
		t.Fatalf("run with vulnerability outputs failed: %v", err)
	}
	for _, path := range []string{vulnHTMLPath, vulnJSONPath} {
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("expected vulnerability output %s: %v", path, err)
		}
	}
	if !strings.Contains(stdout.String(), "generated vulnerability HTML") {
		t.Fatalf("unexpected stdout: %s", stdout.String())
	}
}

func TestRunGeneratesOutputsWithRemoteCatalog(t *testing.T) {
	t.Parallel()

	catalogServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
  "licenses":[
    {
      "key":"MIT",
      "name":"MIT License (Remote)",
      "family":"Permissive",
      "version":"",
      "copyleft_strength":"none",
      "requires_manual_review":false,
      "spdx_ids":["MIT"],
      "names":["MIT License","MIT License (Remote)"],
      "exact_urls":[],
      "url_prefixes":[],
      "contains":["mit license"],
      "color":"#22c55e",
      "risk_level":"low",
      "notice_template":"remote notice"
    },
    {
      "key":"Apache-2.0",
      "name":"Apache License 2.0",
      "family":"Permissive",
      "version":"2.0",
      "copyleft_strength":"none",
      "requires_manual_review":false,
      "spdx_ids":["Apache-2.0"],
      "names":["Apache License 2.0"],
      "exact_urls":[],
      "url_prefixes":[],
      "contains":["apache license 2.0"],
      "color":"#3b82f6",
      "risk_level":"low",
      "notice_template":"apache notice"
    },
    {
      "key":"BSD-3-Clause",
      "name":"BSD 3-Clause License",
      "family":"Permissive",
      "version":"",
      "copyleft_strength":"none",
      "requires_manual_review":false,
      "spdx_ids":["BSD-3-Clause"],
      "names":["BSD 3-Clause License"],
      "exact_urls":[],
      "url_prefixes":[],
      "contains":["bsd 3-clause"],
      "color":"#06b6d4",
      "risk_level":"low",
      "notice_template":"bsd notice"
    }
  ]
}`))
	}))
	defer catalogServer.Close()

	dir := t.TempDir()
	htmlPath := filepath.Join(dir, "report.html")
	jsonPath := filepath.Join(dir, "report.json")
	legalPath := filepath.Join(dir, "legal.html")

	var stdout bytes.Buffer
	err := run([]string{
		"-input", "repository-scan=internal/ci/testdata/repo",
		"-license-catalog", "configs/licenses.json",
		"-license-catalog", catalogServer.URL + "/licenses.json",
		"-output-html", htmlPath,
		"-output-json", jsonPath,
		"-output-legal-html", legalPath,
	}, &stdout)
	if err != nil {
		t.Fatalf("run with remote catalog failed: %v", err)
	}

	payload, err := os.ReadFile(jsonPath)
	if err != nil {
		t.Fatalf("read report json: %v", err)
	}
	var output struct {
		Provenance struct {
			CatalogSources []struct {
				Kind     string `json:"kind"`
				Location string `json:"location"`
			} `json:"catalogSources"`
		} `json:"provenance"`
		Report struct {
			Groups []struct {
				Key  string `json:"key"`
				Name string `json:"name"`
			} `json:"groups"`
		} `json:"report"`
	}
	if err := json.Unmarshal(payload, &output); err != nil {
		t.Fatalf("parse report json: %v", err)
	}
	foundRemoteCatalog := false
	for _, source := range output.Provenance.CatalogSources {
		if source.Kind == "remote" && source.Location == catalogServer.URL+"/licenses.json" {
			foundRemoteCatalog = true
		}
	}
	if !foundRemoteCatalog {
		t.Fatalf("catalog sources = %#v", output.Provenance.CatalogSources)
	}
	foundMIT := false
	for _, group := range output.Report.Groups {
		if group.Key == "MIT" {
			foundMIT = true
			if group.Name != "MIT License (Remote)" {
				t.Fatalf("mit group = %#v", group)
			}
		}
	}
	if !foundMIT {
		t.Fatalf("groups = %#v", output.Report.Groups)
	}
}

func TestRunGeneratesOutputsWithRemoteCatalogStaleFallback(t *testing.T) {
	t.Parallel()

	remoteBody := `{
  "licenses":[
    {
      "key":"MIT",
      "name":"MIT License (Stale Cache Remote)",
      "family":"Permissive",
      "version":"",
      "copyleft_strength":"none",
      "requires_manual_review":false,
      "spdx_ids":["MIT"],
      "names":["MIT License","MIT License (Stale Cache Remote)"],
      "exact_urls":[],
      "url_prefixes":[],
      "contains":["mit license"],
      "color":"#22c55e",
      "risk_level":"low",
      "notice_template":"stale cache remote notice"
    }
  ]
}`
	cacheDir := t.TempDir()
	catalogServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(remoteBody))
	}))
	source := catalogServer.URL + "/licenses.json"

	primeDir := t.TempDir()
	if err := run([]string{
		"-input", "repository-scan=internal/ci/testdata/repo",
		"-license-catalog", "configs/licenses.json",
		"-license-catalog", source,
		"-remote-catalog-mode", "stale-fallback",
		"-remote-catalog-cache-dir", cacheDir,
		"-output-html", filepath.Join(primeDir, "report.html"),
		"-output-json", filepath.Join(primeDir, "report.json"),
		"-output-legal-html", filepath.Join(primeDir, "legal.html"),
	}, io.Discard); err != nil {
		t.Fatalf("prime remote catalog cache: %v", err)
	}
	catalogServer.Close()

	dir := t.TempDir()
	jsonPath := filepath.Join(dir, "report.json")
	if err := run([]string{
		"-input", "repository-scan=internal/ci/testdata/repo",
		"-license-catalog", "configs/licenses.json",
		"-license-catalog", source,
		"-remote-catalog-mode", "stale-fallback",
		"-remote-catalog-cache-dir", cacheDir,
		"-output-html", filepath.Join(dir, "report.html"),
		"-output-json", jsonPath,
		"-output-legal-html", filepath.Join(dir, "legal.html"),
	}, io.Discard); err != nil {
		t.Fatalf("run with stale fallback remote catalog failed: %v", err)
	}

	payload, err := os.ReadFile(jsonPath)
	if err != nil {
		t.Fatalf("read report json: %v", err)
	}
	var output struct {
		Provenance struct {
			CatalogSources []struct {
				Kind        string `json:"kind"`
				Location    string `json:"location"`
				CacheStatus string `json:"cacheStatus"`
			} `json:"catalogSources"`
		} `json:"provenance"`
		Report struct {
			Groups []struct {
				Key  string `json:"key"`
				Name string `json:"name"`
			} `json:"groups"`
		} `json:"report"`
	}
	if err := json.Unmarshal(payload, &output); err != nil {
		t.Fatalf("parse report json: %v", err)
	}

	foundStaleRemote := false
	for _, sourceMeta := range output.Provenance.CatalogSources {
		if sourceMeta.Kind == "remote" && sourceMeta.Location == source {
			foundStaleRemote = true
			if sourceMeta.CacheStatus != "stale-cache" {
				t.Fatalf("remote source provenance = %#v", sourceMeta)
			}
		}
	}
	if !foundStaleRemote {
		t.Fatalf("catalog sources = %#v", output.Provenance.CatalogSources)
	}

	foundMIT := false
	for _, group := range output.Report.Groups {
		if group.Key == "MIT" {
			foundMIT = true
			if group.Name != "MIT License (Stale Cache Remote)" {
				t.Fatalf("mit group = %#v", group)
			}
		}
	}
	if !foundMIT {
		t.Fatalf("groups = %#v", output.Report.Groups)
	}
}

func TestRunGeneratesOutputsWithPinnedRemoteCatalogStaleFallback(t *testing.T) {
	t.Parallel()

	remoteBody := `{
  "licenses":[
    {
      "key":"MIT",
      "name":"MIT License (Pinned Stale Cache Remote)",
      "family":"Permissive",
      "version":"",
      "copyleft_strength":"none",
      "requires_manual_review":false,
      "spdx_ids":["MIT"],
      "names":["MIT License","MIT License (Pinned Stale Cache Remote)"],
      "exact_urls":[],
      "url_prefixes":[],
      "contains":["mit license"],
      "color":"#22c55e",
      "risk_level":"low",
      "notice_template":"pinned stale cache remote notice"
    }
  ]
}`
	sum := sha256.Sum256([]byte(remoteBody))
	requestedSHA := strings.ToLower(fmt.Sprintf("%x", sum))
	cacheDir := t.TempDir()
	catalogServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(remoteBody))
	}))
	source := catalogServer.URL + "/licenses.json#sha256=" + requestedSHA

	primeDir := t.TempDir()
	if err := run([]string{
		"-input", "repository-scan=internal/ci/testdata/repo",
		"-license-catalog", "configs/licenses.json",
		"-license-catalog", source,
		"-remote-catalog-mode", "stale-fallback",
		"-remote-catalog-cache-dir", cacheDir,
		"-output-html", filepath.Join(primeDir, "report.html"),
		"-output-json", filepath.Join(primeDir, "report.json"),
		"-output-legal-html", filepath.Join(primeDir, "legal.html"),
	}, io.Discard); err != nil {
		t.Fatalf("prime pinned remote catalog cache: %v", err)
	}
	catalogServer.Close()

	dir := t.TempDir()
	jsonPath := filepath.Join(dir, "report.json")
	if err := run([]string{
		"-input", "repository-scan=internal/ci/testdata/repo",
		"-license-catalog", "configs/licenses.json",
		"-license-catalog", source,
		"-remote-catalog-mode", "stale-fallback",
		"-remote-catalog-cache-dir", cacheDir,
		"-output-html", filepath.Join(dir, "report.html"),
		"-output-json", jsonPath,
		"-output-legal-html", filepath.Join(dir, "legal.html"),
	}, io.Discard); err != nil {
		t.Fatalf("run with pinned stale fallback remote catalog failed: %v", err)
	}

	payload, err := os.ReadFile(jsonPath)
	if err != nil {
		t.Fatalf("read report json: %v", err)
	}
	var output struct {
		Provenance struct {
			CatalogSources []struct {
				Kind            string `json:"kind"`
				Location        string `json:"location"`
				PinningMode     string `json:"pinningMode"`
				RequestedSHA256 string `json:"requestedSha256"`
				CacheStatus     string `json:"cacheStatus"`
			} `json:"catalogSources"`
		} `json:"provenance"`
		Report struct {
			Groups []struct {
				Key  string `json:"key"`
				Name string `json:"name"`
			} `json:"groups"`
		} `json:"report"`
	}
	if err := json.Unmarshal(payload, &output); err != nil {
		t.Fatalf("parse report json: %v", err)
	}

	foundPinnedStaleRemote := false
	for _, sourceMeta := range output.Provenance.CatalogSources {
		if sourceMeta.Kind == "remote" && sourceMeta.Location == source {
			foundPinnedStaleRemote = true
			if sourceMeta.PinningMode != "pinned" || sourceMeta.RequestedSHA256 != requestedSHA || sourceMeta.CacheStatus != "stale-cache" {
				t.Fatalf("remote source provenance = %#v", sourceMeta)
			}
		}
	}
	if !foundPinnedStaleRemote {
		t.Fatalf("catalog sources = %#v", output.Provenance.CatalogSources)
	}

	foundMIT := false
	for _, group := range output.Report.Groups {
		if group.Key == "MIT" {
			foundMIT = true
			if group.Name != "MIT License (Pinned Stale Cache Remote)" {
				t.Fatalf("mit group = %#v", group)
			}
		}
	}
	if !foundMIT {
		t.Fatalf("groups = %#v", output.Report.Groups)
	}
}

func TestRunFailsFastForRemoteCatalogEvenWhenStaleCacheExists(t *testing.T) {
	t.Parallel()

	remoteBody := `{
  "licenses":[
    {
      "key":"MIT",
      "name":"MIT License (Fail Fast Remote)",
      "family":"Permissive",
      "version":"",
      "copyleft_strength":"none",
      "requires_manual_review":false,
      "spdx_ids":["MIT"],
      "names":["MIT License","MIT License (Fail Fast Remote)"],
      "exact_urls":[],
      "url_prefixes":[],
      "contains":["mit license"],
      "color":"#22c55e",
      "risk_level":"low",
      "notice_template":"fail fast remote notice"
    }
  ]
}`
	cacheDir := t.TempDir()
	catalogServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(remoteBody))
	}))
	source := catalogServer.URL + "/licenses.json"

	primeDir := t.TempDir()
	if err := run([]string{
		"-input", "repository-scan=internal/ci/testdata/repo",
		"-license-catalog", "configs/licenses.json",
		"-license-catalog", source,
		"-remote-catalog-mode", "stale-fallback",
		"-remote-catalog-cache-dir", cacheDir,
		"-output-html", filepath.Join(primeDir, "report.html"),
		"-output-json", filepath.Join(primeDir, "report.json"),
		"-output-legal-html", filepath.Join(primeDir, "legal.html"),
	}, io.Discard); err != nil {
		t.Fatalf("prime remote catalog cache: %v", err)
	}
	catalogServer.Close()

	err := run([]string{
		"-input", "repository-scan=internal/ci/testdata/repo",
		"-license-catalog", "configs/licenses.json",
		"-license-catalog", source,
		"-remote-catalog-mode", "fail-fast",
		"-remote-catalog-cache-dir", cacheDir,
		"-output-html", filepath.Join(t.TempDir(), "report.html"),
		"-output-json", filepath.Join(t.TempDir(), "report.json"),
		"-output-legal-html", filepath.Join(t.TempDir(), "legal.html"),
	}, io.Discard)
	if err == nil {
		t.Fatal("expected fail-fast remote catalog error")
	}
	if strings.Contains(err.Error(), "stale-cache") {
		t.Fatalf("unexpected stale cache success path: %v", err)
	}
}

func TestRunIncludesMergedEffectiveCatalogInReportJSON(t *testing.T) {
	t.Parallel()

	catalogServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
  "licenses":[
    {
      "key":"MIT",
      "name":"MIT License (Merged Remote)",
      "family":"Permissive",
      "version":"",
      "copyleft_strength":"none",
      "requires_manual_review":false,
      "spdx_ids":["MIT"],
      "names":["MIT License","MIT License (Merged Remote)"],
      "exact_urls":[],
      "url_prefixes":[],
      "contains":["mit license"],
      "color":"#22c55e",
      "risk_level":"low",
      "notice_template":"merged remote notice"
    }
  ]
}`))
	}))
	defer catalogServer.Close()

	dir := t.TempDir()
	jsonPath := filepath.Join(dir, "report.json")

	var stdout bytes.Buffer
	err := run([]string{
		"-input", "repository-scan=internal/ci/testdata/repo",
		"-license-catalog", "configs/licenses.json",
		"-license-catalog", catalogServer.URL + "/licenses.json",
		"-output-html", filepath.Join(dir, "report.html"),
		"-output-json", jsonPath,
		"-output-legal-html", filepath.Join(dir, "legal.html"),
	}, &stdout)
	if err != nil {
		t.Fatalf("run with merged catalog failed: %v", err)
	}

	payload, err := os.ReadFile(jsonPath)
	if err != nil {
		t.Fatalf("read report json: %v", err)
	}
	var output struct {
		Provenance struct {
			EffectiveCatalog struct {
				Fallback string `json:"fallback"`
				Licenses []struct {
					Key  string `json:"key"`
					Name string `json:"name"`
				} `json:"licenses"`
			} `json:"effectiveCatalog"`
		} `json:"provenance"`
	}
	if err := json.Unmarshal(payload, &output); err != nil {
		t.Fatalf("parse report json: %v", err)
	}
	if output.Provenance.EffectiveCatalog.Fallback != "Unknown" {
		t.Fatalf("effective fallback = %#v", output.Provenance.EffectiveCatalog)
	}
	foundMIT := false
	for _, def := range output.Provenance.EffectiveCatalog.Licenses {
		if def.Key == "MIT" {
			foundMIT = true
			if def.Name != "MIT License (Merged Remote)" {
				t.Fatalf("effective mit definition = %#v", def)
			}
		}
	}
	if !foundMIT {
		t.Fatalf("effective catalog licenses = %#v", output.Provenance.EffectiveCatalog.Licenses)
	}
}

func TestRunCatalogOverrideStaysConsistentAcrossOutputs(t *testing.T) {
	t.Parallel()

	catalogServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/licenses.json" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
  "fallback": "Unknown",
  "licenses": [
    {
      "key": "MIT",
      "name": "MIT License (Consistent Remote)",
      "family": "MIT",
      "copyleft_strength": "none",
      "requires_manual_review": false,
      "spdx_ids": ["MIT"],
      "names": ["MIT License (Consistent Remote)"],
      "contains": ["mit"],
      "risk_level": "low",
      "notice_template": "consistent remote notice"
    }
  ]
}`))
	}))
	defer catalogServer.Close()

	dir := t.TempDir()
	jsonPath := filepath.Join(dir, "report.json")
	htmlPath := filepath.Join(dir, "report.html")
	legalPath := filepath.Join(dir, "legal.html")

	if err := run([]string{
		"-input", "repository-scan=internal/ci/testdata/repo",
		"-license-catalog", "configs/licenses.json",
		"-license-catalog", catalogServer.URL + "/licenses.json",
		"-output-html", htmlPath,
		"-output-json", jsonPath,
		"-output-legal-html", legalPath,
	}, &bytes.Buffer{}); err != nil {
		t.Fatalf("run with cross-output catalog override failed: %v", err)
	}

	jsonPayload, err := os.ReadFile(jsonPath)
	if err != nil {
		t.Fatalf("read report json: %v", err)
	}
	var output struct {
		Report struct {
			Groups []struct {
				Key  string `json:"key"`
				Name string `json:"name"`
			} `json:"groups"`
		} `json:"report"`
	}
	if err := json.Unmarshal(jsonPayload, &output); err != nil {
		t.Fatalf("parse report json: %v", err)
	}
	foundMIT := false
	for _, group := range output.Report.Groups {
		if group.Key == "MIT" {
			foundMIT = true
			if group.Name != "MIT License (Consistent Remote)" {
				t.Fatalf("json mit group = %#v", group)
			}
		}
	}
	if !foundMIT {
		t.Fatalf("json groups = %#v", output.Report.Groups)
	}

	htmlPayload, err := os.ReadFile(htmlPath)
	if err != nil {
		t.Fatalf("read report html: %v", err)
	}
	reportHTML := string(htmlPayload)
	for _, want := range []string{
		"MIT License (Consistent Remote)",
		"consistent remote notice",
	} {
		if !strings.Contains(reportHTML, want) {
			t.Fatalf("report html missing %q\n%s", want, reportHTML)
		}
	}

	legalPayload, err := os.ReadFile(legalPath)
	if err != nil {
		t.Fatalf("read legal html: %v", err)
	}
	legalHTML := string(legalPayload)
	for _, want := range []string{
		"MIT License (Consistent Remote)",
		"consistent remote notice",
	} {
		if !strings.Contains(legalHTML, want) {
			t.Fatalf("legal html missing %q\n%s", want, legalHTML)
		}
	}
}

func TestRunPinnedCatalogOverrideStaysConsistentAcrossOutputs(t *testing.T) {
	t.Parallel()

	remoteBody := `{
  "licenses":[
    {
      "key":"MIT",
      "name":"MIT License (Pinned Consistent Remote)",
      "family":"Permissive",
      "version":"",
      "copyleft_strength":"none",
      "requires_manual_review":false,
      "spdx_ids":["MIT"],
      "names":["MIT License","MIT License (Pinned Consistent Remote)"],
      "exact_urls":[],
      "url_prefixes":[],
      "contains":["mit license"],
      "color":"#22c55e",
      "risk_level":"low",
      "notice_template":"pinned consistent remote notice"
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

	dir := t.TempDir()
	jsonPath := filepath.Join(dir, "report.json")
	htmlPath := filepath.Join(dir, "report.html")
	legalPath := filepath.Join(dir, "legal.html")

	if err := run([]string{
		"-input", "repository-scan=internal/ci/testdata/repo",
		"-license-catalog", "configs/licenses.json",
		"-license-catalog", catalogServer.URL + "/licenses.json#sha256=" + requestedSHA,
		"-output-html", htmlPath,
		"-output-json", jsonPath,
		"-output-legal-html", legalPath,
	}, &bytes.Buffer{}); err != nil {
		t.Fatalf("run with pinned cross-output catalog override failed: %v", err)
	}

	jsonPayload, err := os.ReadFile(jsonPath)
	if err != nil {
		t.Fatalf("read report json: %v", err)
	}
	var output struct {
		Provenance struct {
			CatalogSources []struct {
				Kind         string `json:"kind"`
				Location     string `json:"location"`
				PinningMode  string `json:"pinningMode"`
				RequestedSHA string `json:"requestedSha256"`
			} `json:"catalogSources"`
		} `json:"provenance"`
		Report struct {
			Groups []struct {
				Key  string `json:"key"`
				Name string `json:"name"`
			} `json:"groups"`
		} `json:"report"`
	}
	if err := json.Unmarshal(jsonPayload, &output); err != nil {
		t.Fatalf("parse report json: %v", err)
	}
	foundPinned := false
	for _, source := range output.Provenance.CatalogSources {
		if source.Kind == "remote" && source.Location == catalogServer.URL+"/licenses.json#sha256="+requestedSHA {
			foundPinned = true
			if source.PinningMode != "pinned" || source.RequestedSHA != requestedSHA {
				t.Fatalf("pinned source = %#v", source)
			}
		}
	}
	if !foundPinned {
		t.Fatalf("catalog sources = %#v", output.Provenance.CatalogSources)
	}

	foundMIT := false
	for _, group := range output.Report.Groups {
		if group.Key == "MIT" {
			foundMIT = true
			if group.Name != "MIT License (Pinned Consistent Remote)" {
				t.Fatalf("json mit group = %#v", group)
			}
		}
	}
	if !foundMIT {
		t.Fatalf("json groups = %#v", output.Report.Groups)
	}

	htmlPayload, err := os.ReadFile(htmlPath)
	if err != nil {
		t.Fatalf("read report html: %v", err)
	}
	reportHTML := string(htmlPayload)
	for _, want := range []string{
		"MIT License (Pinned Consistent Remote)",
		"pinned consistent remote notice",
	} {
		if !strings.Contains(reportHTML, want) {
			t.Fatalf("report html missing %q\n%s", want, reportHTML)
		}
	}

	legalPayload, err := os.ReadFile(legalPath)
	if err != nil {
		t.Fatalf("read legal html: %v", err)
	}
	legalHTML := string(legalPayload)
	for _, want := range []string{
		"MIT License (Pinned Consistent Remote)",
		"pinned consistent remote notice",
	} {
		if !strings.Contains(legalHTML, want) {
			t.Fatalf("legal html missing %q\n%s", want, legalHTML)
		}
	}
}

func TestRunReportJSONUsesCycloneDXInputKindProvenance(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	jsonPath := filepath.Join(dir, "report.json")

	var stdout bytes.Buffer
	err := run([]string{
		"-input", "cyclonedx-json=internal/sbom/testdata/cyclonedx/app.json",
		"-output-html", filepath.Join(dir, "report.html"),
		"-output-json", jsonPath,
		"-output-legal-html", filepath.Join(dir, "legal.html"),
	}, &stdout)
	if err != nil {
		t.Fatalf("run with cyclonedx input failed: %v", err)
	}

	payload, err := os.ReadFile(jsonPath)
	if err != nil {
		t.Fatalf("read report json: %v", err)
	}
	var output struct {
		Provenance struct {
			InputKind string `json:"inputKind"`
		} `json:"provenance"`
	}
	if err := json.Unmarshal(payload, &output); err != nil {
		t.Fatalf("parse report json: %v", err)
	}
	if output.Provenance.InputKind != "cyclonedx-json" {
		t.Fatalf("input kind = %#v", output.Provenance)
	}
}

func TestRunAppliesPackageLicenseOverrideFileToReportJSON(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	sbomPath := filepath.Join(dir, "custom-bom.json")
	testutil.WriteIndentedJSONFixture(t, sbomPath, map[string]any{
		"bomFormat":   "CycloneDX",
		"specVersion": "1.5",
		"version":     1,
		"components": []any{
			map[string]any{
				"bom-ref": "pkg:generic/acme/manual-widget@1.2.3",
				"type":    "library",
				"group":   "acme",
				"name":    "manual-widget",
				"version": "1.2.3",
				"purl":    "pkg:generic/acme/manual-widget@1.2.3",
				"scope":   "required",
				"licenses": []any{
					map[string]any{
						"license": map[string]any{
							"name": "Reviewed Private Terms",
							"text": map[string]any{
								"content":     "Custom reviewed license evidence",
								"contentType": "text/plain",
							},
						},
					},
				},
			},
		},
	})

	overridePath := filepath.Join(dir, "license-overrides.json")
	testutil.WriteIndentedJSONFixture(t, overridePath, map[string]any{
		"version": "v1alpha1",
		"licenseOverrides": []any{
			map[string]any{
				"id":         "manual-widget-mit",
				"reason":     "manual review confirmed MIT terms",
				"licenseKey": "MIT",
				"mode":       "ifMissing",
				"match": map[string]any{
					"ecosystems": []string{"generic"},
					"names":      []string{"acme/manual-widget"},
					"versions":   []string{"1.2.3"},
					"purls":      []string{"pkg:generic/acme/manual-widget@1.2.3"},
				},
				"evidence": map[string]any{
					"note": "test review evidence",
				},
			},
		},
	})

	jsonPath := filepath.Join(dir, "report.json")
	if err := run([]string{
		"-input", "cyclonedx-json=" + sbomPath,
		"-license-override-file", overridePath,
		"-output-html", filepath.Join(dir, "report.html"),
		"-output-json", jsonPath,
		"-output-legal-html", filepath.Join(dir, "legal.html"),
	}, &bytes.Buffer{}); err != nil {
		t.Fatalf("run with license override file failed: %v", err)
	}

	payload, err := os.ReadFile(jsonPath)
	if err != nil {
		t.Fatalf("read report json: %v", err)
	}
	var output struct {
		Report struct {
			Packages []struct {
				Name       string `json:"name"`
				RawLicense string `json:"rawLicense"`
				LicenseKey string `json:"licenseKey"`
				Provenance struct {
					SourceIDs    []string          `json:"sourceIds"`
					FieldOrigins map[string]string `json:"fieldOrigins"`
				} `json:"provenance"`
			} `json:"packages"`
			Diagnostics []struct {
				SourceID string `json:"sourceId"`
				RuleID   string `json:"ruleId"`
				Code     string `json:"code"`
				Severity string `json:"severity"`
			} `json:"diagnostics"`
		} `json:"report"`
	}
	if err := json.Unmarshal(payload, &output); err != nil {
		t.Fatalf("parse report json: %v", err)
	}
	if len(output.Report.Packages) != 1 {
		t.Fatalf("packages = %#v", output.Report.Packages)
	}
	pkg := output.Report.Packages[0]
	if pkg.Name != "acme/manual-widget" || pkg.LicenseKey != "MIT" || pkg.RawLicense != "Reviewed Private Terms" {
		t.Fatalf("package = %#v", pkg)
	}
	if pkg.Provenance.FieldOrigins["licenseKey"] != "license-override:manual-widget-mit" {
		t.Fatalf("field origins = %#v", pkg.Provenance.FieldOrigins)
	}
	if !slices.Contains(pkg.Provenance.SourceIDs, "license-override:manual-widget-mit") {
		t.Fatalf("source ids = %#v", pkg.Provenance.SourceIDs)
	}
	if len(output.Report.Diagnostics) != 1 ||
		output.Report.Diagnostics[0].Code != "license_override_applied" ||
		output.Report.Diagnostics[0].RuleID != "manual-widget-mit" ||
		output.Report.Diagnostics[0].Severity != "info" {
		t.Fatalf("diagnostics = %#v", output.Report.Diagnostics)
	}
}

func TestRunRejectsLicenseOverrideFileWithUnknownCatalogKey(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	overridePath := filepath.Join(dir, "license-overrides.json")
	testutil.WriteIndentedJSONFixture(t, overridePath, map[string]any{
		"version": "v1alpha1",
		"licenseOverrides": []any{
			map[string]any{
				"id":         "manual-widget-missing-key",
				"licenseKey": "Missing-License-Key",
				"match": map[string]any{
					"names": []string{"manual-widget"},
				},
			},
		},
	})

	err := run([]string{
		"-input", "cyclonedx-json=internal/sbom/testdata/cyclonedx/missing-license.json",
		"-license-override-file", overridePath,
		"-output-html", filepath.Join(dir, "report.html"),
		"-output-json", filepath.Join(dir, "report.json"),
		"-output-legal-html", filepath.Join(dir, "legal.html"),
	}, &bytes.Buffer{})
	if err == nil {
		t.Fatal("expected license override validation error")
	}
	if !strings.Contains(err.Error(), "license override") || !strings.Contains(err.Error(), "Missing-License-Key") {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, statErr := os.Stat(filepath.Join(dir, "report.json")); !os.IsNotExist(statErr) {
		t.Fatalf("expected report output to be absent, stat error = %v", statErr)
	}
}

func TestRunLicenseOverrideFileCanUseCustomCatalogKey(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	customCatalogPath := filepath.Join(dir, "custom-catalog.json")
	testutil.WriteIndentedJSONFixture(t, customCatalogPath, map[string]any{
		"licenses": []any{
			map[string]any{
				"key":                    "Custom-Reviewed",
				"name":                   "Custom Reviewed License",
				"family":                 "Custom",
				"version":                "",
				"copyleft_strength":      "custom",
				"requires_manual_review": true,
				"spdx_ids":               []string{},
				"names":                  []string{"Custom Reviewed License"},
				"exact_urls":             []string{},
				"url_prefixes":           []string{},
				"contains":               []string{"custom-reviewed-license-marker"},
				"color":                  "#718096",
				"risk_level":             "unknown",
				"notice_template":        "{{.LicenseName}}\n\nPackages: {{.PackageList}}\nManual review required.",
			},
		},
	})

	bundlePath := writeEnglishLicenseTextBundleFixtureWithMutation(t, dir, func(bundle map[string]any) {
		licenses, ok := bundle["licenses"].([]any)
		if !ok {
			t.Fatalf("unexpected licenses payload in bundle fixture")
		}
		bundle["licenses"] = append(licenses, map[string]any{
			"key":         "Custom-Reviewed",
			"description": "Custom reviewed license description",
			"obligations": []string{
				"Retain reviewed notice text.",
			},
			"permissions": []string{
				"Use according to reviewed terms.",
			},
			"limitations": []string{
				"Manual review required.",
			},
		})
	})

	overridePath := filepath.Join(dir, "license-overrides.json")
	testutil.WriteIndentedJSONFixture(t, overridePath, map[string]any{
		"version": "v1alpha1",
		"licenseOverrides": []any{
			map[string]any{
				"id":         "widget-custom-reviewed",
				"licenseKey": "Custom-Reviewed",
				"match": map[string]any{
					"purls": []string{"pkg:generic/acme/widget@1.2.3"},
				},
			},
		},
	})

	jsonPath := filepath.Join(dir, "report.json")
	if err := run([]string{
		"-input", "cyclonedx-json=internal/sbom/testdata/cyclonedx/missing-license.json",
		"-license-catalog", "configs/licenses.json",
		"-license-catalog", customCatalogPath,
		"-license-text-bundle", bundlePath,
		"-license-override-file", overridePath,
		"-output-html", filepath.Join(dir, "report.html"),
		"-output-json", jsonPath,
		"-output-legal-html", filepath.Join(dir, "legal.html"),
	}, &bytes.Buffer{}); err != nil {
		t.Fatalf("run with custom catalog license override failed: %v", err)
	}

	payload, err := os.ReadFile(jsonPath)
	if err != nil {
		t.Fatalf("read report json: %v", err)
	}
	var output struct {
		Report struct {
			Groups []struct {
				Key      string `json:"key"`
				Name     string `json:"name"`
				Packages []struct {
					Name string `json:"name"`
				} `json:"packages"`
			} `json:"groups"`
		} `json:"report"`
	}
	if err := json.Unmarshal(payload, &output); err != nil {
		t.Fatalf("parse report json: %v", err)
	}

	for _, group := range output.Report.Groups {
		if group.Key == "Custom-Reviewed" && group.Name == "Custom Reviewed License" && len(group.Packages) == 1 && group.Packages[0].Name == "acme/widget" {
			return
		}
	}
	t.Fatalf("expected custom reviewed license group, got %#v", output.Report.Groups)
}

func TestRunReportJSONUsesSPDXInputKindProvenance(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	jsonPath := filepath.Join(dir, "report.json")

	var stdout bytes.Buffer
	err := run([]string{
		"-input", "spdx-json=internal/sbom/testdata/spdx/app.json",
		"-output-html", filepath.Join(dir, "report.html"),
		"-output-json", jsonPath,
		"-output-legal-html", filepath.Join(dir, "legal.html"),
	}, &stdout)
	if err != nil {
		t.Fatalf("run with spdx input failed: %v", err)
	}

	payload, err := os.ReadFile(jsonPath)
	if err != nil {
		t.Fatalf("read report json: %v", err)
	}
	var output struct {
		Provenance struct {
			InputKind string `json:"inputKind"`
		} `json:"provenance"`
	}
	if err := json.Unmarshal(payload, &output); err != nil {
		t.Fatalf("parse report json: %v", err)
	}
	if output.Provenance.InputKind != "spdx-json" {
		t.Fatalf("input kind = %#v", output.Provenance)
	}
}

func TestRunReportJSONUsesCustomLicenseTextBundleContract(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	bundlePath := writeEnglishLicenseTextBundleFixtureWithMutation(t, dir, func(bundle map[string]any) {
		updateLicenseTextBundleEntry(bundle, "MIT", func(entry map[string]any) {
			entry["description"] = "Custom English MIT description"
		})
	})

	jsonPath := filepath.Join(dir, "report.json")
	if err := run([]string{
		"-input", "repository-scan=internal/ci/testdata/repo",
		"-license-text-bundle", bundlePath,
		"-output-html", filepath.Join(dir, "report.html"),
		"-output-json", jsonPath,
		"-output-legal-html", filepath.Join(dir, "legal.html"),
	}, &bytes.Buffer{}); err != nil {
		t.Fatalf("run with custom bundle failed: %v", err)
	}

	payload, err := os.ReadFile(jsonPath)
	if err != nil {
		t.Fatalf("read report json: %v", err)
	}
	var output struct {
		Provenance struct {
			SelectedLocale string `json:"selectedLocale"`
		} `json:"provenance"`
		Report struct {
			Groups []struct {
				Key         string `json:"key"`
				Description string `json:"description"`
			} `json:"groups"`
		} `json:"report"`
	}
	if err := json.Unmarshal(payload, &output); err != nil {
		t.Fatalf("parse report json: %v", err)
	}

	if output.Provenance.SelectedLocale != "en-US" {
		t.Fatalf("selected locale = %#v", output.Provenance)
	}

	found := false
	for _, group := range output.Report.Groups {
		if group.Key == "MIT" {
			found = true
			if group.Description != "Custom English MIT description" {
				t.Fatalf("mit group = %#v", group)
			}
		}
	}
	if !found {
		t.Fatalf("groups = %#v", output.Report.Groups)
	}
}

func TestRunLicenseTextBundleStaysConsistentAcrossOutputs(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	bundlePath := writeEnglishLicenseTextBundleFixtureWithMutation(t, dir, func(bundle map[string]any) {
		updateLicenseTextBundleEntry(bundle, "MIT", func(entry map[string]any) {
			entry["description"] = "Consistent bundle MIT description"
			entry["obligations"] = []string{"Carry consistent MIT notice"}
		})
	})

	jsonPath := filepath.Join(dir, "report.json")
	htmlPath := filepath.Join(dir, "report.html")
	if err := run([]string{
		"-input", "repository-scan=internal/ci/testdata/repo",
		"-license-text-bundle", bundlePath,
		"-output-html", htmlPath,
		"-output-json", jsonPath,
		"-output-legal-html", filepath.Join(dir, "legal.html"),
	}, &bytes.Buffer{}); err != nil {
		t.Fatalf("run with cross-output bundle failed: %v", err)
	}

	payload, err := os.ReadFile(jsonPath)
	if err != nil {
		t.Fatalf("read report json: %v", err)
	}
	var output struct {
		Provenance struct {
			SelectedLocale string `json:"selectedLocale"`
		} `json:"provenance"`
		Report struct {
			Groups []struct {
				Key         string   `json:"key"`
				Description string   `json:"description"`
				Obligations []string `json:"obligations"`
			} `json:"groups"`
		} `json:"report"`
	}
	if err := json.Unmarshal(payload, &output); err != nil {
		t.Fatalf("parse report json: %v", err)
	}
	if output.Provenance.SelectedLocale != "en-US" {
		t.Fatalf("selected locale = %#v", output.Provenance)
	}

	found := false
	for _, group := range output.Report.Groups {
		if group.Key == "MIT" {
			found = true
			if group.Description != "Consistent bundle MIT description" || !slices.Equal(group.Obligations, []string{"Carry consistent MIT notice"}) {
				t.Fatalf("json mit group = %#v", group)
			}
		}
	}
	if !found {
		t.Fatalf("json groups = %#v", output.Report.Groups)
	}

	htmlPayload, err := os.ReadFile(htmlPath)
	if err != nil {
		t.Fatalf("read report html: %v", err)
	}
	html := string(htmlPayload)
	for _, want := range []string{
		"Consistent bundle MIT description",
		"Carry consistent MIT notice",
	} {
		if !strings.Contains(html, want) {
			t.Fatalf("report html missing %q\n%s", want, html)
		}
	}
}

func TestRunLayeredCustomizationStaysConsistentAcrossOutputs(t *testing.T) {
	t.Parallel()

	catalogServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/licenses.json" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
  "fallback": "Unknown",
  "licenses": [
    {
      "key": "MIT",
      "name": "MIT License (Layered Remote)",
      "family": "MIT",
      "copyleft_strength": "none",
      "requires_manual_review": false,
      "spdx_ids": ["MIT"],
      "names": ["MIT License (Layered Remote)"],
      "contains": ["mit"],
      "risk_level": "low",
      "notice_template": "layered remote notice"
    }
  ]
}`))
	}))
	defer catalogServer.Close()

	dir := t.TempDir()
	bundlePath := writeEnglishLicenseTextBundleFixtureWithMutation(t, dir, func(bundle map[string]any) {
		updateLicenseTextBundleEntry(bundle, "MIT", func(entry map[string]any) {
			entry["description"] = "Layered bundle MIT description"
			entry["obligations"] = []string{"Carry layered MIT notice"}
		})
	})

	jsonPath := filepath.Join(dir, "report.json")
	reportHTMLPath := filepath.Join(dir, "report.html")
	legalHTMLPath := filepath.Join(dir, "legal.html")

	if err := run([]string{
		"-input", "repository-scan=internal/ci/testdata/repo",
		"-license-catalog", "configs/licenses.json",
		"-license-catalog", catalogServer.URL + "/licenses.json",
		"-license-text-bundle", bundlePath,
		"-output-html", reportHTMLPath,
		"-output-json", jsonPath,
		"-output-legal-html", legalHTMLPath,
	}, &bytes.Buffer{}); err != nil {
		t.Fatalf("run with layered customization failed: %v", err)
	}

	payload, err := os.ReadFile(jsonPath)
	if err != nil {
		t.Fatalf("read report json: %v", err)
	}
	var output struct {
		Provenance struct {
			SelectedLocale string `json:"selectedLocale"`
		} `json:"provenance"`
		Report struct {
			Groups []struct {
				Key         string   `json:"key"`
				Name        string   `json:"name"`
				Description string   `json:"description"`
				Obligations []string `json:"obligations"`
			} `json:"groups"`
		} `json:"report"`
	}
	if err := json.Unmarshal(payload, &output); err != nil {
		t.Fatalf("parse report json: %v", err)
	}
	if output.Provenance.SelectedLocale != "en-US" {
		t.Fatalf("selected locale = %#v", output.Provenance)
	}
	foundMIT := false
	for _, group := range output.Report.Groups {
		if group.Key == "MIT" {
			foundMIT = true
			if group.Name != "MIT License (Layered Remote)" || group.Description != "Layered bundle MIT description" || !slices.Equal(group.Obligations, []string{"Carry layered MIT notice"}) {
				t.Fatalf("json mit group = %#v", group)
			}
		}
	}
	if !foundMIT {
		t.Fatalf("json groups = %#v", output.Report.Groups)
	}

	reportHTMLBytes, err := os.ReadFile(reportHTMLPath)
	if err != nil {
		t.Fatalf("read report html: %v", err)
	}
	reportHTML := string(reportHTMLBytes)
	for _, want := range []string{
		"MIT License (Layered Remote)",
		"Layered bundle MIT description",
		"Carry layered MIT notice",
	} {
		if !strings.Contains(reportHTML, want) {
			t.Fatalf("report html missing %q\n%s", want, reportHTML)
		}
	}

	legalHTMLBytes, err := os.ReadFile(legalHTMLPath)
	if err != nil {
		t.Fatalf("read legal html: %v", err)
	}
	legalHTML := string(legalHTMLBytes)
	for _, want := range []string{
		"MIT License (Layered Remote)",
		"layered remote notice",
	} {
		if !strings.Contains(legalHTML, want) {
			t.Fatalf("legal html missing %q\n%s", want, legalHTML)
		}
	}
}

func TestRunPinnedLayeredCustomizationStaysConsistentAcrossOutputs(t *testing.T) {
	t.Parallel()

	remoteBody := `{
  "fallback": "Unknown",
  "licenses": [
    {
      "key": "MIT",
      "name": "MIT License (Pinned Layered Remote)",
      "family": "MIT",
      "copyleft_strength": "none",
      "requires_manual_review": false,
      "spdx_ids": ["MIT"],
      "names": ["MIT License (Pinned Layered Remote)"],
      "contains": ["mit"],
      "risk_level": "low",
      "notice_template": "pinned layered remote notice"
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

	dir := t.TempDir()
	bundlePath := writeEnglishLicenseTextBundleFixtureWithMutation(t, dir, func(bundle map[string]any) {
		updateLicenseTextBundleEntry(bundle, "MIT", func(entry map[string]any) {
			entry["description"] = "Pinned layered MIT description"
			entry["obligations"] = []string{"Carry pinned layered MIT notice"}
		})
	})

	jsonPath := filepath.Join(dir, "report.json")
	reportHTMLPath := filepath.Join(dir, "report.html")
	legalHTMLPath := filepath.Join(dir, "legal.html")

	if err := run([]string{
		"-input", "repository-scan=internal/ci/testdata/repo",
		"-license-catalog", "configs/licenses.json",
		"-license-catalog", catalogServer.URL + "/licenses.json#sha256=" + requestedSHA,
		"-license-text-bundle", bundlePath,
		"-output-html", reportHTMLPath,
		"-output-json", jsonPath,
		"-output-legal-html", legalHTMLPath,
	}, &bytes.Buffer{}); err != nil {
		t.Fatalf("run with pinned layered customization failed: %v", err)
	}

	payload, err := os.ReadFile(jsonPath)
	if err != nil {
		t.Fatalf("read report json: %v", err)
	}
	var output struct {
		Provenance struct {
			SelectedLocale string `json:"selectedLocale"`
			CatalogSources []struct {
				Kind         string `json:"kind"`
				Location     string `json:"location"`
				PinningMode  string `json:"pinningMode"`
				RequestedSHA string `json:"requestedSha256"`
			} `json:"catalogSources"`
		} `json:"provenance"`
		Report struct {
			Groups []struct {
				Key         string   `json:"key"`
				Name        string   `json:"name"`
				Description string   `json:"description"`
				Obligations []string `json:"obligations"`
			} `json:"groups"`
		} `json:"report"`
	}
	if err := json.Unmarshal(payload, &output); err != nil {
		t.Fatalf("parse report json: %v", err)
	}
	if output.Provenance.SelectedLocale != "en-US" {
		t.Fatalf("selected locale = %#v", output.Provenance)
	}
	foundPinned := false
	for _, source := range output.Provenance.CatalogSources {
		if source.Kind == "remote" && source.Location == catalogServer.URL+"/licenses.json#sha256="+requestedSHA {
			foundPinned = true
			if source.PinningMode != "pinned" || source.RequestedSHA != requestedSHA {
				t.Fatalf("pinned source = %#v", source)
			}
		}
	}
	if !foundPinned {
		t.Fatalf("catalog sources = %#v", output.Provenance.CatalogSources)
	}
	foundMIT := false
	for _, group := range output.Report.Groups {
		if group.Key == "MIT" {
			foundMIT = true
			if group.Name != "MIT License (Pinned Layered Remote)" || group.Description != "Pinned layered MIT description" || !slices.Equal(group.Obligations, []string{"Carry pinned layered MIT notice"}) {
				t.Fatalf("json mit group = %#v", group)
			}
		}
	}
	if !foundMIT {
		t.Fatalf("json groups = %#v", output.Report.Groups)
	}

	reportHTMLBytes, err := os.ReadFile(reportHTMLPath)
	if err != nil {
		t.Fatalf("read report html: %v", err)
	}
	reportHTML := string(reportHTMLBytes)
	for _, want := range []string{
		"MIT License (Pinned Layered Remote)",
		"Pinned layered MIT description",
		"Carry pinned layered MIT notice",
	} {
		if !strings.Contains(reportHTML, want) {
			t.Fatalf("report html missing %q\n%s", want, reportHTML)
		}
	}

	legalHTMLBytes, err := os.ReadFile(legalHTMLPath)
	if err != nil {
		t.Fatalf("read legal html: %v", err)
	}
	legalHTML := string(legalHTMLBytes)
	for _, want := range []string{
		"MIT License (Pinned Layered Remote)",
		"pinned layered remote notice",
	} {
		if !strings.Contains(legalHTML, want) {
			t.Fatalf("legal html missing %q\n%s", want, legalHTML)
		}
	}
}

func TestRunMultiSourcePinnedLayeredCustomizationStaysConsistentAcrossOutputs(t *testing.T) {
	t.Parallel()

	remoteBody := `{
  "fallback": "Unknown",
  "licenses": [
    {
      "key": "MIT",
      "name": "MIT License (Pinned Multi-Source Remote)",
      "family": "MIT",
      "copyleft_strength": "none",
      "requires_manual_review": false,
      "spdx_ids": ["MIT"],
      "names": ["MIT License (Pinned Multi-Source Remote)"],
      "contains": ["mit"],
      "risk_level": "low",
      "notice_template": "pinned multi-source remote notice"
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

	dir := t.TempDir()
	bundlePath := writeEnglishLicenseTextBundleFixtureWithMutation(t, dir, func(bundle map[string]any) {
		updateLicenseTextBundleEntry(bundle, "MIT", func(entry map[string]any) {
			entry["description"] = "Pinned multi-source MIT description"
			entry["obligations"] = []string{"Carry pinned multi-source MIT notice"}
		})
	})

	jsonPath := filepath.Join(dir, "report.json")
	reportHTMLPath := filepath.Join(dir, "report.html")
	legalHTMLPath := filepath.Join(dir, "legal.html")

	if err := run([]string{
		"-input", "repository-scan=internal/ci/testdata/repo",
		"-input", "cyclonedx-json=internal/sbom/testdata/cyclonedx/app.json",
		"-license-catalog", "configs/licenses.json",
		"-license-catalog", catalogServer.URL + "/licenses.json#sha256=" + requestedSHA,
		"-license-text-bundle", bundlePath,
		"-output-html", reportHTMLPath,
		"-output-json", jsonPath,
		"-output-legal-html", legalHTMLPath,
	}, &bytes.Buffer{}); err != nil {
		t.Fatalf("run with multi-source pinned layered customization failed: %v", err)
	}

	payload, err := os.ReadFile(jsonPath)
	if err != nil {
		t.Fatalf("read report json: %v", err)
	}
	var output struct {
		Provenance struct {
			InputKind      string `json:"inputKind"`
			SelectedLocale string `json:"selectedLocale"`
			CatalogSources []struct {
				Kind         string `json:"kind"`
				Location     string `json:"location"`
				PinningMode  string `json:"pinningMode"`
				RequestedSHA string `json:"requestedSha256"`
			} `json:"catalogSources"`
		} `json:"provenance"`
		Report struct {
			Root   string `json:"root"`
			Groups []struct {
				Key         string   `json:"key"`
				Name        string   `json:"name"`
				Description string   `json:"description"`
				Obligations []string `json:"obligations"`
			} `json:"groups"`
		} `json:"report"`
	}
	if err := json.Unmarshal(payload, &output); err != nil {
		t.Fatalf("parse report json: %v", err)
	}
	if output.Provenance.InputKind != "multi-source" || output.Provenance.SelectedLocale != "en-US" {
		t.Fatalf("provenance = %#v", output.Provenance)
	}
	if output.Report.Root != rootDisplay("internal/ci/testdata/repo", "internal/sbom/testdata/cyclonedx/app.json") {
		t.Fatalf("report root = %q", output.Report.Root)
	}
	foundPinned := false
	for _, source := range output.Provenance.CatalogSources {
		if source.Kind == "remote" && source.Location == catalogServer.URL+"/licenses.json#sha256="+requestedSHA {
			foundPinned = true
			if source.PinningMode != "pinned" || source.RequestedSHA != requestedSHA {
				t.Fatalf("pinned source = %#v", source)
			}
		}
	}
	if !foundPinned {
		t.Fatalf("catalog sources = %#v", output.Provenance.CatalogSources)
	}
	foundMIT := false
	for _, group := range output.Report.Groups {
		if group.Key == "MIT" {
			foundMIT = true
			if group.Name != "MIT License (Pinned Multi-Source Remote)" || group.Description != "Pinned multi-source MIT description" || !slices.Equal(group.Obligations, []string{"Carry pinned multi-source MIT notice"}) {
				t.Fatalf("json mit group = %#v", group)
			}
		}
	}
	if !foundMIT {
		t.Fatalf("json groups = %#v", output.Report.Groups)
	}

	reportHTMLBytes, err := os.ReadFile(reportHTMLPath)
	if err != nil {
		t.Fatalf("read report html: %v", err)
	}
	reportHTML := string(reportHTMLBytes)
	for _, want := range []string{
		`Input: <code>` + escapedRootDisplay("internal/ci/testdata/repo", "internal/sbom/testdata/cyclonedx/app.json") + `</code>`,
		"MIT License (Pinned Multi-Source Remote)",
		"Pinned multi-source MIT description",
		"Carry pinned multi-source MIT notice",
	} {
		if !strings.Contains(reportHTML, want) {
			t.Fatalf("report html missing %q\n%s", want, reportHTML)
		}
	}

	legalHTMLBytes, err := os.ReadFile(legalHTMLPath)
	if err != nil {
		t.Fatalf("read legal html: %v", err)
	}
	legalHTML := string(legalHTMLBytes)
	for _, want := range []string{
		`Repository root: <code>` + escapedRootDisplay("internal/ci/testdata/repo", "internal/sbom/testdata/cyclonedx/app.json") + `</code>`,
		"MIT License (Pinned Multi-Source Remote)",
		"pinned multi-source remote notice",
	} {
		if !strings.Contains(legalHTML, want) {
			t.Fatalf("legal html missing %q\n%s", want, legalHTML)
		}
	}
}

func TestRunMultiSourcePinnedVulnerabilityStaysConsistentAcrossOutputs(t *testing.T) {
	t.Parallel()

	remoteBody := `{
  "fallback": "Unknown",
  "licenses": [
    {
      "key": "MIT",
      "name": "MIT License (Pinned Vulnerability Remote)",
      "family": "MIT",
      "copyleft_strength": "none",
      "requires_manual_review": false,
      "spdx_ids": ["MIT"],
      "names": ["MIT License (Pinned Vulnerability Remote)"],
      "contains": ["mit"],
      "risk_level": "low",
      "notice_template": "pinned vulnerability remote notice"
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
			_, _ = w.Write([]byte(`{"results":[{"vulns":[{"id":"CVE-2026-1001"}]},{"vulns":[]},{"vulns":[]},{"vulns":[]},{"vulns":[]},{"vulns":[]}]} `))
		case "/advisories":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`[
  {
    "ghsa_id":"GHSA-react-pinned-multi-1",
    "cve_id":"CVE-2026-1001",
    "html_url":"https://github.com/advisories/GHSA-react-pinned-multi-1",
    "summary":"Pinned multi-source advisory",
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
        "id":"CVE-2026-1001",
        "vendorComments":[{"organization":"vendor-a","comment":"Pinned multi-source patch available"}],
        "metrics":{
          "cvssMetricV40":[{"type":"Primary","cvssData":{"baseScore":9.1,"baseSeverity":"CRITICAL","vectorString":"CVSS:4.0/..."}}]
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
	reportJSONPath := filepath.Join(dir, "report.json")
	reportHTMLPath := filepath.Join(dir, "report.html")
	legalHTMLPath := filepath.Join(dir, "legal.html")
	vulnJSONPath := filepath.Join(dir, "vuln.json")
	vulnHTMLPath := filepath.Join(dir, "vuln.html")

	if err := run([]string{
		"-input", "repository-scan=internal/ci/testdata/repo",
		"-input", "cyclonedx-json=internal/sbom/testdata/cyclonedx/app.json",
		"-license-catalog", "configs/licenses.json",
		"-license-catalog", catalogServer.URL + "/licenses.json#sha256=" + requestedSHA,
		"-output-html", reportHTMLPath,
		"-output-json", reportJSONPath,
		"-output-legal-html", legalHTMLPath,
		"-output-vuln-json", vulnJSONPath,
		"-output-vuln-html", vulnHTMLPath,
		"-vuln-mode", "full",
		"-osv-base-url", vulnServer.URL,
		"-github-advisory-base-url", vulnServer.URL,
		"-nvd-base-url", vulnServer.URL,
	}, &bytes.Buffer{}); err != nil {
		t.Fatalf("run with multi-source pinned vulnerability consistency failed: %v", err)
	}

	reportPayload, err := os.ReadFile(reportJSONPath)
	if err != nil {
		t.Fatalf("read report json: %v", err)
	}
	var reportOutput struct {
		Provenance struct {
			InputKind      string `json:"inputKind"`
			CatalogSources []struct {
				Kind         string `json:"kind"`
				Location     string `json:"location"`
				PinningMode  string `json:"pinningMode"`
				RequestedSHA string `json:"requestedSha256"`
			} `json:"catalogSources"`
		} `json:"provenance"`
		Report struct {
			Root   string `json:"root"`
			Groups []struct {
				Key  string `json:"key"`
				Name string `json:"name"`
			} `json:"groups"`
		} `json:"report"`
	}
	if err := json.Unmarshal(reportPayload, &reportOutput); err != nil {
		t.Fatalf("parse report json: %v", err)
	}
	if reportOutput.Provenance.InputKind != "multi-source" {
		t.Fatalf("report provenance = %#v", reportOutput.Provenance)
	}
	if reportOutput.Report.Root != rootDisplay("internal/ci/testdata/repo", "internal/sbom/testdata/cyclonedx/app.json") {
		t.Fatalf("report root = %q", reportOutput.Report.Root)
	}
	foundPinned := false
	for _, source := range reportOutput.Provenance.CatalogSources {
		if source.Kind == "remote" && source.Location == catalogServer.URL+"/licenses.json#sha256="+requestedSHA {
			foundPinned = true
			if source.PinningMode != "pinned" || source.RequestedSHA != requestedSHA {
				t.Fatalf("pinned source = %#v", source)
			}
		}
	}
	if !foundPinned {
		t.Fatalf("catalog sources = %#v", reportOutput.Provenance.CatalogSources)
	}
	foundMIT := false
	for _, group := range reportOutput.Report.Groups {
		if group.Key == "MIT" && group.Name == "MIT License (Pinned Vulnerability Remote)" {
			foundMIT = true
		}
	}
	if !foundMIT {
		t.Fatalf("report groups = %#v", reportOutput.Report.Groups)
	}

	reportHTMLBytes, err := os.ReadFile(reportHTMLPath)
	if err != nil {
		t.Fatalf("read report html: %v", err)
	}
	reportHTML := string(reportHTMLBytes)
	for _, want := range []string{
		`Input: <code>` + escapedRootDisplay("internal/ci/testdata/repo", "internal/sbom/testdata/cyclonedx/app.json") + `</code>`,
		"MIT License (Pinned Vulnerability Remote)",
	} {
		if !strings.Contains(reportHTML, want) {
			t.Fatalf("report html missing %q\n%s", want, reportHTML)
		}
	}

	legalHTMLBytes, err := os.ReadFile(legalHTMLPath)
	if err != nil {
		t.Fatalf("read legal html: %v", err)
	}
	legalHTML := string(legalHTMLBytes)
	for _, want := range []string{
		`Repository root: <code>` + escapedRootDisplay("internal/ci/testdata/repo", "internal/sbom/testdata/cyclonedx/app.json") + `</code>`,
		"MIT License (Pinned Vulnerability Remote)",
		"pinned vulnerability remote notice",
	} {
		if !strings.Contains(legalHTML, want) {
			t.Fatalf("legal html missing %q\n%s", want, legalHTML)
		}
	}

	vulnPayload, err := os.ReadFile(vulnJSONPath)
	if err != nil {
		t.Fatalf("read vulnerability json: %v", err)
	}
	var vulnOutput struct {
		Provenance struct {
			Sources []string `json:"sources"`
		} `json:"provenance"`
		Checklist struct {
			Mode            string `json:"mode"`
			PackageFindings []struct {
				Name       string `json:"name"`
				Advisories []struct {
					ID        string  `json:"id"`
					Summary   string  `json:"summary"`
					CVSSScore float64 `json:"cvssScore"`
				} `json:"advisories"`
			} `json:"packageFindings"`
		} `json:"checklist"`
	}
	if err := json.Unmarshal(vulnPayload, &vulnOutput); err != nil {
		t.Fatalf("parse vulnerability json: %v", err)
	}
	if vulnOutput.Checklist.Mode != "full" {
		t.Fatalf("vulnerability checklist = %#v", vulnOutput.Checklist)
	}
	for _, want := range []string{"cyclonedx-json", "github-advisory", "metadata-enrichment", "nvd", "osv", "repository-scan"} {
		if !slices.Contains(vulnOutput.Provenance.Sources, want) {
			t.Fatalf("vulnerability sources missing %q in %#v", want, vulnOutput.Provenance.Sources)
		}
	}
	foundAdvisory := false
	for _, finding := range vulnOutput.Checklist.PackageFindings {
		for _, advisory := range finding.Advisories {
			if advisory.ID == "GHSA-react-pinned-multi-1" {
				foundAdvisory = true
				if advisory.Summary != "Pinned multi-source advisory" || advisory.CVSSScore != 9.1 {
					t.Fatalf("advisory = %#v", advisory)
				}
			}
		}
	}
	if !foundAdvisory {
		t.Fatalf("package findings = %#v", vulnOutput.Checklist.PackageFindings)
	}

	vulnHTMLBytes, err := os.ReadFile(vulnHTMLPath)
	if err != nil {
		t.Fatalf("read vulnerability html: %v", err)
	}
	vulnHTML := string(vulnHTMLBytes)
	for _, want := range []string{
		"Sources: cyclonedx-json, github-advisory, metadata-enrichment, nvd, osv, repository-scan",
		"GHSA-react-pinned-multi-1",
		"Pinned multi-source advisory",
		"CVSS 9.1",
	} {
		if !strings.Contains(vulnHTML, want) {
			t.Fatalf("vulnerability html missing %q\n%s", want, vulnHTML)
		}
	}
}

func TestRunSPDXMultiSourcePinnedLayeredCustomizationStaysConsistentAcrossOutputs(t *testing.T) {
	t.Parallel()

	remoteBody := `{
  "fallback": "Unknown",
  "licenses": [
    {
      "key": "MIT",
      "name": "MIT License (Pinned SPDX Remote)",
      "family": "MIT",
      "copyleft_strength": "none",
      "requires_manual_review": false,
      "spdx_ids": ["MIT"],
      "names": ["MIT License (Pinned SPDX Remote)"],
      "contains": ["mit"],
      "risk_level": "low",
      "notice_template": "pinned spdx remote notice"
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

	dir := t.TempDir()
	bundlePath := writeEnglishLicenseTextBundleFixtureWithMutation(t, dir, func(bundle map[string]any) {
		updateLicenseTextBundleEntry(bundle, "MIT", func(entry map[string]any) {
			entry["description"] = "Pinned SPDX MIT description"
			entry["obligations"] = []string{"Carry pinned SPDX MIT notice"}
		})
	})

	jsonPath := filepath.Join(dir, "report.json")
	reportHTMLPath := filepath.Join(dir, "report.html")
	legalHTMLPath := filepath.Join(dir, "legal.html")

	if err := run([]string{
		"-input", "repository-scan=internal/ci/testdata/repo",
		"-input", "spdx-json=internal/sbom/testdata/spdx/app.json",
		"-license-catalog", "configs/licenses.json",
		"-license-catalog", catalogServer.URL + "/licenses.json#sha256=" + requestedSHA,
		"-license-text-bundle", bundlePath,
		"-output-html", reportHTMLPath,
		"-output-json", jsonPath,
		"-output-legal-html", legalHTMLPath,
	}, &bytes.Buffer{}); err != nil {
		t.Fatalf("run with SPDX multi-source pinned layered customization failed: %v", err)
	}

	payload, err := os.ReadFile(jsonPath)
	if err != nil {
		t.Fatalf("read report json: %v", err)
	}
	var output struct {
		Provenance struct {
			InputKind      string `json:"inputKind"`
			SelectedLocale string `json:"selectedLocale"`
			CatalogSources []struct {
				Kind         string `json:"kind"`
				Location     string `json:"location"`
				PinningMode  string `json:"pinningMode"`
				RequestedSHA string `json:"requestedSha256"`
			} `json:"catalogSources"`
		} `json:"provenance"`
		Report struct {
			Root   string `json:"root"`
			Groups []struct {
				Key         string   `json:"key"`
				Name        string   `json:"name"`
				Description string   `json:"description"`
				Obligations []string `json:"obligations"`
			} `json:"groups"`
		} `json:"report"`
	}
	if err := json.Unmarshal(payload, &output); err != nil {
		t.Fatalf("parse report json: %v", err)
	}
	if output.Provenance.InputKind != "multi-source" || output.Provenance.SelectedLocale != "en-US" {
		t.Fatalf("provenance = %#v", output.Provenance)
	}
	if output.Report.Root != rootDisplay("internal/ci/testdata/repo", "internal/sbom/testdata/spdx/app.json") {
		t.Fatalf("report root = %q", output.Report.Root)
	}
	foundPinned := false
	for _, source := range output.Provenance.CatalogSources {
		if source.Kind == "remote" && source.Location == catalogServer.URL+"/licenses.json#sha256="+requestedSHA {
			foundPinned = true
			if source.PinningMode != "pinned" || source.RequestedSHA != requestedSHA {
				t.Fatalf("pinned source = %#v", source)
			}
		}
	}
	if !foundPinned {
		t.Fatalf("catalog sources = %#v", output.Provenance.CatalogSources)
	}
	foundMIT := false
	for _, group := range output.Report.Groups {
		if group.Key == "MIT" {
			foundMIT = true
			if group.Name != "MIT License (Pinned SPDX Remote)" || group.Description != "Pinned SPDX MIT description" || !slices.Equal(group.Obligations, []string{"Carry pinned SPDX MIT notice"}) {
				t.Fatalf("json mit group = %#v", group)
			}
		}
	}
	if !foundMIT {
		t.Fatalf("json groups = %#v", output.Report.Groups)
	}

	reportHTMLBytes, err := os.ReadFile(reportHTMLPath)
	if err != nil {
		t.Fatalf("read report html: %v", err)
	}
	reportHTML := string(reportHTMLBytes)
	for _, want := range []string{
		`Input: <code>` + escapedRootDisplay("internal/ci/testdata/repo", "internal/sbom/testdata/spdx/app.json") + `</code>`,
		"MIT License (Pinned SPDX Remote)",
		"Pinned SPDX MIT description",
		"Carry pinned SPDX MIT notice",
	} {
		if !strings.Contains(reportHTML, want) {
			t.Fatalf("report html missing %q\n%s", want, reportHTML)
		}
	}

	legalHTMLBytes, err := os.ReadFile(legalHTMLPath)
	if err != nil {
		t.Fatalf("read legal html: %v", err)
	}
	legalHTML := string(legalHTMLBytes)
	for _, want := range []string{
		`Repository root: <code>` + escapedRootDisplay("internal/ci/testdata/repo", "internal/sbom/testdata/spdx/app.json") + `</code>`,
		"MIT License (Pinned SPDX Remote)",
		"pinned spdx remote notice",
	} {
		if !strings.Contains(legalHTML, want) {
			t.Fatalf("legal html missing %q\n%s", want, legalHTML)
		}
	}
}

func TestRunSPDXMultiSourcePinnedVulnerabilityStaysConsistentAcrossOutputs(t *testing.T) {
	t.Parallel()

	remoteBody := `{
  "fallback": "Unknown",
  "licenses": [
    {
      "key": "MIT",
      "name": "MIT License (Pinned SPDX Vulnerability Remote)",
      "family": "MIT",
      "copyleft_strength": "none",
      "requires_manual_review": false,
      "spdx_ids": ["MIT"],
      "names": ["MIT License (Pinned SPDX Vulnerability Remote)"],
      "contains": ["mit"],
      "risk_level": "low",
      "notice_template": "pinned spdx vulnerability remote notice"
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
			_, _ = w.Write([]byte(`{"results":[{"vulns":[{"id":"CVE-2026-1002"}]},{"vulns":[]},{"vulns":[]},{"vulns":[]},{"vulns":[]},{"vulns":[]}]} `))
		case "/advisories":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`[
  {
    "ghsa_id":"GHSA-react-pinned-spdx-1",
    "cve_id":"CVE-2026-1002",
    "html_url":"https://github.com/advisories/GHSA-react-pinned-spdx-1",
    "summary":"Pinned SPDX advisory",
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
        "id":"CVE-2026-1002",
        "vendorComments":[{"organization":"vendor-a","comment":"Pinned SPDX patch available"}],
        "metrics":{
          "cvssMetricV40":[{"type":"Primary","cvssData":{"baseScore":9.0,"baseSeverity":"CRITICAL","vectorString":"CVSS:4.0/..."}}]
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
	reportJSONPath := filepath.Join(dir, "report.json")
	reportHTMLPath := filepath.Join(dir, "report.html")
	legalHTMLPath := filepath.Join(dir, "legal.html")
	vulnJSONPath := filepath.Join(dir, "vuln.json")
	vulnHTMLPath := filepath.Join(dir, "vuln.html")

	if err := run([]string{
		"-input", "repository-scan=internal/ci/testdata/repo",
		"-input", "spdx-json=internal/sbom/testdata/spdx/app.json",
		"-license-catalog", "configs/licenses.json",
		"-license-catalog", catalogServer.URL + "/licenses.json#sha256=" + requestedSHA,
		"-output-html", reportHTMLPath,
		"-output-json", reportJSONPath,
		"-output-legal-html", legalHTMLPath,
		"-output-vuln-json", vulnJSONPath,
		"-output-vuln-html", vulnHTMLPath,
		"-vuln-mode", "full",
		"-osv-base-url", vulnServer.URL,
		"-github-advisory-base-url", vulnServer.URL,
		"-nvd-base-url", vulnServer.URL,
	}, &bytes.Buffer{}); err != nil {
		t.Fatalf("run with SPDX multi-source pinned vulnerability consistency failed: %v", err)
	}

	reportPayload, err := os.ReadFile(reportJSONPath)
	if err != nil {
		t.Fatalf("read report json: %v", err)
	}
	var reportOutput struct {
		Provenance struct {
			InputKind      string `json:"inputKind"`
			CatalogSources []struct {
				Kind         string `json:"kind"`
				Location     string `json:"location"`
				PinningMode  string `json:"pinningMode"`
				RequestedSHA string `json:"requestedSha256"`
			} `json:"catalogSources"`
		} `json:"provenance"`
		Report struct {
			Root   string `json:"root"`
			Groups []struct {
				Key  string `json:"key"`
				Name string `json:"name"`
			} `json:"groups"`
		} `json:"report"`
	}
	if err := json.Unmarshal(reportPayload, &reportOutput); err != nil {
		t.Fatalf("parse report json: %v", err)
	}
	if reportOutput.Provenance.InputKind != "multi-source" {
		t.Fatalf("report provenance = %#v", reportOutput.Provenance)
	}
	if reportOutput.Report.Root != rootDisplay("internal/ci/testdata/repo", "internal/sbom/testdata/spdx/app.json") {
		t.Fatalf("report root = %q", reportOutput.Report.Root)
	}
	foundPinned := false
	for _, source := range reportOutput.Provenance.CatalogSources {
		if source.Kind == "remote" && source.Location == catalogServer.URL+"/licenses.json#sha256="+requestedSHA {
			foundPinned = true
			if source.PinningMode != "pinned" || source.RequestedSHA != requestedSHA {
				t.Fatalf("pinned source = %#v", source)
			}
		}
	}
	if !foundPinned {
		t.Fatalf("catalog sources = %#v", reportOutput.Provenance.CatalogSources)
	}
	foundMIT := false
	for _, group := range reportOutput.Report.Groups {
		if group.Key == "MIT" && group.Name == "MIT License (Pinned SPDX Vulnerability Remote)" {
			foundMIT = true
		}
	}
	if !foundMIT {
		t.Fatalf("report groups = %#v", reportOutput.Report.Groups)
	}

	reportHTMLBytes, err := os.ReadFile(reportHTMLPath)
	if err != nil {
		t.Fatalf("read report html: %v", err)
	}
	reportHTML := string(reportHTMLBytes)
	for _, want := range []string{
		`Input: <code>` + escapedRootDisplay("internal/ci/testdata/repo", "internal/sbom/testdata/spdx/app.json") + `</code>`,
		"MIT License (Pinned SPDX Vulnerability Remote)",
	} {
		if !strings.Contains(reportHTML, want) {
			t.Fatalf("report html missing %q\n%s", want, reportHTML)
		}
	}

	legalHTMLBytes, err := os.ReadFile(legalHTMLPath)
	if err != nil {
		t.Fatalf("read legal html: %v", err)
	}
	legalHTML := string(legalHTMLBytes)
	for _, want := range []string{
		`Repository root: <code>` + escapedRootDisplay("internal/ci/testdata/repo", "internal/sbom/testdata/spdx/app.json") + `</code>`,
		"MIT License (Pinned SPDX Vulnerability Remote)",
		"pinned spdx vulnerability remote notice",
	} {
		if !strings.Contains(legalHTML, want) {
			t.Fatalf("legal html missing %q\n%s", want, legalHTML)
		}
	}

	vulnPayload, err := os.ReadFile(vulnJSONPath)
	if err != nil {
		t.Fatalf("read vulnerability json: %v", err)
	}
	var vulnOutput struct {
		Provenance struct {
			Sources []string `json:"sources"`
		} `json:"provenance"`
		Checklist struct {
			Mode            string `json:"mode"`
			PackageFindings []struct {
				Name       string `json:"name"`
				Advisories []struct {
					ID        string  `json:"id"`
					Summary   string  `json:"summary"`
					CVSSScore float64 `json:"cvssScore"`
				} `json:"advisories"`
			} `json:"packageFindings"`
		} `json:"checklist"`
	}
	if err := json.Unmarshal(vulnPayload, &vulnOutput); err != nil {
		t.Fatalf("parse vulnerability json: %v", err)
	}
	if vulnOutput.Checklist.Mode != "full" {
		t.Fatalf("vulnerability checklist = %#v", vulnOutput.Checklist)
	}
	for _, want := range []string{"github-advisory", "metadata-enrichment", "nvd", "osv", "repository-scan", "spdx-json"} {
		if !slices.Contains(vulnOutput.Provenance.Sources, want) {
			t.Fatalf("vulnerability sources missing %q in %#v", want, vulnOutput.Provenance.Sources)
		}
	}
	foundAdvisory := false
	for _, finding := range vulnOutput.Checklist.PackageFindings {
		for _, advisory := range finding.Advisories {
			if advisory.ID == "GHSA-react-pinned-spdx-1" {
				foundAdvisory = true
				if advisory.Summary != "Pinned SPDX advisory" || advisory.CVSSScore != 9.0 {
					t.Fatalf("advisory = %#v", advisory)
				}
			}
		}
	}
	if !foundAdvisory {
		t.Fatalf("package findings = %#v", vulnOutput.Checklist.PackageFindings)
	}

	vulnHTMLBytes, err := os.ReadFile(vulnHTMLPath)
	if err != nil {
		t.Fatalf("read vulnerability html: %v", err)
	}
	vulnHTML := string(vulnHTMLBytes)
	for _, want := range []string{
		"Sources: github-advisory, metadata-enrichment, nvd, osv, repository-scan, spdx-json",
		"GHSA-react-pinned-spdx-1",
		"Pinned SPDX advisory",
		"CVSS 9",
	} {
		if !strings.Contains(vulnHTML, want) {
			t.Fatalf("vulnerability html missing %q\n%s", want, vulnHTML)
		}
	}
}

func TestRunAllCustomizationsStayConsistentAcrossFullOutputs(t *testing.T) {
	t.Parallel()

	remoteBody := `{
  "fallback": "Unknown",
  "licenses": [
    {
      "key": "MIT",
      "name": "MIT License (Pinned All Customizations Remote)",
      "family": "MIT",
      "copyleft_strength": "none",
      "requires_manual_review": false,
      "spdx_ids": ["MIT"],
      "names": ["MIT License (Pinned All Customizations Remote)"],
      "contains": ["mit"],
      "risk_level": "low",
      "notice_template": "pinned all customizations remote notice"
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
			_, _ = w.Write([]byte(`{"results":[{"vulns":[{"id":"CVE-2026-2001"}]},{"vulns":[]},{"vulns":[]},{"vulns":[]}]} `))
		case "/advisories":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`[
  {
    "ghsa_id":"GHSA-react-all-custom-1",
    "cve_id":"CVE-2026-2001",
    "html_url":"https://github.com/advisories/GHSA-react-all-custom-1",
    "summary":"All customizations advisory",
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
        "id":"CVE-2026-2001",
        "vendorComments":[{"organization":"vendor-a","comment":"All customizations patch available"}],
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
			entry["description"] = "All customizations MIT description"
			entry["obligations"] = []string{"Carry all customizations MIT notice"}
		})
	})

	reportJSONPath := filepath.Join(dir, "report.json")
	reportHTMLPath := filepath.Join(dir, "report.html")
	legalHTMLPath := filepath.Join(dir, "legal.html")
	vulnJSONPath := filepath.Join(dir, "vuln.json")
	vulnHTMLPath := filepath.Join(dir, "vuln.html")

	if err := run([]string{
		"-input", "repository-scan=internal/ci/testdata/repo",
		"-license-catalog", "configs/licenses.json",
		"-license-catalog", catalogServer.URL + "/licenses.json#sha256=" + requestedSHA,
		"-license-text-bundle", bundlePath,
		"-output-html", reportHTMLPath,
		"-output-json", reportJSONPath,
		"-output-legal-html", legalHTMLPath,
		"-output-vuln-json", vulnJSONPath,
		"-output-vuln-html", vulnHTMLPath,
		"-vuln-mode", "full",
		"-osv-base-url", vulnServer.URL,
		"-github-advisory-base-url", vulnServer.URL,
		"-nvd-base-url", vulnServer.URL,
	}, &bytes.Buffer{}); err != nil {
		t.Fatalf("run with all customizations failed: %v", err)
	}

	reportPayload, err := os.ReadFile(reportJSONPath)
	if err != nil {
		t.Fatalf("read report json: %v", err)
	}
	var reportOutput struct {
		Provenance struct {
			SelectedLocale string `json:"selectedLocale"`
			CatalogSources []struct {
				Kind         string `json:"kind"`
				Location     string `json:"location"`
				PinningMode  string `json:"pinningMode"`
				RequestedSHA string `json:"requestedSha256"`
			} `json:"catalogSources"`
		} `json:"provenance"`
		Report struct {
			Groups []struct {
				Key         string   `json:"key"`
				Name        string   `json:"name"`
				Description string   `json:"description"`
				Obligations []string `json:"obligations"`
			} `json:"groups"`
		} `json:"report"`
	}
	if err := json.Unmarshal(reportPayload, &reportOutput); err != nil {
		t.Fatalf("parse report json: %v", err)
	}
	if reportOutput.Provenance.SelectedLocale != "en-US" {
		t.Fatalf("report provenance = %#v", reportOutput.Provenance)
	}
	foundPinned := false
	for _, source := range reportOutput.Provenance.CatalogSources {
		if source.Kind == "remote" && source.Location == catalogServer.URL+"/licenses.json#sha256="+requestedSHA {
			foundPinned = true
			if source.PinningMode != "pinned" || source.RequestedSHA != requestedSHA {
				t.Fatalf("pinned source = %#v", source)
			}
		}
	}
	if !foundPinned {
		t.Fatalf("catalog sources = %#v", reportOutput.Provenance.CatalogSources)
	}
	foundMIT := false
	for _, group := range reportOutput.Report.Groups {
		if group.Key == "MIT" {
			foundMIT = true
			if group.Name != "MIT License (Pinned All Customizations Remote)" || group.Description != "All customizations MIT description" || !slices.Equal(group.Obligations, []string{"Carry all customizations MIT notice"}) {
				t.Fatalf("report mit group = %#v", group)
			}
		}
	}
	if !foundMIT {
		t.Fatalf("report groups = %#v", reportOutput.Report.Groups)
	}

	reportHTMLBytes, err := os.ReadFile(reportHTMLPath)
	if err != nil {
		t.Fatalf("read report html: %v", err)
	}
	reportHTML := string(reportHTMLBytes)
	for _, want := range []string{
		"MIT License (Pinned All Customizations Remote)",
		"All customizations MIT description",
		"Carry all customizations MIT notice",
	} {
		if !strings.Contains(reportHTML, want) {
			t.Fatalf("report html missing %q\n%s", want, reportHTML)
		}
	}

	legalHTMLBytes, err := os.ReadFile(legalHTMLPath)
	if err != nil {
		t.Fatalf("read legal html: %v", err)
	}
	legalHTML := string(legalHTMLBytes)
	for _, want := range []string{
		"MIT License (Pinned All Customizations Remote)",
		"pinned all customizations remote notice",
	} {
		if !strings.Contains(legalHTML, want) {
			t.Fatalf("legal html missing %q\n%s", want, legalHTML)
		}
	}

	vulnPayload, err := os.ReadFile(vulnJSONPath)
	if err != nil {
		t.Fatalf("read vulnerability json: %v", err)
	}
	var vulnOutput struct {
		Provenance struct {
			Sources []string `json:"sources"`
		} `json:"provenance"`
		Checklist struct {
			Mode            string `json:"mode"`
			PackageFindings []struct {
				Advisories []struct {
					ID        string  `json:"id"`
					Summary   string  `json:"summary"`
					CVSSScore float64 `json:"cvssScore"`
				} `json:"advisories"`
			} `json:"packageFindings"`
		} `json:"checklist"`
	}
	if err := json.Unmarshal(vulnPayload, &vulnOutput); err != nil {
		t.Fatalf("parse vulnerability json: %v", err)
	}
	if vulnOutput.Checklist.Mode != "full" {
		t.Fatalf("vulnerability checklist = %#v", vulnOutput.Checklist)
	}
	for _, want := range []string{"github-advisory", "metadata-enrichment", "nvd", "osv", "repository-scan"} {
		if !slices.Contains(vulnOutput.Provenance.Sources, want) {
			t.Fatalf("vulnerability sources missing %q in %#v", want, vulnOutput.Provenance.Sources)
		}
	}
	foundAdvisory := false
	for _, finding := range vulnOutput.Checklist.PackageFindings {
		for _, advisory := range finding.Advisories {
			if advisory.ID == "GHSA-react-all-custom-1" {
				foundAdvisory = true
				if advisory.Summary != "All customizations advisory" || advisory.CVSSScore != 9.2 {
					t.Fatalf("advisory = %#v", advisory)
				}
			}
		}
	}
	if !foundAdvisory {
		t.Fatalf("package findings = %#v", vulnOutput.Checklist.PackageFindings)
	}

	vulnHTMLBytes, err := os.ReadFile(vulnHTMLPath)
	if err != nil {
		t.Fatalf("read vulnerability html: %v", err)
	}
	vulnHTML := string(vulnHTMLBytes)
	for _, want := range []string{
		"Sources: github-advisory, metadata-enrichment, nvd, osv, repository-scan",
		"GHSA-react-all-custom-1",
		"All customizations advisory",
		"CVSS 9.2",
	} {
		if !strings.Contains(vulnHTML, want) {
			t.Fatalf("vulnerability html missing %q\n%s", want, vulnHTML)
		}
	}
}

func TestRunSPDXAllCustomizationsStayConsistentAcrossFullOutputs(t *testing.T) {
	t.Parallel()

	remoteBody := `{
  "fallback": "Unknown",
  "licenses": [
    {
      "key": "MIT",
      "name": "MIT License (Pinned SPDX All Customizations Remote)",
      "family": "MIT",
      "copyleft_strength": "none",
      "requires_manual_review": false,
      "spdx_ids": ["MIT"],
      "names": ["MIT License (Pinned SPDX All Customizations Remote)"],
      "contains": ["mit"],
      "risk_level": "low",
      "notice_template": "pinned spdx all customizations remote notice"
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
			_, _ = w.Write([]byte(`{"results":[{"vulns":[{"id":"CVE-2026-2002"}]},{"vulns":[]},{"vulns":[]},{"vulns":[]},{"vulns":[]},{"vulns":[]}]} `))
		case "/advisories":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`[
  {
    "ghsa_id":"GHSA-react-spdx-all-custom-1",
    "cve_id":"CVE-2026-2002",
    "html_url":"https://github.com/advisories/GHSA-react-spdx-all-custom-1",
    "summary":"SPDX all customizations advisory",
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
        "id":"CVE-2026-2002",
        "vendorComments":[{"organization":"vendor-a","comment":"SPDX all customizations patch available"}],
        "metrics":{
          "cvssMetricV40":[{"type":"Primary","cvssData":{"baseScore":9.4,"baseSeverity":"CRITICAL","vectorString":"CVSS:4.0/..."}}]
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
			entry["description"] = "SPDX all customizations MIT description"
			entry["obligations"] = []string{"Carry SPDX all customizations MIT notice"}
		})
	})

	reportJSONPath := filepath.Join(dir, "report.json")
	reportHTMLPath := filepath.Join(dir, "report.html")
	legalHTMLPath := filepath.Join(dir, "legal.html")
	vulnJSONPath := filepath.Join(dir, "vuln.json")
	vulnHTMLPath := filepath.Join(dir, "vuln.html")

	if err := run([]string{
		"-input", "spdx-json=internal/sbom/testdata/spdx/app.json",
		"-license-catalog", "configs/licenses.json",
		"-license-catalog", catalogServer.URL + "/licenses.json#sha256=" + requestedSHA,
		"-license-text-bundle", bundlePath,
		"-output-html", reportHTMLPath,
		"-output-json", reportJSONPath,
		"-output-legal-html", legalHTMLPath,
		"-output-vuln-json", vulnJSONPath,
		"-output-vuln-html", vulnHTMLPath,
		"-vuln-mode", "full",
		"-osv-base-url", vulnServer.URL,
		"-github-advisory-base-url", vulnServer.URL,
		"-nvd-base-url", vulnServer.URL,
	}, &bytes.Buffer{}); err != nil {
		t.Fatalf("run with SPDX all customizations failed: %v", err)
	}

	reportPayload, err := os.ReadFile(reportJSONPath)
	if err != nil {
		t.Fatalf("read report json: %v", err)
	}
	var reportOutput struct {
		Provenance struct {
			InputKind      string `json:"inputKind"`
			SelectedLocale string `json:"selectedLocale"`
			CatalogSources []struct {
				Kind         string `json:"kind"`
				Location     string `json:"location"`
				PinningMode  string `json:"pinningMode"`
				RequestedSHA string `json:"requestedSha256"`
			} `json:"catalogSources"`
		} `json:"provenance"`
		Report struct {
			Groups []struct {
				Key         string   `json:"key"`
				Name        string   `json:"name"`
				Description string   `json:"description"`
				Obligations []string `json:"obligations"`
			} `json:"groups"`
		} `json:"report"`
	}
	if err := json.Unmarshal(reportPayload, &reportOutput); err != nil {
		t.Fatalf("parse report json: %v", err)
	}
	if reportOutput.Provenance.InputKind != "spdx-json" || reportOutput.Provenance.SelectedLocale != "en-US" {
		t.Fatalf("report provenance = %#v", reportOutput.Provenance)
	}
	foundPinned := false
	for _, source := range reportOutput.Provenance.CatalogSources {
		if source.Kind == "remote" && source.Location == catalogServer.URL+"/licenses.json#sha256="+requestedSHA {
			foundPinned = true
			if source.PinningMode != "pinned" || source.RequestedSHA != requestedSHA {
				t.Fatalf("pinned source = %#v", source)
			}
		}
	}
	if !foundPinned {
		t.Fatalf("catalog sources = %#v", reportOutput.Provenance.CatalogSources)
	}
	foundMIT := false
	for _, group := range reportOutput.Report.Groups {
		if group.Key == "MIT" {
			foundMIT = true
			if group.Name != "MIT License (Pinned SPDX All Customizations Remote)" || group.Description != "SPDX all customizations MIT description" || !slices.Equal(group.Obligations, []string{"Carry SPDX all customizations MIT notice"}) {
				t.Fatalf("report mit group = %#v", group)
			}
		}
	}
	if !foundMIT {
		t.Fatalf("report groups = %#v", reportOutput.Report.Groups)
	}

	reportHTMLBytes, err := os.ReadFile(reportHTMLPath)
	if err != nil {
		t.Fatalf("read report html: %v", err)
	}
	reportHTML := string(reportHTMLBytes)
	for _, want := range []string{
		"MIT License (Pinned SPDX All Customizations Remote)",
		"SPDX all customizations MIT description",
		"Carry SPDX all customizations MIT notice",
	} {
		if !strings.Contains(reportHTML, want) {
			t.Fatalf("report html missing %q\n%s", want, reportHTML)
		}
	}

	legalHTMLBytes, err := os.ReadFile(legalHTMLPath)
	if err != nil {
		t.Fatalf("read legal html: %v", err)
	}
	legalHTML := string(legalHTMLBytes)
	for _, want := range []string{
		"MIT License (Pinned SPDX All Customizations Remote)",
		"pinned spdx all customizations remote notice",
	} {
		if !strings.Contains(legalHTML, want) {
			t.Fatalf("legal html missing %q\n%s", want, legalHTML)
		}
	}

	vulnPayload, err := os.ReadFile(vulnJSONPath)
	if err != nil {
		t.Fatalf("read vulnerability json: %v", err)
	}
	var vulnOutput struct {
		Provenance struct {
			Sources []string `json:"sources"`
		} `json:"provenance"`
		Checklist struct {
			Mode            string `json:"mode"`
			PackageFindings []struct {
				Advisories []struct {
					ID        string  `json:"id"`
					Summary   string  `json:"summary"`
					CVSSScore float64 `json:"cvssScore"`
				} `json:"advisories"`
			} `json:"packageFindings"`
		} `json:"checklist"`
	}
	if err := json.Unmarshal(vulnPayload, &vulnOutput); err != nil {
		t.Fatalf("parse vulnerability json: %v", err)
	}
	if vulnOutput.Checklist.Mode != "full" {
		t.Fatalf("vulnerability checklist = %#v", vulnOutput.Checklist)
	}
	for _, want := range []string{"github-advisory", "metadata-enrichment", "nvd", "osv", "spdx-json"} {
		if !slices.Contains(vulnOutput.Provenance.Sources, want) {
			t.Fatalf("vulnerability sources missing %q in %#v", want, vulnOutput.Provenance.Sources)
		}
	}
	foundAdvisory := false
	for _, finding := range vulnOutput.Checklist.PackageFindings {
		for _, advisory := range finding.Advisories {
			if advisory.ID == "GHSA-react-spdx-all-custom-1" {
				foundAdvisory = true
				if advisory.Summary != "SPDX all customizations advisory" || advisory.CVSSScore != 9.4 {
					t.Fatalf("advisory = %#v", advisory)
				}
			}
		}
	}
	if !foundAdvisory {
		t.Fatalf("package findings = %#v", vulnOutput.Checklist.PackageFindings)
	}

	vulnHTMLBytes, err := os.ReadFile(vulnHTMLPath)
	if err != nil {
		t.Fatalf("read vulnerability html: %v", err)
	}
	vulnHTML := string(vulnHTMLBytes)
	for _, want := range []string{
		"Sources: github-advisory, metadata-enrichment, nvd, osv, spdx-json",
		"GHSA-react-spdx-all-custom-1",
		"SPDX all customizations advisory",
		"CVSS 9.4",
	} {
		if !strings.Contains(vulnHTML, want) {
			t.Fatalf("vulnerability html missing %q\n%s", want, vulnHTML)
		}
	}
}

func TestRunAllCustomizationsAnnounceFullOutputs(t *testing.T) {
	t.Parallel()

	remoteBody := `{
  "licenses": [
    {
      "key": "MIT",
      "name": "MIT License (Stdout Remote)",
      "family": "MIT",
      "copyleft_strength": "none",
      "requires_manual_review": false,
      "spdx_ids": ["MIT"],
      "names": ["MIT License (Stdout Remote)"],
      "contains": ["mit"],
      "risk_level": "low",
      "notice_template": "stdout remote notice"
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
			_, _ = w.Write([]byte(`{"results":[{"vulns":[{"id":"CVE-2026-3001"}]},{"vulns":[]},{"vulns":[]},{"vulns":[]}]} `))
		case "/advisories":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`[
  {
    "ghsa_id":"GHSA-react-stdout-all-custom-1",
    "cve_id":"CVE-2026-3001",
    "html_url":"https://github.com/advisories/GHSA-react-stdout-all-custom-1",
    "summary":"Stdout all customizations advisory",
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
        "id":"CVE-2026-3001",
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
	bundlePath := writeEnglishLicenseTextBundleFixture(t, dir)

	var stdout bytes.Buffer
	if err := run([]string{
		"-input", "repository-scan=internal/ci/testdata/repo",
		"-license-catalog", "configs/licenses.json",
		"-license-catalog", catalogServer.URL + "/licenses.json#sha256=" + requestedSHA,
		"-license-text-bundle", bundlePath,
		"-output-html", filepath.Join(dir, "report.html"),
		"-output-json", filepath.Join(dir, "report.json"),
		"-output-legal-html", filepath.Join(dir, "legal.html"),
		"-output-vuln-html", filepath.Join(dir, "vuln.html"),
		"-output-vuln-json", filepath.Join(dir, "vuln.json"),
		"-vuln-mode", "full",
		"-osv-base-url", vulnServer.URL,
		"-github-advisory-base-url", vulnServer.URL,
		"-nvd-base-url", vulnServer.URL,
	}, &stdout); err != nil {
		t.Fatalf("run with all-customizations stdout contract failed: %v", err)
	}

	for _, want := range []string{
		"generated HTML",
		"generated legal notice HTML",
		"generated JSON",
		"generated vulnerability HTML",
		"generated vulnerability JSON",
	} {
		if !strings.Contains(stdout.String(), want) {
			t.Fatalf("stdout missing %q\n%s", want, stdout.String())
		}
	}
}

func TestRunSPDXAllCustomizationsAnnounceFullOutputs(t *testing.T) {
	t.Parallel()

	remoteBody := `{
  "licenses": [
    {
      "key": "MIT",
      "name": "MIT License (SPDX Stdout Remote)",
      "family": "MIT",
      "copyleft_strength": "none",
      "requires_manual_review": false,
      "spdx_ids": ["MIT"],
      "names": ["MIT License (SPDX Stdout Remote)"],
      "contains": ["mit"],
      "risk_level": "low",
      "notice_template": "spdx stdout remote notice"
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
			_, _ = w.Write([]byte(`{"results":[{"vulns":[{"id":"CVE-2026-3002"}]},{"vulns":[]},{"vulns":[]},{"vulns":[]},{"vulns":[]},{"vulns":[]}]} `))
		case "/advisories":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`[
  {
    "ghsa_id":"GHSA-react-stdout-spdx-all-custom-1",
    "cve_id":"CVE-2026-3002",
    "html_url":"https://github.com/advisories/GHSA-react-stdout-spdx-all-custom-1",
    "summary":"Stdout SPDX all customizations advisory",
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
        "id":"CVE-2026-3002",
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
	bundlePath := writeEnglishLicenseTextBundleFixture(t, dir)

	var stdout bytes.Buffer
	if err := run([]string{
		"-input", "spdx-json=internal/sbom/testdata/spdx/app.json",
		"-license-catalog", "configs/licenses.json",
		"-license-catalog", catalogServer.URL + "/licenses.json#sha256=" + requestedSHA,
		"-license-text-bundle", bundlePath,
		"-output-html", filepath.Join(dir, "report.html"),
		"-output-json", filepath.Join(dir, "report.json"),
		"-output-legal-html", filepath.Join(dir, "legal.html"),
		"-output-vuln-html", filepath.Join(dir, "vuln.html"),
		"-output-vuln-json", filepath.Join(dir, "vuln.json"),
		"-vuln-mode", "full",
		"-osv-base-url", vulnServer.URL,
		"-github-advisory-base-url", vulnServer.URL,
		"-nvd-base-url", vulnServer.URL,
	}, &stdout); err != nil {
		t.Fatalf("run with SPDX all-customizations stdout contract failed: %v", err)
	}

	for _, want := range []string{
		"generated HTML",
		"generated legal notice HTML",
		"generated JSON",
		"generated vulnerability HTML",
		"generated vulnerability JSON",
	} {
		if !strings.Contains(stdout.String(), want) {
			t.Fatalf("stdout missing %q\n%s", want, stdout.String())
		}
	}
}

func TestRunReportHTMLUsesCustomLicenseTextBundleContract(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	bundlePath := writeEnglishLicenseTextBundleFixtureWithMutation(t, dir, func(bundle map[string]any) {
		updateLicenseTextBundleEntry(bundle, "MIT", func(entry map[string]any) {
			entry["description"] = "Custom HTML MIT description"
			entry["obligations"] = []string{"Keep custom MIT notice"}
		})
	})

	htmlPath := filepath.Join(dir, "report.html")
	if err := run([]string{
		"-input", "repository-scan=internal/ci/testdata/repo",
		"-license-text-bundle", bundlePath,
		"-output-html", htmlPath,
		"-output-json", filepath.Join(dir, "report.json"),
		"-output-legal-html", filepath.Join(dir, "legal.html"),
	}, &bytes.Buffer{}); err != nil {
		t.Fatalf("run with custom bundle failed: %v", err)
	}

	payload, err := os.ReadFile(htmlPath)
	if err != nil {
		t.Fatalf("read report html: %v", err)
	}
	html := string(payload)
	for _, want := range []string{
		"Custom HTML MIT description",
		"Keep custom MIT notice",
		"MIT License",
	} {
		if !strings.Contains(html, want) {
			t.Fatalf("report html missing %q\n%s", want, html)
		}
	}
}

func TestRunReportJSONUsesMultiSourceInputContract(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	jsonPath := filepath.Join(dir, "report.json")

	var stdout bytes.Buffer
	err := run([]string{
		"-input", "repository-scan=internal/ci/testdata/repo",
		"-input", "cyclonedx-json=internal/sbom/testdata/cyclonedx/app.json",
		"-output-html", filepath.Join(dir, "report.html"),
		"-output-json", jsonPath,
		"-output-legal-html", filepath.Join(dir, "legal.html"),
	}, &stdout)
	if err != nil {
		t.Fatalf("run with multi-source input failed: %v", err)
	}

	payload, err := os.ReadFile(jsonPath)
	if err != nil {
		t.Fatalf("read report json: %v", err)
	}
	var output struct {
		Provenance struct {
			InputKind string `json:"inputKind"`
		} `json:"provenance"`
		Report struct {
			TotalPackages      int `json:"totalPackages"`
			ProductionPackages int `json:"productionPackages"`
			Groups             []struct {
				Key      string `json:"key"`
				Packages []struct {
					Name    string `json:"name"`
					Version string `json:"version"`
				} `json:"packages"`
			} `json:"groups"`
		} `json:"report"`
	}
	if err := json.Unmarshal(payload, &output); err != nil {
		t.Fatalf("parse report json: %v", err)
	}

	if output.Provenance.InputKind != "multi-source" {
		t.Fatalf("input kind = %#v", output.Provenance)
	}
	if output.Report.TotalPackages == 0 || output.Report.ProductionPackages == 0 {
		t.Fatalf("unexpected report package counts: %#v", output.Report)
	}

	foundReact := false
	for _, group := range output.Report.Groups {
		for _, pkg := range group.Packages {
			if pkg.Name == "react" && pkg.Version == "19.2.4" {
				foundReact = true
				break
			}
		}
	}
	if !foundReact {
		t.Fatalf("expected merged react package in %#v", output.Report.Groups)
	}
}

func TestRunUsesMultiSourceRootDisplayContract(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	jsonPath := filepath.Join(dir, "report.json")
	legalPath := filepath.Join(dir, "legal.html")

	if err := run([]string{
		"-input", "repository-scan=internal/ci/testdata/repo",
		"-input", "spdx-json=internal/sbom/testdata/spdx/app.json",
		"-output-html", filepath.Join(dir, "report.html"),
		"-output-json", jsonPath,
		"-output-legal-html", legalPath,
	}, &bytes.Buffer{}); err != nil {
		t.Fatalf("run with multi-source root display failed: %v", err)
	}

	payload, err := os.ReadFile(jsonPath)
	if err != nil {
		t.Fatalf("read report json: %v", err)
	}
	var output struct {
		Report struct {
			Root string `json:"root"`
		} `json:"report"`
	}
	if err := json.Unmarshal(payload, &output); err != nil {
		t.Fatalf("parse report json: %v", err)
	}
	wantRoot := rootDisplay("internal/ci/testdata/repo", "internal/sbom/testdata/spdx/app.json")
	if output.Report.Root != wantRoot {
		t.Fatalf("report root = %q", output.Report.Root)
	}

	legalHTMLBytes, err := os.ReadFile(legalPath)
	if err != nil {
		t.Fatalf("read legal html: %v", err)
	}
	legalHTML := string(legalHTMLBytes)
	wantRootHTML := strings.ReplaceAll(wantRoot, "+", "&#43;")
	if !strings.Contains(legalHTML, `Repository root: <code>`+wantRootHTML+`</code>`) {
		t.Fatalf("legal html missing root display %q\n%s", wantRoot, legalHTML)
	}
}

func TestRunReportHTMLUsesMultiSourceRootDisplayContract(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	htmlPath := filepath.Join(dir, "report.html")

	if err := run([]string{
		"-input", "repository-scan=internal/ci/testdata/repo",
		"-input", "spdx-json=internal/sbom/testdata/spdx/app.json",
		"-output-html", htmlPath,
		"-output-json", filepath.Join(dir, "report.json"),
		"-output-legal-html", filepath.Join(dir, "legal.html"),
	}, &bytes.Buffer{}); err != nil {
		t.Fatalf("run with multi-source report html root display failed: %v", err)
	}

	htmlBytes, err := os.ReadFile(htmlPath)
	if err != nil {
		t.Fatalf("read report html: %v", err)
	}
	html := string(htmlBytes)
	wantRoot := rootDisplay("internal/ci/testdata/repo", "internal/sbom/testdata/spdx/app.json")
	wantRootHTML := escapedRootDisplay("internal/ci/testdata/repo", "internal/sbom/testdata/spdx/app.json")
	if !strings.Contains(html, `Input: <code>`+wantRootHTML+`</code>`) {
		t.Fatalf("report html missing root display %q\n%s", wantRoot, html)
	}
}

func TestRunGeneratesOutputsWithPinnedRemoteCatalog(t *testing.T) {
	t.Parallel()

	remoteBody := `{
  "licenses":[
    {
      "key":"MIT",
      "name":"MIT License (Pinned Remote)",
      "family":"Permissive",
      "version":"",
      "copyleft_strength":"none",
      "requires_manual_review":false,
      "spdx_ids":["MIT"],
      "names":["MIT License","MIT License (Pinned Remote)"],
      "exact_urls":[],
      "url_prefixes":[],
      "contains":["mit license"],
      "color":"#22c55e",
      "risk_level":"low",
      "notice_template":"pinned remote notice"
    }
  ]
}`
	sum := sha256.Sum256([]byte(remoteBody))
	requestedSHA := strings.ToLower(fmt.Sprintf("%x", sum))

	catalogServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(remoteBody))
	}))
	defer catalogServer.Close()

	dir := t.TempDir()
	jsonPath := filepath.Join(dir, "report.json")

	var stdout bytes.Buffer
	err := run([]string{
		"-input", "repository-scan=internal/ci/testdata/repo",
		"-license-catalog", "configs/licenses.json",
		"-license-catalog", catalogServer.URL + "/licenses.json#sha256=" + requestedSHA,
		"-output-html", filepath.Join(dir, "report.html"),
		"-output-json", jsonPath,
		"-output-legal-html", filepath.Join(dir, "legal.html"),
	}, &stdout)
	if err != nil {
		t.Fatalf("run with pinned remote catalog failed: %v", err)
	}

	payload, err := os.ReadFile(jsonPath)
	if err != nil {
		t.Fatalf("read report json: %v", err)
	}
	var output struct {
		Provenance struct {
			CatalogSources []struct {
				Kind            string `json:"kind"`
				Location        string `json:"location"`
				PinningMode     string `json:"pinningMode"`
				RequestedSHA256 string `json:"requestedSha256"`
			} `json:"catalogSources"`
		} `json:"provenance"`
		Report struct {
			Groups []struct {
				Key  string `json:"key"`
				Name string `json:"name"`
			} `json:"groups"`
		} `json:"report"`
	}
	if err := json.Unmarshal(payload, &output); err != nil {
		t.Fatalf("parse report json: %v", err)
	}

	foundPinnedRemote := false
	for _, source := range output.Provenance.CatalogSources {
		if source.Kind == "remote" && source.Location == catalogServer.URL+"/licenses.json#sha256="+requestedSHA {
			if source.PinningMode != "pinned" || source.RequestedSHA256 != requestedSHA {
				t.Fatalf("remote source provenance = %#v", source)
			}
			foundPinnedRemote = true
		}
	}
	if !foundPinnedRemote {
		t.Fatalf("catalog sources = %#v", output.Provenance.CatalogSources)
	}

	foundMIT := false
	for _, group := range output.Report.Groups {
		if group.Key == "MIT" {
			foundMIT = true
			if group.Name != "MIT License (Pinned Remote)" {
				t.Fatalf("mit group = %#v", group)
			}
		}
	}
	if !foundMIT {
		t.Fatalf("groups = %#v", output.Report.Groups)
	}
}

func TestRunGeneratesFullVulnerabilityOutputWithSupplementalSources(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/querybatch":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"results":[{"vulns":[{"id":"CVE-2026-0001"}]},{"vulns":[]},{"vulns":[]},{"vulns":[]}]} `))
		case "/advisories":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`[
  {
    "ghsa_id":"GHSA-react-1",
    "cve_id":"CVE-2026-0001",
    "html_url":"https://github.com/advisories/GHSA-react-1",
    "summary":"Supplemental advisory",
    "severity":"high",
    "updated_at":"2026-04-02T00:00:00Z"
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

	dir := t.TempDir()
	vulnJSONPath := filepath.Join(dir, "vuln.json")

	var stdout bytes.Buffer
	err := run([]string{
		"-input", "repository-scan=internal/ci/testdata/repo",
		"-output-html", filepath.Join(dir, "report.html"),
		"-output-json", filepath.Join(dir, "report.json"),
		"-output-legal-html", filepath.Join(dir, "legal.html"),
		"-output-vuln-json", vulnJSONPath,
		"-vuln-mode", "full",
		"-osv-base-url", server.URL,
		"-github-advisory-base-url", server.URL,
		"-nvd-base-url", server.URL,
	}, &stdout)
	if err != nil {
		t.Fatalf("run with full vulnerability pipeline failed: %v", err)
	}

	payload, err := os.ReadFile(vulnJSONPath)
	if err != nil {
		t.Fatalf("read vulnerability json: %v", err)
	}
	var output struct {
		Checklist struct {
			Mode            string `json:"mode"`
			TotalAdvisories int    `json:"totalAdvisories"`
			PackageFindings []struct {
				Name       string `json:"name"`
				Severity   string `json:"severity"`
				Advisories []struct {
					ID             string  `json:"id"`
					Severity       string  `json:"severity"`
					Summary        string  `json:"summary"`
					CVSSScore      float64 `json:"cvssScore"`
					VendorComments []struct {
						Comment string `json:"comment"`
					} `json:"vendorComments"`
				} `json:"advisories"`
			} `json:"packageFindings"`
		} `json:"checklist"`
	}
	if err := json.Unmarshal(payload, &output); err != nil {
		t.Fatalf("parse vulnerability json: %v", err)
	}
	if output.Checklist.Mode != "full" || output.Checklist.TotalAdvisories == 0 {
		t.Fatalf("checklist = %#v", output.Checklist)
	}
	if len(output.Checklist.PackageFindings) == 0 {
		t.Fatalf("package findings = %#v", output.Checklist.PackageFindings)
	}

	var enrichedAdvisory *struct {
		ID             string  `json:"id"`
		Severity       string  `json:"severity"`
		Summary        string  `json:"summary"`
		CVSSScore      float64 `json:"cvssScore"`
		VendorComments []struct {
			Comment string `json:"comment"`
		} `json:"vendorComments"`
	}
	for _, pkg := range output.Checklist.PackageFindings {
		for _, advisory := range pkg.Advisories {
			if advisory.Summary == "Supplemental advisory" {
				advisoryCopy := advisory
				enrichedAdvisory = &advisoryCopy
				break
			}
		}
		if enrichedAdvisory != nil {
			break
		}
	}
	if enrichedAdvisory == nil {
		t.Fatalf("package findings = %#v", output.Checklist.PackageFindings)
	}
	if enrichedAdvisory.Severity != "critical" || enrichedAdvisory.CVSSScore != 9.3 || len(enrichedAdvisory.VendorComments) != 1 || enrichedAdvisory.VendorComments[0].Comment != "Patched in 1.2.3" {
		t.Fatalf("advisory enrichment = %#v", enrichedAdvisory)
	}
}

func TestRunGeneratesVulnerabilityHTMLOutputOnly(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/querybatch" {
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"results":[{"vulns":[]},{"vulns":[]},{"vulns":[]},{"vulns":[]}]}`))
	}))
	defer server.Close()

	dir := t.TempDir()
	vulnHTMLPath := filepath.Join(dir, "vuln.html")

	var stdout bytes.Buffer
	err := run([]string{
		"-input", "repository-scan=internal/ci/testdata/repo",
		"-output-html", filepath.Join(dir, "report.html"),
		"-output-json", filepath.Join(dir, "report.json"),
		"-output-legal-html", filepath.Join(dir, "legal.html"),
		"-output-vuln-html", vulnHTMLPath,
		"-osv-base-url", server.URL,
	}, &stdout)
	if err != nil {
		t.Fatalf("run with vulnerability html output failed: %v", err)
	}
	if _, err := os.Stat(vulnHTMLPath); err != nil {
		t.Fatalf("expected vulnerability html output: %v", err)
	}
	if !strings.Contains(stdout.String(), "generated vulnerability HTML") {
		t.Fatalf("unexpected stdout: %s", stdout.String())
	}
	if strings.Contains(stdout.String(), "generated vulnerability JSON") {
		t.Fatalf("unexpected vulnerability json output in stdout: %s", stdout.String())
	}
}

func TestRunVulnerabilityHTMLIncludesPipelineContent(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/querybatch":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"results":[{"vulns":[{"id":"CVE-2026-0001"}]},{"vulns":[]},{"vulns":[]},{"vulns":[]}]} `))
		case "/advisories":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`[
  {
    "ghsa_id":"GHSA-react-1",
    "cve_id":"CVE-2026-0001",
    "html_url":"https://github.com/advisories/GHSA-react-1",
    "summary":"Supplemental advisory",
    "severity":"high",
    "updated_at":"2026-04-02T00:00:00Z"
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

	dir := t.TempDir()
	vulnHTMLPath := filepath.Join(dir, "vuln.html")

	err := run([]string{
		"-input", "repository-scan=internal/ci/testdata/repo",
		"-output-html", filepath.Join(dir, "report.html"),
		"-output-json", filepath.Join(dir, "report.json"),
		"-output-legal-html", filepath.Join(dir, "legal.html"),
		"-output-vuln-html", vulnHTMLPath,
		"-vuln-mode", "full",
		"-osv-base-url", server.URL,
		"-github-advisory-base-url", server.URL,
		"-nvd-base-url", server.URL,
	}, &bytes.Buffer{})
	if err != nil {
		t.Fatalf("run with vulnerability html output failed: %v", err)
	}

	payload, err := os.ReadFile(vulnHTMLPath)
	if err != nil {
		t.Fatalf("read vulnerability html: %v", err)
	}
	html := string(payload)
	for _, want := range []string{
		"Vulnerability Checklist",
		"Mode: full",
		"Sources: github-advisory, metadata-enrichment, nvd, osv, repository-scan",
		"Pipeline Stages",
		"GHSA-react-1",
		"Critical",
		"CVSS 9.3",
		"Supplemental advisory",
		"vendor-a",
		"Patched in 1.2.3",
		"Query: purl",
	} {
		if !strings.Contains(html, want) {
			t.Fatalf("expected vulnerability html to contain %q\n%s", want, html)
		}
	}
}

func TestRunGeneratesVulnerabilityJSONOutputOnly(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/querybatch" {
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"results":[{"vulns":[]},{"vulns":[]},{"vulns":[]},{"vulns":[]}]}`))
	}))
	defer server.Close()

	dir := t.TempDir()
	vulnJSONPath := filepath.Join(dir, "vuln.json")

	var stdout bytes.Buffer
	err := run([]string{
		"-input", "repository-scan=internal/ci/testdata/repo",
		"-output-html", filepath.Join(dir, "report.html"),
		"-output-json", filepath.Join(dir, "report.json"),
		"-output-legal-html", filepath.Join(dir, "legal.html"),
		"-output-vuln-json", vulnJSONPath,
		"-osv-base-url", server.URL,
	}, &stdout)
	if err != nil {
		t.Fatalf("run with vulnerability json output failed: %v", err)
	}
	if _, err := os.Stat(vulnJSONPath); err != nil {
		t.Fatalf("expected vulnerability json output: %v", err)
	}
	if !strings.Contains(stdout.String(), "generated vulnerability JSON") {
		t.Fatalf("unexpected stdout: %s", stdout.String())
	}
	if strings.Contains(stdout.String(), "generated vulnerability HTML") {
		t.Fatalf("unexpected vulnerability html output in stdout: %s", stdout.String())
	}
}

func TestRunVulnerabilityJSONIncludesProvenance(t *testing.T) {
	t.Parallel()

	npmServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
  "license":"MIT",
  "repository":{"type":"git","url":"https://github.com/example/pkg.git"},
  "homepage":"https://example.test/pkg",
  "author":{"name":"Example Maintainer"}
}`))
	}))
	defer npmServer.Close()

	osvServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/querybatch" {
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"results":[{"vulns":[]},{"vulns":[]},{"vulns":[]}]}`))
	}))
	defer osvServer.Close()

	dir := t.TempDir()
	vulnJSONPath := filepath.Join(dir, "vuln.json")

	err := run([]string{
		"-input", "cyclonedx-json=internal/sbom/testdata/cyclonedx/app.json",
		"-output-html", filepath.Join(dir, "report.html"),
		"-output-json", filepath.Join(dir, "report.json"),
		"-output-legal-html", filepath.Join(dir, "legal.html"),
		"-output-vuln-json", vulnJSONPath,
		"-npm-registry-base-url", npmServer.URL,
		"-osv-base-url", osvServer.URL,
	}, &bytes.Buffer{})
	if err != nil {
		t.Fatalf("run with vulnerability json output failed: %v", err)
	}

	payload, err := os.ReadFile(vulnJSONPath)
	if err != nil {
		t.Fatalf("read vulnerability json: %v", err)
	}
	var output struct {
		Provenance struct {
			InputSchemaVersion string   `json:"inputSchemaVersion"`
			Sources            []string `json:"sources"`
			ExternalSources    []struct {
				ID      string `json:"id"`
				Purpose string `json:"purpose"`
				BaseURL string `json:"baseUrl"`
			} `json:"externalSources"`
		} `json:"provenance"`
	}
	if err := json.Unmarshal(payload, &output); err != nil {
		t.Fatalf("parse vulnerability json: %v", err)
	}
	if output.Provenance.InputSchemaVersion != "1" {
		t.Fatalf("input schema version = %#v", output.Provenance)
	}
	if !slices.Equal(output.Provenance.Sources, []string{"cyclonedx-json", "metadata-enrichment", "osv"}) {
		t.Fatalf("sources = %#v", output.Provenance.Sources)
	}
	if len(output.Provenance.ExternalSources) != 2 {
		t.Fatalf("external sources = %#v", output.Provenance.ExternalSources)
	}
	if output.Provenance.ExternalSources[0].ID != "npm-registry" ||
		output.Provenance.ExternalSources[0].BaseURL != npmServer.URL ||
		output.Provenance.ExternalSources[1].ID != "osv" ||
		output.Provenance.ExternalSources[1].BaseURL != osvServer.URL {
		t.Fatalf("external sources = %#v", output.Provenance.ExternalSources)
	}
}

func TestRunReportJSONIncludesExternalSourceProvenance(t *testing.T) {
	t.Parallel()

	npmServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
  "license":"MIT",
  "repository":{"type":"git","url":"https://github.com/example/pkg.git"},
  "homepage":"https://example.test/pkg",
  "author":{"name":"Example Maintainer"}
}`))
	}))
	defer npmServer.Close()

	dir := t.TempDir()
	reportJSONPath := filepath.Join(dir, "report.json")

	err := run([]string{
		"-input", "cyclonedx-json=internal/sbom/testdata/cyclonedx/app.json",
		"-output-html", filepath.Join(dir, "report.html"),
		"-output-json", reportJSONPath,
		"-output-legal-html", filepath.Join(dir, "legal.html"),
		"-npm-registry-base-url", npmServer.URL,
		"-http-cache-mode", "use",
		"-http-cache-ttl", "0s",
	}, &bytes.Buffer{})
	if err != nil {
		t.Fatalf("run with report json output failed: %v", err)
	}

	payload, err := os.ReadFile(reportJSONPath)
	if err != nil {
		t.Fatalf("read report json: %v", err)
	}
	var output struct {
		Provenance struct {
			ExternalSources []struct {
				ID        string `json:"id"`
				Purpose   string `json:"purpose"`
				BaseURL   string `json:"baseUrl"`
				CacheMode string `json:"cacheMode"`
				CacheTTL  string `json:"cacheTtl"`
			} `json:"externalSources"`
		} `json:"provenance"`
	}
	if err := json.Unmarshal(payload, &output); err != nil {
		t.Fatalf("parse report json: %v", err)
	}
	if len(output.Provenance.ExternalSources) != 1 {
		t.Fatalf("external sources = %#v", output.Provenance.ExternalSources)
	}
	if output.Provenance.ExternalSources[0].ID != "npm-registry" ||
		output.Provenance.ExternalSources[0].BaseURL != npmServer.URL ||
		output.Provenance.ExternalSources[0].CacheMode != "use" {
		t.Fatalf("first external source = %#v", output.Provenance.ExternalSources[0])
	}
	if output.Provenance.ExternalSources[0].CacheTTL != "0s" {
		t.Fatalf("first external source = %#v", output.Provenance.ExternalSources[0])
	}
}

func TestRunReportJSONMarksRemoteNuGetArtifactFallbackForReview(t *testing.T) {
	mainSeamMu.Lock()
	defer mainSeamMu.Unlock()

	oldStderr := stderrOut
	t.Cleanup(func() {
		stderrOut = oldStderr
	})

	var stderr bytes.Buffer
	stderrOut = &stderr

	t.Setenv("NUGET_PACKAGES", filepath.Join(t.TempDir(), "missing"))

	var archive bytes.Buffer
	writer := zip.NewWriter(&archive)
	nuspec, err := writer.Create("Sample.Package.nuspec")
	if err != nil {
		t.Fatalf("create nuspec: %v", err)
	}
	if _, err := nuspec.Write([]byte(`<?xml version="1.0" encoding="utf-8"?>
<package>
  <metadata>
    <id>Sample.Package</id>
    <version>1.2.3</version>
    <authors>Sample Author</authors>
    <license type="file">LICENSE.txt</license>
  </metadata>
</package>`)); err != nil {
		t.Fatalf("write nuspec: %v", err)
	}
	licenseFile, err := writer.Create("LICENSE.txt")
	if err != nil {
		t.Fatalf("create license: %v", err)
	}
	if _, err := licenseFile.Write([]byte("MIT License\n\nCopyright (c) 2024 Example")); err != nil {
		t.Fatalf("write license: %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("close archive: %v", err)
	}

	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/sample.package/1.2.3.json":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"catalogEntry":"` + server.URL + `/catalog/sample.package.1.2.3.json","packageContent":"` + server.URL + `/package/sample.package.1.2.3.nupkg"}`))
		case "/catalog/sample.package.1.2.3.json":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"authors":"Sample Author","projectUrl":"https://example.test/sample","published":"2024-02-03T00:00:00Z"}`))
		case "/package/sample.package.1.2.3.nupkg":
			w.Header().Set("Content-Type", "application/octet-stream")
			_, _ = w.Write(archive.Bytes())
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	dir := t.TempDir()
	sbomPath := filepath.Join(dir, "sample.cdx.json")
	sbomPayload, err := json.Marshal(map[string]any{
		"bomFormat":   "CycloneDX",
		"specVersion": "1.5",
		"version":     1,
		"metadata": map[string]any{
			"component": map[string]any{
				"bom-ref": "root-app",
				"type":    "application",
				"name":    "sample-app",
				"version": "1.0.0",
			},
		},
		"components": []map[string]any{
			{
				"bom-ref": "pkg:nuget/Sample.Package@1.2.3",
				"type":    "library",
				"name":    "Sample.Package",
				"version": "1.2.3",
				"purl":    "pkg:nuget/Sample.Package@1.2.3",
			},
		},
		"dependencies": []map[string]any{
			{
				"ref":       "root-app",
				"dependsOn": []string{"pkg:nuget/Sample.Package@1.2.3"},
			},
		},
	})
	if err != nil {
		t.Fatalf("marshal sbom: %v", err)
	}
	if err := os.WriteFile(sbomPath, sbomPayload, 0o644); err != nil {
		t.Fatalf("write sbom: %v", err)
	}

	reportJSONPath := filepath.Join(dir, "report.json")
	if err := run([]string{
		"-input", "cyclonedx-json=" + sbomPath,
		"-output-html", filepath.Join(dir, "report.html"),
		"-output-json", reportJSONPath,
		"-output-legal-html", filepath.Join(dir, "legal.html"),
		"-nuget-registration-base-url", server.URL,
	}, &bytes.Buffer{}); err != nil {
		t.Fatalf("run with remote nuget fallback failed: %v", err)
	}

	if got := stderr.String(); !strings.Contains(got, "remote resolution fallback") || !strings.Contains(got, "Sample.Package@1.2.3") {
		t.Fatalf("stderr = %q", got)
	}

	payload, err := os.ReadFile(reportJSONPath)
	if err != nil {
		t.Fatalf("read report json: %v", err)
	}
	var output struct {
		Report struct {
			Packages []struct {
				Name       string `json:"name"`
				LicenseKey string `json:"licenseKey"`
				Provenance struct {
					ArtifactResolution struct {
						Kind           string `json:"kind"`
						Detail         string `json:"detail"`
						ReviewRequired bool   `json:"reviewRequired"`
						ReviewReason   string `json:"reviewReason"`
					} `json:"artifactResolution"`
				} `json:"provenance"`
			} `json:"packages"`
			Diagnostics []struct {
				Code     string `json:"code"`
				Severity string `json:"severity"`
				Message  string `json:"message"`
			} `json:"diagnostics"`
		} `json:"report"`
	}
	if err := json.Unmarshal(payload, &output); err != nil {
		t.Fatalf("parse report json: %v", err)
	}
	if len(output.Report.Packages) != 1 {
		t.Fatalf("packages = %#v", output.Report.Packages)
	}
	if output.Report.Packages[0].LicenseKey != "MIT" {
		t.Fatalf("package = %#v", output.Report.Packages[0])
	}
	if output.Report.Packages[0].Provenance.ArtifactResolution.Kind != "remote-package-content" ||
		output.Report.Packages[0].Provenance.ArtifactResolution.Detail != "nuget-package-content" ||
		!output.Report.Packages[0].Provenance.ArtifactResolution.ReviewRequired {
		t.Fatalf("artifact resolution = %#v", output.Report.Packages[0].Provenance.ArtifactResolution)
	}
	if len(output.Report.Diagnostics) != 1 || output.Report.Diagnostics[0].Code != "remote_resolution_fallback_used" || output.Report.Diagnostics[0].Severity != "warning" {
		t.Fatalf("diagnostics = %#v", output.Report.Diagnostics)
	}
}

func TestRunFullVulnerabilityStaysConsistentAcrossJSONAndHTML(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/querybatch":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"results":[{"vulns":[{"id":"CVE-2026-0001"}]},{"vulns":[]},{"vulns":[]},{"vulns":[]}]} `))
		case "/advisories":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`[
  {
    "ghsa_id":"GHSA-react-consistent-1",
    "cve_id":"CVE-2026-0001",
    "html_url":"https://github.com/advisories/GHSA-react-consistent-1",
    "summary":"Consistent advisory",
    "severity":"high",
    "updated_at":"2026-04-02T00:00:00Z"
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

	dir := t.TempDir()
	vulnJSONPath := filepath.Join(dir, "vuln.json")
	vulnHTMLPath := filepath.Join(dir, "vuln.html")

	if err := run([]string{
		"-input", "repository-scan=internal/ci/testdata/repo",
		"-output-html", filepath.Join(dir, "report.html"),
		"-output-json", filepath.Join(dir, "report.json"),
		"-output-legal-html", filepath.Join(dir, "legal.html"),
		"-output-vuln-json", vulnJSONPath,
		"-output-vuln-html", vulnHTMLPath,
		"-vuln-mode", "full",
		"-osv-base-url", server.URL,
		"-github-advisory-base-url", server.URL,
		"-nvd-base-url", server.URL,
	}, &bytes.Buffer{}); err != nil {
		t.Fatalf("run with full vulnerability cross-output failed: %v", err)
	}

	payload, err := os.ReadFile(vulnJSONPath)
	if err != nil {
		t.Fatalf("read vulnerability json: %v", err)
	}
	var output struct {
		Provenance struct {
			Sources []string `json:"sources"`
		} `json:"provenance"`
		Checklist struct {
			PackageFindings []struct {
				Advisories []struct {
					ID string `json:"id"`
				} `json:"advisories"`
			} `json:"packageFindings"`
		} `json:"checklist"`
	}
	if err := json.Unmarshal(payload, &output); err != nil {
		t.Fatalf("parse vulnerability json: %v", err)
	}
	if !slices.Equal(output.Provenance.Sources, []string{"github-advisory", "metadata-enrichment", "nvd", "osv", "repository-scan"}) {
		t.Fatalf("json sources = %#v", output.Provenance.Sources)
	}
	foundJSON := false
	for _, pkg := range output.Checklist.PackageFindings {
		for _, advisory := range pkg.Advisories {
			if advisory.ID == "GHSA-react-consistent-1" {
				foundJSON = true
			}
		}
	}
	if !foundJSON {
		t.Fatalf("json findings = %#v", output.Checklist.PackageFindings)
	}

	htmlPayload, err := os.ReadFile(vulnHTMLPath)
	if err != nil {
		t.Fatalf("read vulnerability html: %v", err)
	}
	html := string(htmlPayload)
	for _, want := range []string{
		"Sources: github-advisory, metadata-enrichment, nvd, osv, repository-scan",
		"GHSA-react-consistent-1",
		"Consistent advisory",
		"CVSS 9.3",
	} {
		if !strings.Contains(html, want) {
			t.Fatalf("vulnerability html missing %q\n%s", want, html)
		}
	}
}

func TestRunMultiSourcePrefersLocalArtifactResolutionOverRemoteReview(t *testing.T) {
	dir := t.TempDir()
	repoDir := filepath.Join(dir, "repo")
	packageDir := filepath.Join(repoDir, "node_modules", "react")
	if err := os.MkdirAll(packageDir, 0o755); err != nil {
		t.Fatalf("mkdir package dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(repoDir, "package.json"), []byte(`{
  "name": "client",
  "dependencies": {
    "react": "18.2.0"
  }
}`), 0o644); err != nil {
		t.Fatalf("write repo package.json: %v", err)
	}
	if err := os.WriteFile(filepath.Join(packageDir, "package.json"), []byte(`{
  "name": "react",
  "version": "18.2.0",
  "license": "MIT",
  "homepage": "https://react.dev/",
  "repository": { "url": "https://github.com/facebook/react" },
  "author": { "name": "Meta" }
}`), 0o644); err != nil {
		t.Fatalf("write dependency package.json: %v", err)
	}

	sbomPath := filepath.Join(dir, "app.cdx.json")
	testutil.WriteIndentedJSONFixture(t, sbomPath, map[string]any{
		"bomFormat":   "CycloneDX",
		"specVersion": "1.5",
		"version":     1,
		"metadata": map[string]any{
			"component": map[string]any{
				"type":    "application",
				"name":    "client",
				"version": "1.0.0",
				"bom-ref": "root-app",
			},
		},
		"components": []map[string]any{
			{
				"bom-ref": "pkg:npm/react@18.2.0",
				"type":    "library",
				"name":    "react",
				"version": "18.2.0",
				"purl":    "pkg:npm/react@18.2.0",
			},
		},
		"dependencies": []map[string]any{
			{
				"ref":       "root-app",
				"dependsOn": []string{"pkg:npm/react@18.2.0"},
			},
		},
	})

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/react/18.2.0" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
  "license": "MIT",
  "homepage": "https://registry.example.test/react",
  "repository": { "url": "https://registry.example.test/react.git" },
  "author": { "name": "Registry Author" }
}`))
	}))
	defer server.Close()

	reportJSONPath := filepath.Join(dir, "report.json")
	oldStderr := stderrOut
	var stderr bytes.Buffer
	stderrOut = &stderr
	t.Cleanup(func() {
		stderrOut = oldStderr
	})
	if err := run([]string{
		"-input", "repository-scan=" + repoDir,
		"-input", "cyclonedx-json=" + sbomPath,
		"-output-html", filepath.Join(dir, "report.html"),
		"-output-json", reportJSONPath,
		"-output-legal-html", filepath.Join(dir, "legal.html"),
		"-npm-registry-base-url", server.URL,
	}, &bytes.Buffer{}); err != nil {
		t.Fatalf("run with local multi-source artifact evidence failed: %v", err)
	}

	payload, err := os.ReadFile(reportJSONPath)
	if err != nil {
		t.Fatalf("read report json: %v", err)
	}
	var output struct {
		Report struct {
			Packages []struct {
				Name       string `json:"name"`
				Repository string `json:"repository"`
				Homepage   string `json:"homepage"`
				Provenance struct {
					SourceIDs          []string          `json:"sourceIds"`
					ArtifactResolution struct {
						Kind           string `json:"kind"`
						Detail         string `json:"detail"`
						ReviewRequired bool   `json:"reviewRequired"`
					} `json:"artifactResolution"`
				} `json:"provenance"`
			} `json:"packages"`
			Diagnostics []struct {
				Code string `json:"code"`
			} `json:"diagnostics"`
		} `json:"report"`
	}
	if err := json.Unmarshal(payload, &output); err != nil {
		t.Fatalf("parse report json: %v", err)
	}
	if len(output.Report.Packages) != 1 {
		t.Fatalf("packages = %#v", output.Report.Packages)
	}
	pkg := output.Report.Packages[0]
	if pkg.Name != "react" {
		t.Fatalf("package = %#v", pkg)
	}
	if pkg.Provenance.ArtifactResolution.Kind != "local-package-manager" ||
		pkg.Provenance.ArtifactResolution.Detail != "node-modules" ||
		pkg.Provenance.ArtifactResolution.ReviewRequired {
		t.Fatalf("artifact resolution = %#v", pkg.Provenance.ArtifactResolution)
	}
	if !slices.Equal(pkg.Provenance.SourceIDs, []string{"enrich:node-modules", "input-1", "input-2"}) {
		t.Fatalf("source ids = %#v", pkg.Provenance.SourceIDs)
	}
	for _, diagnostic := range output.Report.Diagnostics {
		if diagnostic.Code == "remote_resolution_fallback_used" {
			t.Fatalf("unexpected remote fallback diagnostic = %#v", output.Report.Diagnostics)
		}
	}
	if got := stderr.String(); strings.Contains(got, "remote resolution fallback") {
		t.Fatalf("unexpected stderr warning = %q", got)
	}
}

func TestRunRemoteFallbackUsesSameArtifactResolutionInReportAndVulnJSON(t *testing.T) {
	dir := t.TempDir()
	sbomPath := filepath.Join(dir, "app.cdx.json")

	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/sample.package/1.2.3.json":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"catalogEntry":"` + server.URL + `/catalog/sample.package.1.2.3.json","packageContent":"` + server.URL + `/package/sample.package.1.2.3.nupkg"}`))
		case "/catalog/sample.package.1.2.3.json":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"authors":"Sample Author","projectUrl":"https://example.test/sample","published":"2024-02-03T00:00:00Z"}`))
		case "/package/sample.package.1.2.3.nupkg":
			var archive bytes.Buffer
			writer := zip.NewWriter(&archive)
			nuspec, err := writer.Create("Sample.Package.nuspec")
			if err != nil {
				t.Fatalf("create nuspec: %v", err)
			}
			if _, err := nuspec.Write([]byte(`<?xml version="1.0" encoding="utf-8"?>
<package>
  <metadata>
    <id>Sample.Package</id>
    <version>1.2.3</version>
    <authors>Sample Author</authors>
    <license type="file">LICENSE.txt</license>
  </metadata>
</package>`)); err != nil {
				t.Fatalf("write nuspec: %v", err)
			}
			licenseFile, err := writer.Create("LICENSE.txt")
			if err != nil {
				t.Fatalf("create license file: %v", err)
			}
			if _, err := licenseFile.Write([]byte("MIT License\n\nCopyright (c) 2024 Example")); err != nil {
				t.Fatalf("write license file: %v", err)
			}
			if err := writer.Close(); err != nil {
				t.Fatalf("close archive: %v", err)
			}
			w.Header().Set("Content-Type", "application/octet-stream")
			_, _ = w.Write(archive.Bytes())
		case "/v1/querybatch":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"results":[{"vulns":[]}]}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	testutil.WriteIndentedJSONFixture(t, sbomPath, map[string]any{
		"bomFormat":   "CycloneDX",
		"specVersion": "1.5",
		"version":     1,
		"metadata": map[string]any{
			"component": map[string]any{
				"type":    "application",
				"name":    "app",
				"version": "1.0.0",
				"bom-ref": "root-app",
			},
		},
		"components": []map[string]any{
			{
				"bom-ref": "pkg:nuget/Sample.Package@1.2.3",
				"type":    "library",
				"name":    "Sample.Package",
				"version": "1.2.3",
				"purl":    "pkg:nuget/Sample.Package@1.2.3",
			},
		},
		"dependencies": []map[string]any{
			{
				"ref":       "root-app",
				"dependsOn": []string{"pkg:nuget/Sample.Package@1.2.3"},
			},
		},
	})

	reportJSONPath := filepath.Join(dir, "report.json")
	vulnJSONPath := filepath.Join(dir, "vuln.json")
	if err := run([]string{
		"-input", "cyclonedx-json=" + sbomPath,
		"-output-html", filepath.Join(dir, "report.html"),
		"-output-json", reportJSONPath,
		"-output-legal-html", filepath.Join(dir, "legal.html"),
		"-output-vuln-json", vulnJSONPath,
		"-nuget-registration-base-url", server.URL,
		"-osv-base-url", server.URL,
	}, &bytes.Buffer{}); err != nil {
		t.Fatalf("run with remote nuget fallback + vuln output failed: %v", err)
	}

	reportPayload, err := os.ReadFile(reportJSONPath)
	if err != nil {
		t.Fatalf("read report json: %v", err)
	}
	var reportOutput struct {
		Report struct {
			Packages []struct {
				Name       string `json:"name"`
				LicenseKey string `json:"licenseKey"`
				Provenance struct {
					ArtifactResolution struct {
						Kind           string `json:"kind"`
						Detail         string `json:"detail"`
						ReviewRequired bool   `json:"reviewRequired"`
						ReviewReason   string `json:"reviewReason"`
					} `json:"artifactResolution"`
				} `json:"provenance"`
			} `json:"packages"`
			Diagnostics []struct {
				Code string `json:"code"`
			} `json:"diagnostics"`
		} `json:"report"`
	}
	if err := json.Unmarshal(reportPayload, &reportOutput); err != nil {
		t.Fatalf("parse report json: %v", err)
	}

	vulnPayload, err := os.ReadFile(vulnJSONPath)
	if err != nil {
		t.Fatalf("read vulnerability json: %v", err)
	}
	var vulnOutput struct {
		Checklist struct {
			PackageFindings []struct {
				Name               string `json:"name"`
				ArtifactResolution struct {
					Kind           string `json:"kind"`
					Detail         string `json:"detail"`
					ReviewRequired bool   `json:"reviewRequired"`
					ReviewReason   string `json:"reviewReason"`
				} `json:"artifactResolution"`
			} `json:"packageFindings"`
		} `json:"checklist"`
	}
	if err := json.Unmarshal(vulnPayload, &vulnOutput); err != nil {
		t.Fatalf("parse vulnerability json: %v", err)
	}

	if len(reportOutput.Report.Packages) != 1 || len(vulnOutput.Checklist.PackageFindings) != 1 {
		t.Fatalf("report packages = %#v, vuln package findings = %#v", reportOutput.Report.Packages, vulnOutput.Checklist.PackageFindings)
	}
	reportPkg := reportOutput.Report.Packages[0]
	vulnPkg := vulnOutput.Checklist.PackageFindings[0]
	if reportPkg.Name != "Sample.Package" || vulnPkg.Name != "Sample.Package" {
		t.Fatalf("report package = %#v, vuln package = %#v", reportPkg, vulnPkg)
	}
	if reportPkg.LicenseKey != "MIT" {
		t.Fatalf("report package = %#v", reportPkg)
	}
	if reportPkg.Provenance.ArtifactResolution != vulnPkg.ArtifactResolution {
		t.Fatalf("artifact resolution mismatch report=%#v vuln=%#v", reportPkg.Provenance.ArtifactResolution, vulnPkg.ArtifactResolution)
	}
	if reportPkg.Provenance.ArtifactResolution.Kind != "remote-package-content" ||
		reportPkg.Provenance.ArtifactResolution.Detail != "nuget-package-content" ||
		!reportPkg.Provenance.ArtifactResolution.ReviewRequired ||
		reportPkg.Provenance.ArtifactResolution.ReviewReason != "local-package-manager-artifact-not-available" {
		t.Fatalf("artifact resolution = %#v", reportPkg.Provenance.ArtifactResolution)
	}
	if len(reportOutput.Report.Diagnostics) != 1 || reportOutput.Report.Diagnostics[0].Code != "remote_resolution_fallback_used" {
		t.Fatalf("report diagnostics = %#v", reportOutput.Report.Diagnostics)
	}
}

func TestRunReturnsErrorForMissingTemplateAsset(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	err := run([]string{
		"-input", "repository-scan=internal/ci/testdata/repo",
		"-output-html", filepath.Join(dir, "report.html"),
		"-output-json", filepath.Join(dir, "report.json"),
		"-output-legal-html", filepath.Join(dir, "legal.html"),
		"-template", filepath.Join(dir, "missing.tmpl"),
	}, &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "asset not found") {
		t.Fatalf("expected missing template error, got %v", err)
	}
}

func TestRunReturnsErrorForMissingThemeAsset(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	err := run([]string{
		"-input", "repository-scan=internal/ci/testdata/repo",
		"-output-html", filepath.Join(dir, "report.html"),
		"-output-json", filepath.Join(dir, "report.json"),
		"-output-legal-html", filepath.Join(dir, "legal.html"),
		"-theme-css", filepath.Join(dir, "missing-report.css"),
	}, &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "asset not found") {
		t.Fatalf("expected missing report theme error, got %v", err)
	}
}

func TestRunReturnsErrorForMissingVulnerabilityTemplateAsset(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	err := run([]string{
		"-input", "repository-scan=internal/ci/testdata/repo",
		"-output-html", filepath.Join(dir, "report.html"),
		"-output-json", filepath.Join(dir, "report.json"),
		"-output-legal-html", filepath.Join(dir, "legal.html"),
		"-output-vuln-html", filepath.Join(dir, "vuln.html"),
		"-vuln-template", filepath.Join(dir, "missing-vuln.tmpl"),
	}, &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "asset not found") {
		t.Fatalf("expected missing vulnerability template error, got %v", err)
	}
}

func TestRunReturnsErrorForMissingVulnerabilityThemeAsset(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	err := run([]string{
		"-input", "repository-scan=internal/ci/testdata/repo",
		"-output-html", filepath.Join(dir, "report.html"),
		"-output-json", filepath.Join(dir, "report.json"),
		"-output-legal-html", filepath.Join(dir, "legal.html"),
		"-output-vuln-html", filepath.Join(dir, "vuln.html"),
		"-vuln-theme-css", filepath.Join(dir, "missing-vuln.css"),
	}, &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "asset not found") {
		t.Fatalf("expected missing vulnerability theme error, got %v", err)
	}
}

func TestRunReturnsErrorForMissingLegalTemplateAsset(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	err := run([]string{
		"-input", "repository-scan=internal/ci/testdata/repo",
		"-output-html", filepath.Join(dir, "report.html"),
		"-output-json", filepath.Join(dir, "report.json"),
		"-output-legal-html", filepath.Join(dir, "legal.html"),
		"-legal-template", filepath.Join(dir, "missing-legal.tmpl"),
	}, &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "asset not found") {
		t.Fatalf("expected missing legal template error, got %v", err)
	}
}

func TestRunReturnsErrorForMissingLegalThemeAsset(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	err := run([]string{
		"-input", "repository-scan=internal/ci/testdata/repo",
		"-output-html", filepath.Join(dir, "report.html"),
		"-output-json", filepath.Join(dir, "report.json"),
		"-output-legal-html", filepath.Join(dir, "legal.html"),
		"-legal-theme-css", filepath.Join(dir, "missing-legal.css"),
	}, &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "asset not found") {
		t.Fatalf("expected missing legal theme error, got %v", err)
	}
}

func TestRunReturnsErrorForInvalidCatalogAndLicenseBundle(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	invalidCatalog := filepath.Join(dir, "invalid-catalog.json")
	if err := os.WriteFile(invalidCatalog, []byte(`{invalid`), 0o644); err != nil {
		t.Fatalf("write invalid catalog: %v", err)
	}
	err := run([]string{
		"-input", "repository-scan=internal/ci/testdata/repo",
		"-license-catalog", invalidCatalog,
		"-output-html", filepath.Join(dir, "report.html"),
		"-output-json", filepath.Join(dir, "report.json"),
		"-output-legal-html", filepath.Join(dir, "legal.html"),
	}, &bytes.Buffer{})
	if err == nil {
		t.Fatal("expected invalid catalog error")
	}

	invalidBundle := filepath.Join(dir, "invalid-bundle.json")
	if err := os.WriteFile(invalidBundle, []byte(`{invalid`), 0o644); err != nil {
		t.Fatalf("write invalid bundle: %v", err)
	}
	err = run([]string{
		"-input", "repository-scan=internal/ci/testdata/repo",
		"-license-text-bundle", invalidBundle,
		"-output-html", filepath.Join(dir, "report2.html"),
		"-output-json", filepath.Join(dir, "report2.json"),
		"-output-legal-html", filepath.Join(dir, "legal2.html"),
	}, &bytes.Buffer{})
	if err == nil {
		t.Fatal("expected invalid bundle error")
	}
}

func TestRunReturnsErrorWhenPrimaryJSONWriteFails(t *testing.T) {
	mainSeamMu.Lock()
	defer mainSeamMu.Unlock()

	oldMkdirAll := mkdirAllFunc
	oldWriteFile := writeFileFunc
	t.Cleanup(func() {
		mkdirAllFunc = oldMkdirAll
		writeFileFunc = oldWriteFile
	})

	dir := t.TempDir()
	htmlPath := filepath.Join(dir, "report.html")
	jsonPath := filepath.Join(dir, "report.json")
	legalPath := filepath.Join(dir, "legal.html")

	mkdirAllFunc = func(string, os.FileMode) error { return nil }
	writeFileFunc = func(path string, data []byte, perm os.FileMode) error {
		if path == jsonPath {
			return errors.New("json-write-failed")
		}
		return oldWriteFile(path, data, perm)
	}

	err := run([]string{
		"-input", "repository-scan=internal/ci/testdata/repo",
		"-output-html", htmlPath,
		"-output-json", jsonPath,
		"-output-legal-html", legalPath,
	}, &bytes.Buffer{})
	if err == nil || err.Error() != "json-write-failed" {
		t.Fatalf("expected json write error, got %v", err)
	}
}

func TestRunReturnsErrorWhenOutputDirectoryCreationFails(t *testing.T) {
	mainSeamMu.Lock()
	defer mainSeamMu.Unlock()

	oldMkdirAll := mkdirAllFunc
	oldWriteFile := writeFileFunc
	t.Cleanup(func() {
		mkdirAllFunc = oldMkdirAll
		writeFileFunc = oldWriteFile
	})

	dir := t.TempDir()
	htmlPath := filepath.Join(dir, "report.html")

	mkdirAllFunc = func(path string, perm os.FileMode) error {
		if path == filepath.Dir(htmlPath) {
			return errors.New("mkdir-failed")
		}
		return nil
	}
	writeFileFunc = oldWriteFile

	err := run([]string{
		"-input", "repository-scan=internal/ci/testdata/repo",
		"-output-html", htmlPath,
		"-output-json", filepath.Join(dir, "report.json"),
		"-output-legal-html", filepath.Join(dir, "legal.html"),
	}, &bytes.Buffer{})
	if err == nil || err.Error() != "mkdir-failed" {
		t.Fatalf("expected mkdir error, got %v", err)
	}
}

func TestRunReturnsErrorWhenVulnerabilityJSONWriteFails(t *testing.T) {
	mainSeamMu.Lock()
	defer mainSeamMu.Unlock()

	oldMkdirAll := mkdirAllFunc
	oldWriteFile := writeFileFunc
	t.Cleanup(func() {
		mkdirAllFunc = oldMkdirAll
		writeFileFunc = oldWriteFile
	})

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/querybatch" {
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"results":[{"vulns":[]},{"vulns":[]},{"vulns":[]},{"vulns":[]}]}`))
	}))
	defer server.Close()

	dir := t.TempDir()
	vulnJSONPath := filepath.Join(dir, "vuln.json")

	mkdirAllFunc = func(string, os.FileMode) error { return nil }
	writeFileFunc = func(path string, data []byte, perm os.FileMode) error {
		if path == vulnJSONPath {
			return errors.New("vuln-json-write-failed")
		}
		return oldWriteFile(path, data, perm)
	}

	err := run([]string{
		"-input", "repository-scan=internal/ci/testdata/repo",
		"-output-html", filepath.Join(dir, "report.html"),
		"-output-json", filepath.Join(dir, "report.json"),
		"-output-legal-html", filepath.Join(dir, "legal.html"),
		"-output-vuln-json", vulnJSONPath,
		"-osv-base-url", server.URL,
	}, &bytes.Buffer{})
	if err == nil || err.Error() != "vuln-json-write-failed" {
		t.Fatalf("expected vulnerability json write error, got %v", err)
	}
}

func TestRunReturnsErrorForBrokenRenderTemplates(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	brokenTemplate := filepath.Join(dir, "broken.html.tmpl")
	if err := os.WriteFile(brokenTemplate, []byte(`{{`), 0o644); err != nil {
		t.Fatalf("write broken template: %v", err)
	}

	err := run([]string{
		"-input", "repository-scan=internal/ci/testdata/repo",
		"-output-html", filepath.Join(dir, "report.html"),
		"-output-json", filepath.Join(dir, "report.json"),
		"-output-legal-html", filepath.Join(dir, "legal.html"),
		"-template", brokenTemplate,
	}, &bytes.Buffer{})
	if err == nil {
		t.Fatal("expected report render error")
	}

	err = run([]string{
		"-input", "repository-scan=internal/ci/testdata/repo",
		"-output-html", filepath.Join(dir, "report2.html"),
		"-output-json", filepath.Join(dir, "report2.json"),
		"-output-legal-html", filepath.Join(dir, "legal2.html"),
		"-legal-template", brokenTemplate,
	}, &bytes.Buffer{})
	if err == nil {
		t.Fatal("expected legal render error")
	}

	err = run([]string{
		"-input", "repository-scan=internal/ci/testdata/repo",
		"-output-html", filepath.Join(dir, "report3.html"),
		"-output-json", filepath.Join(dir, "report3.json"),
		"-output-legal-html", filepath.Join(dir, "legal3.html"),
		"-output-vuln-html", filepath.Join(dir, "vuln.html"),
		"-vuln-template", brokenTemplate,
	}, &bytes.Buffer{})
	if err == nil {
		t.Fatal("expected vulnerability render error")
	}
}

func TestRunReturnsErrorWhenHTMLWritesFail(t *testing.T) {
	mainSeamMu.Lock()
	defer mainSeamMu.Unlock()

	oldMkdirAll := mkdirAllFunc
	oldWriteFile := writeFileFunc
	t.Cleanup(func() {
		mkdirAllFunc = oldMkdirAll
		writeFileFunc = oldWriteFile
	})
	mkdirAllFunc = func(string, os.FileMode) error { return nil }

	t.Run("primary-html", func(t *testing.T) {
		dir := t.TempDir()
		htmlPath := filepath.Join(dir, "report.html")
		writeFileFunc = func(path string, data []byte, perm os.FileMode) error {
			if path == htmlPath {
				return errors.New("html-write-failed")
			}
			return oldWriteFile(path, data, perm)
		}
		err := run([]string{
			"-input", "repository-scan=internal/ci/testdata/repo",
			"-output-html", htmlPath,
			"-output-json", filepath.Join(dir, "report.json"),
			"-output-legal-html", filepath.Join(dir, "legal.html"),
		}, &bytes.Buffer{})
		if err == nil || err.Error() != "html-write-failed" {
			t.Fatalf("expected html write error, got %v", err)
		}
	})

	t.Run("legal-html", func(t *testing.T) {
		dir := t.TempDir()
		legalPath := filepath.Join(dir, "legal.html")
		writeFileFunc = func(path string, data []byte, perm os.FileMode) error {
			if path == legalPath {
				return errors.New("legal-write-failed")
			}
			return oldWriteFile(path, data, perm)
		}
		err := run([]string{
			"-input", "repository-scan=internal/ci/testdata/repo",
			"-output-html", filepath.Join(dir, "report.html"),
			"-output-json", filepath.Join(dir, "report.json"),
			"-output-legal-html", legalPath,
		}, &bytes.Buffer{})
		if err == nil || err.Error() != "legal-write-failed" {
			t.Fatalf("expected legal write error, got %v", err)
		}
	})

	t.Run("vuln-html", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"results":[{"vulns":[]},{"vulns":[]},{"vulns":[]},{"vulns":[]}]}`))
		}))
		defer server.Close()

		dir := t.TempDir()
		vulnHTMLPath := filepath.Join(dir, "vuln.html")
		writeFileFunc = func(path string, data []byte, perm os.FileMode) error {
			if path == vulnHTMLPath {
				return errors.New("vuln-html-write-failed")
			}
			return oldWriteFile(path, data, perm)
		}
		err := run([]string{
			"-input", "repository-scan=internal/ci/testdata/repo",
			"-output-html", filepath.Join(dir, "report.html"),
			"-output-json", filepath.Join(dir, "report.json"),
			"-output-legal-html", filepath.Join(dir, "legal.html"),
			"-output-vuln-html", vulnHTMLPath,
			"-osv-base-url", server.URL,
		}, &bytes.Buffer{})
		if err == nil || err.Error() != "vuln-html-write-failed" {
			t.Fatalf("expected vulnerability html write error, got %v", err)
		}
	})
}

func TestRunReportHTMLIncludesCatalogOverrideContent(t *testing.T) {
	t.Parallel()

	catalogServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/licenses.json" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
  "fallback": "Unknown",
  "licenses": [
    {
      "key": "MIT",
      "name": "MIT License (HTML Remote)",
      "family": "MIT",
      "copyleft_strength": "none",
      "requires_manual_review": false,
      "spdx_ids": ["MIT"],
      "names": ["MIT License (HTML Remote)"],
      "contains": ["mit"],
      "risk_level": "low",
      "notice_template": "html remote notice"
    }
  ]
}`))
	}))
	defer catalogServer.Close()

	dir := t.TempDir()
	htmlPath := filepath.Join(dir, "report.html")

	var stdout bytes.Buffer
	if err := run([]string{
		"-input", "repository-scan=internal/ci/testdata/repo",
		"-license-catalog", "configs/licenses.json",
		"-license-catalog", catalogServer.URL + "/licenses.json",
		"-output-html", htmlPath,
		"-output-json", filepath.Join(dir, "report.json"),
		"-output-legal-html", filepath.Join(dir, "legal.html"),
	}, &stdout); err != nil {
		t.Fatalf("run failed: %v", err)
	}

	htmlBytes, err := os.ReadFile(htmlPath)
	if err != nil {
		t.Fatalf("read report html: %v", err)
	}
	html := string(htmlBytes)

	for _, want := range []string{
		"OSS license inventory and notice in one command.",
		"Generated at:",
		"MIT License (HTML Remote)",
		"Risk: low",
		"All packages:",
		"Production:",
		"Distribution Notice",
		"html remote notice",
		"react",
	} {
		if !strings.Contains(html, want) {
			t.Fatalf("report html missing %q\n%s", want, html)
		}
	}
}

func TestRunLegalHTMLIncludesCatalogOverrideNotice(t *testing.T) {
	t.Parallel()

	catalogServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/licenses.json" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
  "fallback": "Unknown",
  "licenses": [
    {
      "key": "MIT",
      "name": "MIT License (Legal Remote)",
      "family": "MIT",
      "copyleft_strength": "none",
      "requires_manual_review": false,
      "spdx_ids": ["MIT"],
      "names": ["MIT License (Legal Remote)"],
      "contains": ["mit"],
      "risk_level": "low",
      "notice_template": "legal remote notice"
    }
  ]
}`))
	}))
	defer catalogServer.Close()

	dir := t.TempDir()
	legalPath := filepath.Join(dir, "legal.html")

	var stdout bytes.Buffer
	if err := run([]string{
		"-input", "repository-scan=internal/ci/testdata/repo",
		"-license-catalog", "configs/licenses.json",
		"-license-catalog", catalogServer.URL + "/licenses.json",
		"-output-html", filepath.Join(dir, "report.html"),
		"-output-json", filepath.Join(dir, "report.json"),
		"-output-legal-html", legalPath,
	}, &stdout); err != nil {
		t.Fatalf("run failed: %v", err)
	}

	legalBytes, err := os.ReadFile(legalPath)
	if err != nil {
		t.Fatalf("read legal html: %v", err)
	}
	legalHTML := string(legalBytes)

	for _, want := range []string{
		"Open Source Software Legal Notice",
		"Generated at:",
		"Production packages:",
		"MIT License (Legal Remote)",
		"Notice Text",
		"legal remote notice",
		"react",
	} {
		if !strings.Contains(legalHTML, want) {
			t.Fatalf("legal html missing %q\n%s", want, legalHTML)
		}
	}
}

func TestRunLegalHTMLUsesMultiSourceInputContract(t *testing.T) {
	t.Parallel()

	catalogServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/licenses.json" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
  "fallback": "Unknown",
  "licenses": [
    {
      "key": "MIT",
      "name": "MIT License (Multi Source Legal)",
      "family": "MIT",
      "copyleft_strength": "none",
      "requires_manual_review": false,
      "spdx_ids": ["MIT"],
      "names": ["MIT License (Multi Source Legal)"],
      "contains": ["mit"],
      "risk_level": "low",
      "notice_template": "multi source legal notice"
    }
  ]
}`))
	}))
	defer catalogServer.Close()

	dir := t.TempDir()
	legalPath := filepath.Join(dir, "legal.html")

	if err := run([]string{
		"-input", "repository-scan=internal/ci/testdata/repo",
		"-input", "cyclonedx-json=internal/sbom/testdata/cyclonedx/app.json",
		"-license-catalog", "configs/licenses.json",
		"-license-catalog", catalogServer.URL + "/licenses.json",
		"-output-html", filepath.Join(dir, "report.html"),
		"-output-json", filepath.Join(dir, "report.json"),
		"-output-legal-html", legalPath,
	}, &bytes.Buffer{}); err != nil {
		t.Fatalf("run with multi-source legal html failed: %v", err)
	}

	payload, err := os.ReadFile(legalPath)
	if err != nil {
		t.Fatalf("read legal html: %v", err)
	}
	html := string(payload)

	for _, want := range []string{
		"Open Source Software Legal Notice",
		"Generated at:",
		"MIT License (Multi Source Legal)",
		"Embedded License Text",
		"multi source legal notice",
		"react",
	} {
		if !strings.Contains(html, want) {
			t.Fatalf("legal html missing %q\n%s", want, html)
		}
	}
	if strings.Count(html, "<strong>react</strong>") < 2 {
		t.Fatalf("expected react in both embedded and catalog notice groups\n%s", html)
	}
}

func TestRunVulnerabilityJSONUsesCycloneDXInputContract(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/querybatch" {
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"results":[{"vulns":[{"id":"GHSA-cyclonedx-0001","modified":"2026-01-01T00:00:00Z","aliases":["CVE-2026-0001"],"database_specific":{"severity":"HIGH"}}]},{"vulns":[]},{"vulns":[]}]}`))
	}))
	defer server.Close()

	dir := t.TempDir()
	vulnJSONPath := filepath.Join(dir, "vuln.json")

	if err := run([]string{
		"-input", "cyclonedx-json=internal/sbom/testdata/cyclonedx/app.json",
		"-output-html", filepath.Join(dir, "report.html"),
		"-output-json", filepath.Join(dir, "report.json"),
		"-output-legal-html", filepath.Join(dir, "legal.html"),
		"-output-vuln-json", vulnJSONPath,
		"-osv-base-url", server.URL,
	}, &bytes.Buffer{}); err != nil {
		t.Fatalf("run with cyclonedx vulnerability json failed: %v", err)
	}

	payload, err := os.ReadFile(vulnJSONPath)
	if err != nil {
		t.Fatalf("read vulnerability json: %v", err)
	}
	var output struct {
		Provenance struct {
			InputSchemaVersion string   `json:"inputSchemaVersion"`
			Sources            []string `json:"sources"`
		} `json:"provenance"`
		Checklist struct {
			TotalPackages   int `json:"totalPackages"`
			TotalAdvisories int `json:"totalAdvisories"`
			PackageFindings []struct {
				Name       string `json:"name"`
				Severity   string `json:"severity"`
				Advisories []struct {
					ID string `json:"id"`
				} `json:"advisories"`
			} `json:"packageFindings"`
		} `json:"checklist"`
	}
	if err := json.Unmarshal(payload, &output); err != nil {
		t.Fatalf("parse vulnerability json: %v", err)
	}

	if output.Provenance.InputSchemaVersion != "1" {
		t.Fatalf("input schema version = %#v", output.Provenance)
	}
	if !slices.Equal(output.Provenance.Sources, []string{"cyclonedx-json", "metadata-enrichment", "osv"}) {
		t.Fatalf("sources = %#v", output.Provenance.Sources)
	}
	if output.Checklist.TotalPackages != 3 {
		t.Fatalf("total packages = %d", output.Checklist.TotalPackages)
	}
	if output.Checklist.TotalAdvisories != 1 {
		t.Fatalf("total advisories = %d", output.Checklist.TotalAdvisories)
	}
	if len(output.Checklist.PackageFindings) == 0 {
		t.Fatal("expected package findings")
	}
	first := output.Checklist.PackageFindings[0]
	if first.Name != "@facebook/react" || first.Severity != "unknown" {
		t.Fatalf("first finding = %#v", first)
	}
	if len(first.Advisories) != 1 || first.Advisories[0].ID != "GHSA-cyclonedx-0001" {
		t.Fatalf("advisories = %#v", first.Advisories)
	}
}

func TestRunVulnerabilityJSONUsesSPDXInputContract(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/querybatch" {
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"results":[{"vulns":[]},{"vulns":[{"id":"GHSA-spdx-0001","modified":"2026-01-01T00:00:00Z","aliases":["CVE-2026-1001"]}]},{"vulns":[]}]}`))
	}))
	defer server.Close()

	dir := t.TempDir()
	vulnJSONPath := filepath.Join(dir, "vuln.json")

	if err := run([]string{
		"-input", "spdx-json=internal/sbom/testdata/spdx/app.json",
		"-output-html", filepath.Join(dir, "report.html"),
		"-output-json", filepath.Join(dir, "report.json"),
		"-output-legal-html", filepath.Join(dir, "legal.html"),
		"-output-vuln-json", vulnJSONPath,
		"-osv-base-url", server.URL,
	}, &bytes.Buffer{}); err != nil {
		t.Fatalf("run with spdx vulnerability json failed: %v", err)
	}

	payload, err := os.ReadFile(vulnJSONPath)
	if err != nil {
		t.Fatalf("read vulnerability json: %v", err)
	}
	var output struct {
		Provenance struct {
			InputSchemaVersion string   `json:"inputSchemaVersion"`
			Sources            []string `json:"sources"`
		} `json:"provenance"`
		Checklist struct {
			TotalPackages   int `json:"totalPackages"`
			TotalAdvisories int `json:"totalAdvisories"`
			PackageFindings []struct {
				Name       string `json:"name"`
				Advisories []struct {
					ID string `json:"id"`
				} `json:"advisories"`
			} `json:"packageFindings"`
		} `json:"checklist"`
	}
	if err := json.Unmarshal(payload, &output); err != nil {
		t.Fatalf("parse vulnerability json: %v", err)
	}

	if output.Provenance.InputSchemaVersion != "1" {
		t.Fatalf("input schema version = %#v", output.Provenance)
	}
	if !slices.Equal(output.Provenance.Sources, []string{"metadata-enrichment", "osv", "spdx-json"}) {
		t.Fatalf("sources = %#v", output.Provenance.Sources)
	}
	if output.Checklist.TotalPackages != 3 {
		t.Fatalf("total packages = %d", output.Checklist.TotalPackages)
	}
	if output.Checklist.TotalAdvisories != 1 {
		t.Fatalf("total advisories = %d", output.Checklist.TotalAdvisories)
	}

	found := false
	for _, pkg := range output.Checklist.PackageFindings {
		if pkg.Name == "react" && len(pkg.Advisories) == 1 && pkg.Advisories[0].ID == "GHSA-spdx-0001" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected react advisory in %#v", output.Checklist.PackageFindings)
	}
}

func TestRunVulnerabilityJSONUsesMultiSourceInputContract(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/querybatch" {
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"results":[{"vulns":[]},{"vulns":[]},{"vulns":[{"id":"GHSA-multi-0001","modified":"2026-01-01T00:00:00Z"}]},{"vulns":[]},{"vulns":[]},{"vulns":[]}]}`))
	}))
	defer server.Close()

	dir := t.TempDir()
	vulnJSONPath := filepath.Join(dir, "vuln.json")

	if err := run([]string{
		"-input", "repository-scan=internal/ci/testdata/repo",
		"-input", "cyclonedx-json=internal/sbom/testdata/cyclonedx/app.json",
		"-output-html", filepath.Join(dir, "report.html"),
		"-output-json", filepath.Join(dir, "report.json"),
		"-output-legal-html", filepath.Join(dir, "legal.html"),
		"-output-vuln-json", vulnJSONPath,
		"-osv-base-url", server.URL,
	}, &bytes.Buffer{}); err != nil {
		t.Fatalf("run with multi-source vulnerability json failed: %v", err)
	}

	payload, err := os.ReadFile(vulnJSONPath)
	if err != nil {
		t.Fatalf("read vulnerability json: %v", err)
	}
	var output struct {
		Provenance struct {
			InputSchemaVersion string   `json:"inputSchemaVersion"`
			Sources            []string `json:"sources"`
		} `json:"provenance"`
		Checklist struct {
			TotalPackages   int `json:"totalPackages"`
			TotalAdvisories int `json:"totalAdvisories"`
			PackageFindings []struct {
				Name       string   `json:"name"`
				SourceIDs  []string `json:"sourceIds"`
				Advisories []struct {
					ID string `json:"id"`
				} `json:"advisories"`
			} `json:"packageFindings"`
		} `json:"checklist"`
	}
	if err := json.Unmarshal(payload, &output); err != nil {
		t.Fatalf("parse vulnerability json: %v", err)
	}

	if output.Provenance.InputSchemaVersion != "1" {
		t.Fatalf("input schema version = %#v", output.Provenance)
	}
	if !slices.Equal(output.Provenance.Sources, []string{"cyclonedx-json", "metadata-enrichment", "osv", "repository-scan"}) {
		t.Fatalf("sources = %#v", output.Provenance.Sources)
	}
	if output.Checklist.TotalPackages != 6 || output.Checklist.TotalAdvisories != 1 {
		t.Fatalf("unexpected checklist summary: %#v", output.Checklist)
	}

	foundReact := false
	foundAdvisory := false
	for _, pkg := range output.Checklist.PackageFindings {
		if pkg.Name == "react" {
			if !slices.Contains(pkg.SourceIDs, "input-1") || !slices.Contains(pkg.SourceIDs, "input-2") {
				t.Fatalf("react source ids = %#v", pkg.SourceIDs)
			}
			foundReact = true
		}
		if len(pkg.Advisories) == 1 && pkg.Advisories[0].ID == "GHSA-multi-0001" {
			foundAdvisory = true
		}
	}
	if !foundReact || !foundAdvisory {
		t.Fatalf("expected merged react and advisory-bearing package in %#v", output.Checklist.PackageFindings)
	}
}

func TestRunVulnerabilityHTMLUsesMultiSourceInputContract(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/querybatch" {
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"results":[{"vulns":[]},{"vulns":[]},{"vulns":[{"id":"GHSA-multi-html-0001","modified":"2026-01-01T00:00:00Z","summary":"Merged input advisory"}]},{"vulns":[]},{"vulns":[]},{"vulns":[]}]}`))
	}))
	defer server.Close()

	dir := t.TempDir()
	vulnHTMLPath := filepath.Join(dir, "vuln.html")

	if err := run([]string{
		"-input", "repository-scan=internal/ci/testdata/repo",
		"-input", "cyclonedx-json=internal/sbom/testdata/cyclonedx/app.json",
		"-output-html", filepath.Join(dir, "report.html"),
		"-output-json", filepath.Join(dir, "report.json"),
		"-output-legal-html", filepath.Join(dir, "legal.html"),
		"-output-vuln-html", vulnHTMLPath,
		"-osv-base-url", server.URL,
	}, &bytes.Buffer{}); err != nil {
		t.Fatalf("run with multi-source vulnerability html failed: %v", err)
	}

	payload, err := os.ReadFile(vulnHTMLPath)
	if err != nil {
		t.Fatalf("read vulnerability html: %v", err)
	}
	html := string(payload)
	for _, want := range []string{
		"Vulnerability Checklist",
		"Sources: cyclonedx-json, metadata-enrichment, osv, repository-scan",
		"vite",
		"GHSA-multi-html-0001",
		"Query: purl",
	} {
		if !strings.Contains(html, want) {
			t.Fatalf("expected vulnerability html to contain %q\n%s", want, html)
		}
	}
}

func TestRunMultiSourceStaysConsistentAcrossAllOutputs(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/querybatch" {
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"results":[{"vulns":[]},{"vulns":[]},{"vulns":[{"id":"GHSA-all-output-0001","modified":"2026-01-01T00:00:00Z"}]},{"vulns":[]},{"vulns":[]},{"vulns":[]}]}`))
	}))
	defer server.Close()

	dir := t.TempDir()
	reportJSONPath := filepath.Join(dir, "report.json")
	reportHTMLPath := filepath.Join(dir, "report.html")
	legalHTMLPath := filepath.Join(dir, "legal.html")
	vulnJSONPath := filepath.Join(dir, "vuln.json")
	vulnHTMLPath := filepath.Join(dir, "vuln.html")

	if err := run([]string{
		"-input", "repository-scan=internal/ci/testdata/repo",
		"-input", "cyclonedx-json=internal/sbom/testdata/cyclonedx/app.json",
		"-output-html", reportHTMLPath,
		"-output-json", reportJSONPath,
		"-output-legal-html", legalHTMLPath,
		"-output-vuln-json", vulnJSONPath,
		"-output-vuln-html", vulnHTMLPath,
		"-osv-base-url", server.URL,
	}, &bytes.Buffer{}); err != nil {
		t.Fatalf("run with multi-source all outputs failed: %v", err)
	}

	reportJSONPayload, err := os.ReadFile(reportJSONPath)
	if err != nil {
		t.Fatalf("read report json: %v", err)
	}
	var reportOutput struct {
		Provenance struct {
			InputKind string `json:"inputKind"`
		} `json:"provenance"`
		Report struct {
			Root string `json:"root"`
		} `json:"report"`
	}
	if err := json.Unmarshal(reportJSONPayload, &reportOutput); err != nil {
		t.Fatalf("parse report json: %v", err)
	}
	wantRoot := rootDisplay("internal/ci/testdata/repo", "internal/sbom/testdata/cyclonedx/app.json")
	if reportOutput.Provenance.InputKind != "multi-source" || reportOutput.Report.Root != wantRoot {
		t.Fatalf("unexpected report output = %#v", reportOutput)
	}

	reportHTMLPayload, err := os.ReadFile(reportHTMLPath)
	if err != nil {
		t.Fatalf("read report html: %v", err)
	}
	reportHTML := string(reportHTMLPayload)
	wantRootHTML := escapedRootDisplay("internal/ci/testdata/repo", "internal/sbom/testdata/cyclonedx/app.json")
	if !strings.Contains(reportHTML, `Input: <code>`+wantRootHTML+`</code>`) {
		t.Fatalf("report html missing root display %q\n%s", wantRoot, reportHTML)
	}

	legalHTMLPayload, err := os.ReadFile(legalHTMLPath)
	if err != nil {
		t.Fatalf("read legal html: %v", err)
	}
	legalHTML := string(legalHTMLPayload)
	if !strings.Contains(legalHTML, `Repository root: <code>`+wantRootHTML+`</code>`) {
		t.Fatalf("legal html missing root display %q\n%s", wantRoot, legalHTML)
	}

	vulnJSONPayload, err := os.ReadFile(vulnJSONPath)
	if err != nil {
		t.Fatalf("read vulnerability json: %v", err)
	}
	var vulnOutput struct {
		Provenance struct {
			Sources []string `json:"sources"`
		} `json:"provenance"`
		Checklist struct {
			PackageFindings []struct {
				Name       string `json:"name"`
				Advisories []struct {
					ID string `json:"id"`
				} `json:"advisories"`
			} `json:"packageFindings"`
		} `json:"checklist"`
	}
	if err := json.Unmarshal(vulnJSONPayload, &vulnOutput); err != nil {
		t.Fatalf("parse vulnerability json: %v", err)
	}
	if !slices.Equal(vulnOutput.Provenance.Sources, []string{"cyclonedx-json", "metadata-enrichment", "osv", "repository-scan"}) {
		t.Fatalf("vulnerability sources = %#v", vulnOutput.Provenance.Sources)
	}
	foundAdvisory := false
	for _, pkg := range vulnOutput.Checklist.PackageFindings {
		for _, advisory := range pkg.Advisories {
			if advisory.ID == "GHSA-all-output-0001" {
				foundAdvisory = true
			}
		}
	}
	if !foundAdvisory {
		t.Fatalf("vulnerability findings = %#v", vulnOutput.Checklist.PackageFindings)
	}

	vulnHTMLPayload, err := os.ReadFile(vulnHTMLPath)
	if err != nil {
		t.Fatalf("read vulnerability html: %v", err)
	}
	vulnHTML := string(vulnHTMLPayload)
	for _, want := range []string{
		"Sources: cyclonedx-json, metadata-enrichment, osv, repository-scan",
		"GHSA-all-output-0001",
	} {
		if !strings.Contains(vulnHTML, want) {
			t.Fatalf("vulnerability html missing %q\n%s", want, vulnHTML)
		}
	}
}

func TestRunSPDXMultiSourceStaysConsistentAcrossAllOutputs(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/querybatch" {
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"results":[{"vulns":[]},{"vulns":[]},{"vulns":[{"id":"GHSA-spdx-all-output-0001","modified":"2026-01-01T00:00:00Z"}]},{"vulns":[]},{"vulns":[]}]}`))
	}))
	defer server.Close()

	dir := t.TempDir()
	reportJSONPath := filepath.Join(dir, "report.json")
	reportHTMLPath := filepath.Join(dir, "report.html")
	legalHTMLPath := filepath.Join(dir, "legal.html")
	vulnJSONPath := filepath.Join(dir, "vuln.json")
	vulnHTMLPath := filepath.Join(dir, "vuln.html")

	if err := run([]string{
		"-input", "repository-scan=internal/ci/testdata/repo",
		"-input", "spdx-json=internal/sbom/testdata/spdx/app.json",
		"-output-html", reportHTMLPath,
		"-output-json", reportJSONPath,
		"-output-legal-html", legalHTMLPath,
		"-output-vuln-json", vulnJSONPath,
		"-output-vuln-html", vulnHTMLPath,
		"-osv-base-url", server.URL,
	}, &bytes.Buffer{}); err != nil {
		t.Fatalf("run with SPDX multi-source all outputs failed: %v", err)
	}

	reportJSONPayload, err := os.ReadFile(reportJSONPath)
	if err != nil {
		t.Fatalf("read report json: %v", err)
	}
	var reportOutput struct {
		Provenance struct {
			InputKind string `json:"inputKind"`
		} `json:"provenance"`
		Report struct {
			Root string `json:"root"`
		} `json:"report"`
	}
	if err := json.Unmarshal(reportJSONPayload, &reportOutput); err != nil {
		t.Fatalf("parse report json: %v", err)
	}
	wantRoot := rootDisplay("internal/ci/testdata/repo", "internal/sbom/testdata/spdx/app.json")
	if reportOutput.Provenance.InputKind != "multi-source" || reportOutput.Report.Root != wantRoot {
		t.Fatalf("unexpected report output = %#v", reportOutput)
	}

	reportHTMLPayload, err := os.ReadFile(reportHTMLPath)
	if err != nil {
		t.Fatalf("read report html: %v", err)
	}
	reportHTML := string(reportHTMLPayload)
	wantRootHTML := escapedRootDisplay("internal/ci/testdata/repo", "internal/sbom/testdata/spdx/app.json")
	if !strings.Contains(reportHTML, `Input: <code>`+wantRootHTML+`</code>`) {
		t.Fatalf("report html missing root display %q\n%s", wantRoot, reportHTML)
	}

	legalHTMLPayload, err := os.ReadFile(legalHTMLPath)
	if err != nil {
		t.Fatalf("read legal html: %v", err)
	}
	legalHTML := string(legalHTMLPayload)
	if !strings.Contains(legalHTML, `Repository root: <code>`+wantRootHTML+`</code>`) {
		t.Fatalf("legal html missing root display %q\n%s", wantRoot, legalHTML)
	}

	vulnJSONPayload, err := os.ReadFile(vulnJSONPath)
	if err != nil {
		t.Fatalf("read vulnerability json: %v", err)
	}
	var vulnOutput struct {
		Provenance struct {
			Sources []string `json:"sources"`
		} `json:"provenance"`
		Checklist struct {
			PackageFindings []struct {
				Advisories []struct {
					ID string `json:"id"`
				} `json:"advisories"`
			} `json:"packageFindings"`
		} `json:"checklist"`
	}
	if err := json.Unmarshal(vulnJSONPayload, &vulnOutput); err != nil {
		t.Fatalf("parse vulnerability json: %v", err)
	}
	if !slices.Equal(vulnOutput.Provenance.Sources, []string{"metadata-enrichment", "osv", "repository-scan", "spdx-json"}) {
		t.Fatalf("vulnerability sources = %#v", vulnOutput.Provenance.Sources)
	}

	vulnHTMLPayload, err := os.ReadFile(vulnHTMLPath)
	if err != nil {
		t.Fatalf("read vulnerability html: %v", err)
	}
	vulnHTML := string(vulnHTMLPayload)
	for _, want := range []string{
		"Sources: metadata-enrichment, osv, repository-scan, spdx-json",
	} {
		if !strings.Contains(vulnHTML, want) {
			t.Fatalf("vulnerability html missing %q\n%s", want, vulnHTML)
		}
	}
}

func assertBoom() error {
	return &helperError{message: "boom"}
}

type helperError struct {
	message string
}

func (e *helperError) Error() string {
	return e.message
}

func TestMainWritesErrorAndExitsForMissingLegalThemeAsset(t *testing.T) {
	outputs := newCLIOutputPaths(t.TempDir())
	stderr, exitCode := setMainHarness(t, []string{
		os.Args[0],
		"-input", "repository-scan=internal/ci/testdata/repo",
		"-output-html", outputs.HTML,
		"-output-json", outputs.JSON,
		"-output-legal-html", outputs.LegalHTML,
		"-legal-theme-css", filepath.Join(t.TempDir(), "missing-legal.css"),
	})

	main()

	if *exitCode != 1 {
		t.Fatalf("exit code = %d", *exitCode)
	}
	if !strings.Contains(stderr.String(), "error:") || !strings.Contains(stderr.String(), "asset not found") {
		t.Fatalf("stderr = %q", stderr.String())
	}
}
