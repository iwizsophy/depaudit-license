package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"depaudit-license/internal/scan"
	"depaudit-license/internal/vuln"
)

func TestLoadRuntimeConfigRejectsUnknownField(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	configPath := filepath.Join(dir, "depaudit-license.config.json")
	if err := os.WriteFile(configPath, []byte(`{
  "version": "v1alpha1",
  "unknownField": true
}`), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	if _, _, err := loadRuntimeConfig([]string{"-config", configPath}); err == nil {
		t.Fatal("expected unknown field error")
	}
}

func TestLoadRuntimeConfigRejectsUnsupportedVersion(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	configPath := filepath.Join(dir, "depaudit-license.config.json")
	if err := os.WriteFile(configPath, []byte(`{
  "version": "v2"
}`), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	if _, _, err := loadRuntimeConfig([]string{"-config", configPath}); err == nil {
		t.Fatal("expected unsupported version error")
	}
}

func TestLoadRuntimeConfigRejectsTrailingContent(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	configPath := filepath.Join(dir, "depaudit-license.config.json")
	if err := os.WriteFile(configPath, []byte("{\"version\":\"v1alpha1\"}\n{\"extra\":true}"), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	if _, _, err := loadRuntimeConfig([]string{"-config", configPath}); err == nil {
		t.Fatal("expected trailing content error")
	}
}

func TestLoadRuntimeConfigSupportsDoubleDashConfigFlag(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	configPath := filepath.Join(dir, "depaudit-license.config.json")
	if err := os.WriteFile(configPath, []byte(`{"version":"v1alpha1"}`), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	if _, _, err := loadRuntimeConfig([]string{"--config", configPath}); err != nil {
		t.Fatalf("load runtime config with --config: %v", err)
	}
	if _, _, err := loadRuntimeConfig([]string{"--config=" + configPath}); err != nil {
		t.Fatalf("load runtime config with --config=: %v", err)
	}
}

func TestDefaultRuntimeConfigUsesSharedDefaultConstants(t *testing.T) {
	t.Parallel()

	cfg := defaultRuntimeConfig()
	if cfg.osvBaseURL != vuln.DefaultOSVBaseURL {
		t.Fatalf("osvBaseURL = %q", cfg.osvBaseURL)
	}
	if cfg.gitHubAdvisoryBaseURL != vuln.DefaultGitHubAdvisoryBaseURL {
		t.Fatalf("gitHubAdvisoryBaseURL = %q", cfg.gitHubAdvisoryBaseURL)
	}
	if cfg.nvdBaseURL != vuln.DefaultNVDBaseURL {
		t.Fatalf("nvdBaseURL = %q", cfg.nvdBaseURL)
	}
	if cfg.maxPackageArtifactBytes != scan.DefaultMaxPackageArtifactBytes {
		t.Fatalf("maxPackageArtifactBytes = %d", cfg.maxPackageArtifactBytes)
	}
	if cfg.maxPackageMetadataBytes != scan.DefaultMaxPackageMetadataBytes {
		t.Fatalf("maxPackageMetadataBytes = %d", cfg.maxPackageMetadataBytes)
	}
	if cfg.maxEmbeddedLicenseBytes != scan.DefaultMaxEmbeddedLicenseBytes {
		t.Fatalf("maxEmbeddedLicenseBytes = %d", cfg.maxEmbeddedLicenseBytes)
	}
	if cfg.maxPackageArchiveEntries != scan.DefaultMaxPackageArchiveEntries {
		t.Fatalf("maxPackageArchiveEntries = %d", cfg.maxPackageArchiveEntries)
	}
}

func TestParseFlagsUsesRuntimeConfigDefaults(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	repoDir := filepath.Join(dir, "repo")
	catalogPath := filepath.Join(dir, "catalogs", "custom.json")
	overridePath := filepath.Join(dir, "configs", "license-overrides.json")
	policyPath := filepath.Join(dir, "configs", "exclude-policy.json")
	textBundlePath := filepath.Join(dir, "configs", "license-texts.custom.json")
	configPath := filepath.Join(dir, "depaudit-license.config.json")

	if err := os.MkdirAll(filepath.Dir(catalogPath), 0o755); err != nil {
		t.Fatalf("mkdir catalog dir: %v", err)
	}
	if err := os.MkdirAll(filepath.Dir(overridePath), 0o755); err != nil {
		t.Fatalf("mkdir config dir: %v", err)
	}
	if err := os.MkdirAll(repoDir, 0o755); err != nil {
		t.Fatalf("mkdir repo dir: %v", err)
	}
	if err := os.WriteFile(catalogPath, []byte(`{"version":"v1alpha1"}`), 0o644); err != nil {
		t.Fatalf("write catalog: %v", err)
	}
	if err := os.WriteFile(overridePath, []byte(`{"version":"v1alpha1","licenseOverrides":[]}`), 0o644); err != nil {
		t.Fatalf("write override: %v", err)
	}
	if err := os.WriteFile(policyPath, []byte(`{"version":"v1alpha1","shallowExcludes":[],"subgraphExcludes":[]}`), 0o644); err != nil {
		t.Fatalf("write policy: %v", err)
	}
	if err := os.WriteFile(textBundlePath, []byte(`{"locale":"custom","licenses":[]}`), 0o644); err != nil {
		t.Fatalf("write text bundle: %v", err)
	}
	if err := os.WriteFile(configPath, []byte(`{
  "version": "v1alpha1",
  "inputs": ["repository-scan=repo"],
  "outputHtml": "out/report.html",
  "outputJson": "out/report.json",
  "outputLegalHtml": "out/legal.html",
  "outputVulnJson": "out/vuln.json",
  "licenseCatalogs": ["catalogs/custom.json", "https://example.test/licenses.json"],
  "locale": "en",
  "licenseTextBundle": "configs/license-texts.custom.json",
  "licenseOverrideFile": "configs/license-overrides.json",
  "excludePolicy": "configs/exclude-policy.json",
  "remoteCatalogMode": "stale-fallback",
  "remoteCatalogCacheDir": "cache/remote-catalog",
  "httpCacheMode": "cache-only",
  "httpCacheDir": "cache/http",
  "httpCacheTtl": "36h",
  "npmRegistryBaseUrl": "https://npm.example.test",
  "nugetRegistrationBaseUrl": "https://nuget.example.test",
  "githubAdvisoryToken": "config-github-token",
  "nvdApiKey": "config-nvd-key",
  "maxPackageArtifactBytes": 123456,
  "maxPackageMetadataBytes": 654321,
  "maxEmbeddedLicenseBytes": 111222,
  "maxPackageArchiveEntries": 333,
  "timeoutSeconds": 60
}`), 0o644); err != nil {
		t.Fatalf("write runtime config: %v", err)
	}

	cfg, err := parseFlags([]string{"-config", configPath})
	if err != nil {
		t.Fatalf("parse flags: %v", err)
	}

	if len(cfg.inputs) != 1 || cfg.inputs[0].Location != repoDir {
		t.Fatalf("unexpected inputs: %#v", cfg.inputs)
	}
	if cfg.outputHTML != filepath.Join(dir, "out", "report.html") {
		t.Fatalf("outputHTML = %q", cfg.outputHTML)
	}
	if cfg.outputJSON != filepath.Join(dir, "out", "report.json") {
		t.Fatalf("outputJSON = %q", cfg.outputJSON)
	}
	if cfg.outputLegalNoticeHTML != filepath.Join(dir, "out", "legal.html") {
		t.Fatalf("outputLegalNoticeHTML = %q", cfg.outputLegalNoticeHTML)
	}
	if cfg.outputVulnJSON != filepath.Join(dir, "out", "vuln.json") {
		t.Fatalf("outputVulnJSON = %q", cfg.outputVulnJSON)
	}
	if cfg.vulnMode != "osv-only" {
		t.Fatalf("vulnMode = %q", cfg.vulnMode)
	}
	if len(cfg.licenseCatalogs) != 2 || cfg.licenseCatalogs[0] != catalogPath || cfg.licenseCatalogs[1] != "https://example.test/licenses.json" {
		t.Fatalf("licenseCatalogs = %#v", cfg.licenseCatalogs)
	}
	if cfg.locale != "en" {
		t.Fatalf("locale = %q", cfg.locale)
	}
	if cfg.licenseTextBundle != textBundlePath {
		t.Fatalf("licenseTextBundle = %q", cfg.licenseTextBundle)
	}
	if cfg.licenseOverridePath != overridePath {
		t.Fatalf("licenseOverridePath = %q", cfg.licenseOverridePath)
	}
	if cfg.excludePolicyPath != policyPath {
		t.Fatalf("excludePolicyPath = %q", cfg.excludePolicyPath)
	}
	if cfg.remoteCatalogMode != "stale-fallback" {
		t.Fatalf("remoteCatalogMode = %q", cfg.remoteCatalogMode)
	}
	if cfg.remoteCatalogCacheDir != filepath.Join(dir, "cache", "remote-catalog") {
		t.Fatalf("remoteCatalogCacheDir = %q", cfg.remoteCatalogCacheDir)
	}
	if cfg.httpCacheMode != "cache-only" {
		t.Fatalf("httpCacheMode = %q", cfg.httpCacheMode)
	}
	if cfg.httpCacheDir != filepath.Join(dir, "cache", "http") {
		t.Fatalf("httpCacheDir = %q", cfg.httpCacheDir)
	}
	if cfg.httpCacheTTL != 36*time.Hour {
		t.Fatalf("httpCacheTTL = %v", cfg.httpCacheTTL)
	}
	if cfg.npmRegistryBaseURL != "https://npm.example.test" {
		t.Fatalf("npmRegistryBaseURL = %q", cfg.npmRegistryBaseURL)
	}
	if cfg.nugetRegistrationURL != "https://nuget.example.test" {
		t.Fatalf("nugetRegistrationURL = %q", cfg.nugetRegistrationURL)
	}
	if cfg.gitHubAdvisoryToken != "config-github-token" {
		t.Fatalf("gitHubAdvisoryToken = %q", cfg.gitHubAdvisoryToken)
	}
	if cfg.nvdAPIKey != "config-nvd-key" {
		t.Fatalf("nvdAPIKey = %q", cfg.nvdAPIKey)
	}
	if cfg.maxPackageArtifactBytes != 123456 || cfg.maxPackageMetadataBytes != 654321 || cfg.maxEmbeddedLicenseBytes != 111222 || cfg.maxPackageArchiveEntries != 333 {
		t.Fatalf("artifact limits = %#v", cfg)
	}
	if cfg.timeout != 60*time.Second {
		t.Fatalf("timeout = %v", cfg.timeout)
	}
}

func TestParseFlagsSupportsDoubleDashConfigFlag(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	repoDir := filepath.Join(dir, "repo")
	configPath := filepath.Join(dir, "depaudit-license.config.json")
	if err := os.MkdirAll(repoDir, 0o755); err != nil {
		t.Fatalf("mkdir repo dir: %v", err)
	}
	if err := os.WriteFile(configPath, []byte(`{
  "version": "v1alpha1",
  "inputs": ["repository-scan=repo"],
  "outputHtml": "out/report.html"
}`), 0o644); err != nil {
		t.Fatalf("write runtime config: %v", err)
	}

	for _, args := range [][]string{
		{"--config", configPath},
		{"--config=" + configPath},
	} {
		cfg, err := parseFlags(args)
		if err != nil {
			t.Fatalf("parse flags %v: %v", args, err)
		}
		if len(cfg.inputs) != 1 || cfg.inputs[0].Location != repoDir {
			t.Fatalf("inputs for %v = %#v", args, cfg.inputs)
		}
		if cfg.outputHTML != filepath.Join(dir, "out", "report.html") {
			t.Fatalf("outputHTML for %v = %q", args, cfg.outputHTML)
		}
	}
}

func TestParseFlagsRuntimeConfigCLIAndEnvPrecedence(t *testing.T) {
	t.Setenv("DEPAUDIT_LICENSE_GITHUB_ADVISORY_TOKEN", "env-github-token")
	t.Setenv("DEPAUDIT_LICENSE_NVD_API_KEY", "env-nvd-key")

	dir := t.TempDir()
	repoDir := filepath.Join(dir, "repo")
	otherRepoDir := filepath.Join(dir, "other-repo")
	configPath := filepath.Join(dir, "depaudit-license.config.json")
	if err := os.MkdirAll(repoDir, 0o755); err != nil {
		t.Fatalf("mkdir repo dir: %v", err)
	}
	if err := os.MkdirAll(otherRepoDir, 0o755); err != nil {
		t.Fatalf("mkdir other repo dir: %v", err)
	}
	if err := os.WriteFile(configPath, []byte(`{
  "version": "v1alpha1",
  "inputs": ["repository-scan=repo"],
  "outputHtml": "out/from-config.html",
  "githubAdvisoryToken": "config-github-token",
  "nvdApiKey": "config-nvd-key",
  "licenseCatalogs": ["configs/from-config.json"]
}`), 0o644); err != nil {
		t.Fatalf("write runtime config: %v", err)
	}

	cfg, err := parseFlags([]string{
		"-config", configPath,
		"-input", "repository-scan=" + otherRepoDir,
		"-license-catalog", "configs/from-cli.json",
		"-output-html", "dist/from-cli.html",
		"-github-advisory-token", "cli-github-token",
	})
	if err != nil {
		t.Fatalf("parse flags: %v", err)
	}

	if len(cfg.inputs) != 1 || cfg.inputs[0].Location != otherRepoDir {
		t.Fatalf("inputs = %#v", cfg.inputs)
	}
	if cfg.licenseCatalogs[0] != "configs/from-cli.json" || len(cfg.licenseCatalogs) != 1 {
		t.Fatalf("licenseCatalogs = %#v", cfg.licenseCatalogs)
	}
	if cfg.outputHTML != mustAbs(filepath.Join("dist", "from-cli.html")) {
		t.Fatalf("outputHTML = %q", cfg.outputHTML)
	}
	if cfg.gitHubAdvisoryToken != "cli-github-token" {
		t.Fatalf("gitHubAdvisoryToken = %q", cfg.gitHubAdvisoryToken)
	}
	if cfg.nvdAPIKey != "env-nvd-key" {
		t.Fatalf("nvdAPIKey = %q", cfg.nvdAPIKey)
	}
}
