package main

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"depaudit-license/internal/input"
)

var mainSeamMu sync.Mutex

func TestParseFlagsCollectsMultipleLicenseCatalogs(t *testing.T) {
	t.Parallel()

	cfg, err := parseFlags([]string{
		"-license-catalog", "configs/base.json",
		"-license-catalog", "configs/override.json",
	})
	if err != nil {
		t.Fatalf("parse flags: %v", err)
	}

	if len(cfg.licenseCatalogs) != 2 {
		t.Fatalf("expected 2 catalog paths, got %d", len(cfg.licenseCatalogs))
	}
	if cfg.licenseCatalogs[0] != "configs/base.json" {
		t.Fatalf("unexpected first catalog: %q", cfg.licenseCatalogs[0])
	}
	if cfg.licenseCatalogs[1] != "configs/override.json" {
		t.Fatalf("unexpected second catalog: %q", cfg.licenseCatalogs[1])
	}
}

func TestParseFlagsUsesDefaultCatalogWhenUnset(t *testing.T) {
	t.Parallel()

	cfg, err := parseFlags(nil)
	if err != nil {
		t.Fatalf("parse flags: %v", err)
	}

	if len(cfg.licenseCatalogs) != 1 {
		t.Fatalf("expected 1 default catalog path, got %d", len(cfg.licenseCatalogs))
	}
	if cfg.licenseCatalogs[0] != filepath.Join("configs", "licenses.json") {
		t.Fatalf("unexpected default catalog: %q", cfg.licenseCatalogs[0])
	}
	if cfg.locale != "ja" {
		t.Fatalf("unexpected default locale: %q", cfg.locale)
	}
	if cfg.remoteCatalogMode != "fail-fast" {
		t.Fatalf("unexpected default remote catalog mode: %q", cfg.remoteCatalogMode)
	}
	if len(cfg.inputs) != 1 || cfg.inputs[0].Kind != "repository-scan" {
		t.Fatalf("unexpected default inputs: %#v", cfg.inputs)
	}
}

func TestParseFlagsCollectsMultipleInputs(t *testing.T) {
	t.Parallel()

	cfg, err := parseFlags([]string{
		"-input", "repository-scan=.",
		"-input", "cyclonedx-json=internal/sbom/testdata/cyclonedx/app.json",
	})
	if err != nil {
		t.Fatalf("parse flags: %v", err)
	}
	if len(cfg.inputs) != 2 {
		t.Fatalf("expected 2 inputs, got %d", len(cfg.inputs))
	}
	if cfg.inputs[0].Kind != "repository-scan" || cfg.inputs[1].Kind != "cyclonedx-json" {
		t.Fatalf("unexpected inputs: %#v", cfg.inputs)
	}
	if cfg.inputs[0].DisplayLocation != "." {
		t.Fatalf("unexpected display location: %#v", cfg.inputs[0])
	}
}

func TestParseFlagsResolvesVulnerabilityOutputsWhenSpecified(t *testing.T) {
	t.Parallel()

	cfg, err := parseFlags([]string{
		"-output-vuln-html", "dist/vuln.html",
		"-output-vuln-json", "dist/vuln.json",
	})
	if err != nil {
		t.Fatalf("parse flags: %v", err)
	}
	if cfg.outputVulnHTML == "" || cfg.outputVulnJSON == "" {
		t.Fatalf("unexpected vulnerability outputs: %#v", cfg)
	}
	if !vulnerabilityOutputsEnabled(cfg) {
		t.Fatal("expected vulnerability outputs to be enabled")
	}
	if cfg.vulnMode != "osv-only" {
		t.Fatalf("unexpected vulnerability mode: %q", cfg.vulnMode)
	}
}

func TestParseFlagsKeepsExplicitVulnerabilityModeAndTimeout(t *testing.T) {
	t.Parallel()

	cfg, err := parseFlags([]string{
		"-output-vuln-json", "dist/vuln.json",
		"-vuln-mode", "full",
		"-npm-registry-base-url", "https://npm.example.test",
		"-nuget-registration-base-url", "https://nuget.example.test",
		"-github-advisory-base-url", "https://github.example.test",
		"-github-advisory-token", "ghs_test",
		"-nvd-base-url", "https://nvd.example.test",
		"-nvd-api-key", "nvd_test",
		"-http-cache-mode", "cache-only",
		"-http-cache-dir", filepath.Join("dist", "http-cache"),
		"-http-cache-ttl", "48h",
		"-timeout-seconds", "42",
	})
	if err != nil {
		t.Fatalf("parse flags: %v", err)
	}
	if cfg.vulnMode != "full" {
		t.Fatalf("unexpected vulnerability mode: %q", cfg.vulnMode)
	}
	if cfg.timeout != 42*time.Second {
		t.Fatalf("unexpected timeout: %v", cfg.timeout)
	}
	if cfg.npmRegistryBaseURL != "https://npm.example.test" {
		t.Fatalf("unexpected npm registry base url: %q", cfg.npmRegistryBaseURL)
	}
	if cfg.nugetRegistrationURL != "https://nuget.example.test" {
		t.Fatalf("unexpected nuget registration base url: %q", cfg.nugetRegistrationURL)
	}
	if cfg.gitHubAdvisoryBaseURL != "https://github.example.test" {
		t.Fatalf("unexpected github advisory base url: %q", cfg.gitHubAdvisoryBaseURL)
	}
	if cfg.gitHubAdvisoryToken != "ghs_test" {
		t.Fatalf("unexpected github advisory token: %q", cfg.gitHubAdvisoryToken)
	}
	if cfg.nvdBaseURL != "https://nvd.example.test" {
		t.Fatalf("unexpected nvd base url: %q", cfg.nvdBaseURL)
	}
	if cfg.nvdAPIKey != "nvd_test" {
		t.Fatalf("unexpected nvd api key: %q", cfg.nvdAPIKey)
	}
	if cfg.httpCacheMode != "cache-only" {
		t.Fatalf("unexpected http cache mode: %q", cfg.httpCacheMode)
	}
	if cfg.httpCacheDir != filepath.Join("dist", "http-cache") {
		t.Fatalf("unexpected http cache dir: %q", cfg.httpCacheDir)
	}
	if cfg.httpCacheTTL != 48*time.Hour {
		t.Fatalf("unexpected http cache ttl: %v", cfg.httpCacheTTL)
	}
	if cfg.maxPackageArtifactBytes != 268435456 || cfg.maxPackageMetadataBytes != 1048576 || cfg.maxEmbeddedLicenseBytes != 4194304 || cfg.maxPackageArchiveEntries != 10000 {
		t.Fatalf("unexpected artifact read limits: %#v", cfg)
	}
}

func TestParseFlagsRejectsVulnerabilityModeWithoutOutputs(t *testing.T) {
	t.Parallel()

	if _, err := parseFlags([]string{"-vuln-mode", "full"}); err == nil {
		t.Fatal("expected vulnerability mode validation error")
	}
}

func TestParseFlagsLoadsAPISecretsFromEnvironment(t *testing.T) {
	t.Setenv("DEPAUDIT_LICENSE_GITHUB_ADVISORY_TOKEN", "env-github-token")
	t.Setenv("DEPAUDIT_LICENSE_NVD_API_KEY", "env-nvd-key")

	cfg, err := parseFlags([]string{"-output-vuln-json", "dist/vuln.json"})
	if err != nil {
		t.Fatalf("parse flags: %v", err)
	}
	if cfg.gitHubAdvisoryToken != "env-github-token" {
		t.Fatalf("github token = %q", cfg.gitHubAdvisoryToken)
	}
	if cfg.nvdAPIKey != "env-nvd-key" {
		t.Fatalf("nvd api key = %q", cfg.nvdAPIKey)
	}
}

func TestParseFlagsRejectsInvalidHTTPCacheConfig(t *testing.T) {
	t.Parallel()

	if _, err := parseFlags([]string{"-http-cache-mode", "weird"}); err == nil {
		t.Fatal("expected invalid http cache mode error")
	}
	if _, err := parseFlags([]string{"-http-cache-ttl", "-1s"}); err == nil {
		t.Fatal("expected invalid http cache ttl error")
	}
}

func TestParseFlagsRejectsInvalidArtifactReadLimits(t *testing.T) {
	t.Parallel()

	if _, err := parseFlags([]string{"-max-package-artifact-bytes", "0"}); err == nil {
		t.Fatal("expected invalid package artifact byte limit")
	}
	if _, err := parseFlags([]string{"-max-package-metadata-bytes", "-1"}); err == nil {
		t.Fatal("expected invalid package metadata byte limit")
	}
	if _, err := parseFlags([]string{"-max-embedded-license-bytes", "0"}); err == nil {
		t.Fatal("expected invalid embedded license byte limit")
	}
	if _, err := parseFlags([]string{"-max-package-archive-entries", "0"}); err == nil {
		t.Fatal("expected invalid package archive entry limit")
	}
}

func TestConfiguredExternalSourcesUsesConfiguredEndpoints(t *testing.T) {
	t.Parallel()

	sources := configuredExternalSources(config{
		httpCacheMode:         "use",
		httpCacheTTL:          48 * time.Hour,
		npmRegistryBaseURL:    "https://npm.example.test",
		nugetRegistrationURL:  "https://nuget.example.test",
		vulnMode:              "full",
		osvBaseURL:            "https://osv.example.test",
		gitHubAdvisoryBaseURL: "https://github.example.test",
		gitHubAdvisoryToken:   "token",
		nvdBaseURL:            "https://nvd.example.test",
		nvdAPIKey:             "key",
	})

	gotIDs := make([]string, 0, len(sources))
	for _, source := range sources {
		gotIDs = append(gotIDs, source.ID)
	}
	if !slices.Equal(gotIDs, []string{"npm-registry", "nuget-registration", "github-advisory", "nvd", "osv"}) {
		t.Fatalf("external sources = %#v", sources)
	}
	if sources[2].BaseURL != "https://github.example.test" || !sources[2].AuthConfigured {
		t.Fatalf("github advisory source = %#v", sources[2])
	}
	if sources[3].BaseURL != "https://nvd.example.test" || !sources[3].AuthConfigured {
		t.Fatalf("nvd source = %#v", sources[3])
	}
	if sources[0].CacheMode != "use" || sources[0].CacheTTL != "48h0m0s" {
		t.Fatalf("cache settings = %#v", sources[0])
	}
}

func TestResolveCatalogSourcesKeepsRemoteURL(t *testing.T) {
	t.Parallel()

	sources, err := resolveCatalogSources([]string{"https://example.test/licenses.json"})
	if err != nil {
		t.Fatalf("resolve catalog sources: %v", err)
	}

	if len(sources) != 1 || sources[0] != "https://example.test/licenses.json" {
		t.Fatalf("unexpected resolved sources: %#v", sources)
	}
}

func TestResolveLicenseTextBundleUsesLocaleConvention(t *testing.T) {
	t.Parallel()

	path, err := resolveLicenseTextBundle("ja", "")
	if err != nil {
		t.Fatalf("resolve license text bundle: %v", err)
	}

	if path != filepath.Join(mustAbs("configs"), "license-texts.ja.json") {
		t.Fatalf("unexpected bundle path: %q", path)
	}
}

func TestResolveLicenseTextBundleUsesExplicitPath(t *testing.T) {
	t.Parallel()

	path, err := resolveLicenseTextBundle("en", filepath.Join("configs", "license-texts.ja.json"))
	if err != nil {
		t.Fatalf("resolve explicit bundle path: %v", err)
	}

	if path != filepath.Join(mustAbs("configs"), "license-texts.ja.json") {
		t.Fatalf("unexpected bundle path: %q", path)
	}
}

func TestResolveLicenseTextBundleFallsBackToDefaultLocaleWhenBlank(t *testing.T) {
	t.Parallel()

	path, err := resolveLicenseTextBundle("   ", "")
	if err != nil {
		t.Fatalf("resolve default bundle path: %v", err)
	}
	if path != filepath.Join(mustAbs("configs"), "license-texts.ja.json") {
		t.Fatalf("unexpected default bundle path: %q", path)
	}
}

func TestParseFlagsRejectsInvalidInputSyntax(t *testing.T) {
	t.Parallel()

	if _, err := parseFlags([]string{"-input", "cyclonedx-json"}); err == nil {
		t.Fatal("expected invalid input syntax error")
	}
}

func TestParseFlagsLoadsExcludePolicyFile(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	policyPath := filepath.Join(dir, "exclude-policy.json")
	if err := os.WriteFile(policyPath, []byte(`{
  "version": "v1alpha1",
  "shallowExcludes": [
    {
      "id": "omit-dev",
      "match": {
        "names": ["eslint"]
      }
    }
  ]
}`), 0o644); err != nil {
		t.Fatalf("write exclude policy: %v", err)
	}

	cfg, err := parseFlags([]string{"-exclude-policy", policyPath})
	if err != nil {
		t.Fatalf("parse flags: %v", err)
	}
	if cfg.excludePolicyPath != policyPath {
		t.Fatalf("unexpected policy path: %q", cfg.excludePolicyPath)
	}
	if len(cfg.excludePolicy.ShallowExcludes) != 1 {
		t.Fatalf("unexpected shallow rule count: %d", len(cfg.excludePolicy.ShallowExcludes))
	}
}

func TestParseFlagsResolvesLicenseOverrideFile(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	overridePath := filepath.Join(dir, "license-overrides.json")
	if err := os.WriteFile(overridePath, []byte(`{
  "version": "v1alpha1",
  "licenseOverrides": [
    {
      "id": "react-mit",
      "match": {
        "names": ["react"]
      },
      "licenseKey": "MIT"
    }
  ]
}`), 0o644); err != nil {
		t.Fatalf("write license override: %v", err)
	}

	cfg, err := parseFlags([]string{"-license-override-file", overridePath})
	if err != nil {
		t.Fatalf("parse flags: %v", err)
	}
	if cfg.licenseOverridePath != overridePath {
		t.Fatalf("unexpected license override path: %q", cfg.licenseOverridePath)
	}
}

func TestParseFlagsRejectsMissingLicenseOverrideFile(t *testing.T) {
	t.Parallel()

	if _, err := parseFlags([]string{"-license-override-file", filepath.Join(t.TempDir(), "missing.json")}); err == nil {
		t.Fatal("expected missing license override file error")
	}
}

func TestParseFlagsRejectsInvalidExcludePolicy(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	policyPath := filepath.Join(dir, "exclude-policy.json")
	payload, err := json.Marshal(map[string]any{
		"version":         "v2",
		"shallowExcludes": []map[string]any{{"match": map[string]any{"names": []string{"eslint"}}}},
	})
	if err != nil {
		t.Fatalf("marshal exclude policy: %v", err)
	}
	if err := os.WriteFile(policyPath, payload, 0o644); err != nil {
		t.Fatalf("write exclude policy: %v", err)
	}

	if _, err := parseFlags([]string{"-exclude-policy", policyPath}); err == nil {
		t.Fatal("expected invalid exclude policy error")
	}
}

func TestParseFlagsRejectsUnknownInputKind(t *testing.T) {
	t.Parallel()

	if _, err := parseFlags([]string{"-input", "unknown=."}); err == nil {
		t.Fatal("expected unknown input kind error")
	}
}

func TestValidateConfigRejectsInvalidModeAndEmptyInputs(t *testing.T) {
	t.Parallel()

	if err := validateConfig(config{vulnMode: "weird", inputs: []input.SourceSpec{{Kind: input.InputKindRepositoryScan}}}); err == nil {
		t.Fatal("expected invalid mode error")
	}
	if err := validateConfig(config{}); err == nil {
		t.Fatal("expected empty input error")
	}
}

func TestResolveAssetPathReturnsErrorForMissingFile(t *testing.T) {
	t.Parallel()

	if _, err := resolveAssetPath(filepath.Join(t.TempDir(), "missing.txt")); err == nil {
		t.Fatal("expected missing asset error")
	}
}

func TestResolveAssetHelpersAndWriteFile(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	assetPath := filepath.Join(dir, "asset.txt")
	if err := os.WriteFile(assetPath, []byte("ok"), 0o644); err != nil {
		t.Fatalf("write asset: %v", err)
	}
	resolved, err := resolveAssetPath(assetPath)
	if err != nil {
		t.Fatalf("resolve asset path: %v", err)
	}
	if resolved != assetPath {
		t.Fatalf("resolved = %q", resolved)
	}
	resolvedList, err := resolveAssetPaths([]string{assetPath})
	if err != nil || len(resolvedList) != 1 {
		t.Fatalf("resolve asset paths = %#v, %v", resolvedList, err)
	}

	outputPath := filepath.Join(dir, "nested", "out.txt")
	if err := writeFile(outputPath, []byte("hello")); err != nil {
		t.Fatalf("write file: %v", err)
	}
	payload, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatalf("read file: %v", err)
	}
	if string(payload) != "hello" {
		t.Fatalf("payload = %q", string(payload))
	}
}

func TestResolveAssetPathsReturnsErrorWhenAnyAssetIsMissing(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	assetPath := filepath.Join(dir, "asset.txt")
	if err := os.WriteFile(assetPath, []byte("ok"), 0o644); err != nil {
		t.Fatalf("write asset: %v", err)
	}
	if _, err := resolveAssetPaths([]string{assetPath, filepath.Join(dir, "missing.txt")}); err == nil {
		t.Fatal("expected asset path resolution error")
	}
}

func TestHelperFunctions(t *testing.T) {
	t.Parallel()

	if !exists("configs") {
		t.Fatal("expected configs to exist")
	}
	if got := normalizeDisplayLocation(`.\testdata\..\configs\licenses.json`); got != filepath.Clean(`.\testdata\..\configs\licenses.json`) {
		t.Fatalf("normalizeDisplayLocation = %q", got)
	}
	roots := sourceLocalRepositoryRoots(input.SourceSpec{Kind: input.InputKindRepositoryScan, Location: `D:\repo`})
	if len(roots) != 1 || roots[0] != `D:\repo` {
		t.Fatalf("repository roots = %#v", roots)
	}
	if got := sourceLocalRepositoryRoots(input.SourceSpec{Kind: input.InputKindCycloneDXJSON, Location: `D:\repo\bom.json`}); got != nil {
		t.Fatalf("non-repository-scan roots = %#v", got)
	}
}

func TestMainHelperBranches(t *testing.T) {
	t.Parallel()

	if vulnerabilityOutputsEnabled(config{}) {
		t.Fatal("expected vulnerability outputs to be disabled")
	}
	if !vulnerabilityOutputsEnabled(config{outputVulnJSON: "x.json"}) {
		t.Fatal("expected vulnerability outputs to be enabled by JSON output")
	}
	if got := normalizeDisplayLocation(" https://example.test/catalog.json "); got != "https://example.test/catalog.json" {
		t.Fatalf("normalizeDisplayLocation remote = %q", got)
	}
	if got := normalizeDisplayLocation("   "); got != "" {
		t.Fatalf("normalizeDisplayLocation blank = %q", got)
	}

	var values multiStringFlag
	if got := values.String(); got != "" {
		t.Fatalf("String empty = %q", got)
	}
	if err := values.Set("a"); err != nil {
		t.Fatalf("Set a: %v", err)
	}
	if err := values.Set("b"); err != nil {
		t.Fatalf("Set b: %v", err)
	}
	if got := values.String(); got != "a,b" {
		t.Fatalf("String joined = %q", got)
	}
}

func TestResolveInputSourcesTrimsKindAndDisplayLocation(t *testing.T) {
	t.Parallel()

	sources, err := resolveInputSources([]string{"  repository-scan  = . "})
	if err != nil {
		t.Fatalf("resolveInputSources: %v", err)
	}
	if len(sources) != 1 {
		t.Fatalf("sources = %#v", sources)
	}
	if sources[0].Kind != input.InputKindRepositoryScan {
		t.Fatalf("kind = %q", sources[0].Kind)
	}
	if sources[0].DisplayLocation != "." {
		t.Fatalf("display location = %q", sources[0].DisplayLocation)
	}
}

func TestResolveExistingPathAndCatalogSourceErrors(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	existing := filepath.Join(dir, "catalog.json")
	if err := os.WriteFile(existing, []byte(`{"fallback":"Unknown","licenses":[{"key":"Unknown","name":"Unknown","family":"Unknown","version":"","copyleft_strength":"unknown","requires_manual_review":true,"spdx_ids":["unknown"],"risk_level":"unknown"}]}`), 0o644); err != nil {
		t.Fatalf("write catalog: %v", err)
	}

	resolved, err := resolveExistingPath(existing)
	if err != nil {
		t.Fatalf("resolveExistingPath: %v", err)
	}
	if resolved != existing {
		t.Fatalf("resolved existing = %q", resolved)
	}

	if _, err := resolveExistingPath(filepath.Join(dir, "missing.json")); err == nil {
		t.Fatal("expected missing existing-path error")
	}
	if _, err := resolveCatalogSources([]string{filepath.Join(dir, "missing.json")}); err == nil {
		t.Fatal("expected missing catalog source error")
	}
}

func TestResolveAssetPathFallsBackToExecutableDirectory(t *testing.T) {
	mainSeamMu.Lock()
	defer mainSeamMu.Unlock()

	dir := t.TempDir()
	exeDir := filepath.Join(dir, "bin")
	if err := os.MkdirAll(exeDir, 0o755); err != nil {
		t.Fatalf("mkdir exe dir: %v", err)
	}
	assetPath := filepath.Join(exeDir, "fallback.css")
	if err := os.WriteFile(assetPath, []byte("body{}"), 0o644); err != nil {
		t.Fatalf("write fallback asset: %v", err)
	}

	oldExecutablePath := executablePath
	t.Cleanup(func() {
		executablePath = oldExecutablePath
	})
	executablePath = func() (string, error) {
		return filepath.Join(exeDir, "depaudit-license.exe"), nil
	}

	resolved, err := resolveAssetPath("fallback.css")
	if err != nil {
		t.Fatalf("resolveAssetPath fallback: %v", err)
	}
	if resolved != assetPath {
		t.Fatalf("resolved fallback asset = %q", resolved)
	}
}

func TestResolveAssetPathReturnsNotFoundWhenExecutableLookupFails(t *testing.T) {
	mainSeamMu.Lock()
	defer mainSeamMu.Unlock()

	oldExecutablePath := executablePath
	t.Cleanup(func() {
		executablePath = oldExecutablePath
	})
	executablePath = func() (string, error) {
		return "", errors.New("exe-missing")
	}

	if _, err := resolveAssetPath("missing-from-cwd-and-exe.css"); err == nil || !strings.Contains(err.Error(), "asset not found") {
		t.Fatalf("expected asset not found error, got %v", err)
	}
}

func TestMustAbsFallsBackWhenAbsoluteResolutionFails(t *testing.T) {
	mainSeamMu.Lock()
	defer mainSeamMu.Unlock()

	oldAbsPathFunc := absPathFunc
	t.Cleanup(func() {
		absPathFunc = oldAbsPathFunc
	})
	absPathFunc = func(string) (string, error) {
		return "", errors.New("abs-failed")
	}

	if got := mustAbs(filepath.Join("dist", "report.json")); got != filepath.Join("dist", "report.json") {
		t.Fatalf("mustAbs fallback = %q", got)
	}
}

func TestWriteFileReturnsMkdirAndWriteErrors(t *testing.T) {
	mainSeamMu.Lock()
	defer mainSeamMu.Unlock()

	oldMkdirAll := mkdirAllFunc
	oldWriteFile := writeFileFunc
	t.Cleanup(func() {
		mkdirAllFunc = oldMkdirAll
		writeFileFunc = oldWriteFile
	})

	mkdirAllFunc = func(string, os.FileMode) error {
		return errors.New("mkdir-failed")
	}
	if err := writeFile(filepath.Join(t.TempDir(), "out.txt"), []byte("x")); err == nil || err.Error() != "mkdir-failed" {
		t.Fatalf("expected mkdir error, got %v", err)
	}

	mkdirAllFunc = func(string, os.FileMode) error { return nil }
	writeFileFunc = func(string, []byte, os.FileMode) error {
		return errors.New("write-failed")
	}
	if err := writeFile(filepath.Join(t.TempDir(), "out.txt"), []byte("x")); err == nil || err.Error() != "write-failed" {
		t.Fatalf("expected write error, got %v", err)
	}
}

func TestResolveInputSourcesRejectsMissingSBOMFiles(t *testing.T) {
	t.Parallel()

	if _, err := resolveInputSources([]string{"cyclonedx-json=missing-cdx.json"}); err == nil {
		t.Fatal("expected missing CycloneDX path error")
	}
	if _, err := resolveInputSources([]string{"spdx-json=missing-spdx.json"}); err == nil {
		t.Fatal("expected missing SPDX path error")
	}
}
