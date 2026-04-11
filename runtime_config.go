package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"depaudit-license/internal/scan"
	"depaudit-license/internal/vuln"
)

const runtimeConfigVersionV1Alpha1 = "v1alpha1"

type runtimeConfigFile struct {
	Version                  string   `json:"version"`
	Inputs                   []string `json:"inputs,omitempty"`
	OutputHTML               *string  `json:"outputHtml,omitempty"`
	OutputJSON               *string  `json:"outputJson,omitempty"`
	OutputLegalHTML          *string  `json:"outputLegalHtml,omitempty"`
	OutputVulnHTML           *string  `json:"outputVulnHtml,omitempty"`
	OutputVulnJSON           *string  `json:"outputVulnJson,omitempty"`
	VulnMode                 *string  `json:"vulnMode,omitempty"`
	LicenseCatalogs          []string `json:"licenseCatalogs,omitempty"`
	Locale                   *string  `json:"locale,omitempty"`
	LicenseTextBundle        *string  `json:"licenseTextBundle,omitempty"`
	LicenseOverrideFile      *string  `json:"licenseOverrideFile,omitempty"`
	ExcludePolicy            *string  `json:"excludePolicy,omitempty"`
	RemoteCatalogMode        *string  `json:"remoteCatalogMode,omitempty"`
	RemoteCatalogCacheDir    *string  `json:"remoteCatalogCacheDir,omitempty"`
	HTTPCacheMode            *string  `json:"httpCacheMode,omitempty"`
	HTTPCacheDir             *string  `json:"httpCacheDir,omitempty"`
	HTTPCacheTTL             *string  `json:"httpCacheTtl,omitempty"`
	Template                 *string  `json:"template,omitempty"`
	ThemeCSS                 *string  `json:"themeCss,omitempty"`
	LegalTemplate            *string  `json:"legalTemplate,omitempty"`
	LegalThemeCSS            *string  `json:"legalThemeCss,omitempty"`
	VulnTemplate             *string  `json:"vulnTemplate,omitempty"`
	VulnThemeCSS             *string  `json:"vulnThemeCss,omitempty"`
	NPMRegistryBaseURL       *string  `json:"npmRegistryBaseUrl,omitempty"`
	NuGetRegistrationBaseURL *string  `json:"nugetRegistrationBaseUrl,omitempty"`
	OSVBaseURL               *string  `json:"osvBaseUrl,omitempty"`
	GitHubAdvisoryBaseURL    *string  `json:"githubAdvisoryBaseUrl,omitempty"`
	GitHubAdvisoryToken      *string  `json:"githubAdvisoryToken,omitempty"`
	NVDBaseURL               *string  `json:"nvdBaseUrl,omitempty"`
	NVDAPIKey                *string  `json:"nvdApiKey,omitempty"`
	MaxPackageArtifactBytes  *int64   `json:"maxPackageArtifactBytes,omitempty"`
	MaxPackageMetadataBytes  *int64   `json:"maxPackageMetadataBytes,omitempty"`
	MaxEmbeddedLicenseBytes  *int64   `json:"maxEmbeddedLicenseBytes,omitempty"`
	MaxPackageArchiveEntries *int     `json:"maxPackageArchiveEntries,omitempty"`
	TimeoutSeconds           *int     `json:"timeoutSeconds,omitempty"`
}

func extractRuntimeConfigPath(args []string) (string, bool, error) {
	configPath := ""
	for index := 0; index < len(args); index++ {
		value := strings.TrimSpace(args[index])
		switch {
		case value == "-config":
			if index+1 >= len(args) {
				return "", false, fmt.Errorf("missing value for -config")
			}
			configPath = strings.TrimSpace(args[index+1])
			index++
		case strings.HasPrefix(value, "-config="):
			configPath = strings.TrimSpace(strings.TrimPrefix(value, "-config="))
		}
	}
	if strings.TrimSpace(configPath) == "" {
		return "", false, nil
	}
	return configPath, true, nil
}

func loadRuntimeConfig(args []string) (runtimeConfigFile, string, error) {
	configPath, ok, err := extractRuntimeConfigPath(args)
	if err != nil {
		return runtimeConfigFile{}, "", err
	}
	if !ok {
		return runtimeConfigFile{}, "", nil
	}

	resolvedConfigPath, err := resolveExistingPath(configPath)
	if err != nil {
		return runtimeConfigFile{}, "", err
	}
	payload, err := os.ReadFile(resolvedConfigPath)
	if err != nil {
		return runtimeConfigFile{}, "", err
	}

	var file runtimeConfigFile
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&file); err != nil {
		return runtimeConfigFile{}, "", err
	}
	if err := decoder.Decode(&struct{}{}); err != nil && !errors.Is(err, io.EOF) {
		return runtimeConfigFile{}, "", fmt.Errorf("invalid trailing content in runtime config: %w", err)
	}
	if strings.TrimSpace(file.Version) != runtimeConfigVersionV1Alpha1 {
		return runtimeConfigFile{}, "", fmt.Errorf("unsupported runtime config version %q", file.Version)
	}

	baseDir := filepath.Dir(resolvedConfigPath)
	normalizeRuntimeConfigPaths(&file, baseDir)
	return file, baseDir, nil
}

func normalizeRuntimeConfigPaths(file *runtimeConfigFile, baseDir string) {
	for index, value := range file.Inputs {
		kind, location, ok := strings.Cut(value, "=")
		if !ok {
			continue
		}
		if isRemoteCatalogSource(location) {
			file.Inputs[index] = strings.TrimSpace(kind) + "=" + strings.TrimSpace(location)
			continue
		}
		file.Inputs[index] = strings.TrimSpace(kind) + "=" + resolveRuntimeConfigPath(baseDir, location)
	}
	for index, value := range file.LicenseCatalogs {
		file.LicenseCatalogs[index] = resolveRuntimeConfigPathMaybeRemote(baseDir, value)
	}
	resolveStringPointerPath(baseDir, file.OutputHTML)
	resolveStringPointerPath(baseDir, file.OutputJSON)
	resolveStringPointerPath(baseDir, file.OutputLegalHTML)
	resolveStringPointerPath(baseDir, file.OutputVulnHTML)
	resolveStringPointerPath(baseDir, file.OutputVulnJSON)
	resolveStringPointerPath(baseDir, file.LicenseTextBundle)
	resolveStringPointerPath(baseDir, file.LicenseOverrideFile)
	resolveStringPointerPath(baseDir, file.ExcludePolicy)
	resolveStringPointerPath(baseDir, file.RemoteCatalogCacheDir)
	resolveStringPointerPath(baseDir, file.HTTPCacheDir)
	resolveStringPointerPath(baseDir, file.Template)
	resolveStringPointerPath(baseDir, file.ThemeCSS)
	resolveStringPointerPath(baseDir, file.LegalTemplate)
	resolveStringPointerPath(baseDir, file.LegalThemeCSS)
	resolveStringPointerPath(baseDir, file.VulnTemplate)
	resolveStringPointerPath(baseDir, file.VulnThemeCSS)
}

func resolveRuntimeConfigPath(baseDir string, value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	if filepath.IsAbs(value) {
		return filepath.Clean(value)
	}
	return filepath.Clean(filepath.Join(baseDir, value))
}

func resolveRuntimeConfigPathMaybeRemote(baseDir string, value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	if isRemoteCatalogSource(value) {
		return value
	}
	return resolveRuntimeConfigPath(baseDir, value)
}

func resolveStringPointerPath(baseDir string, value *string) {
	if value == nil {
		return
	}
	resolved := resolveRuntimeConfigPath(baseDir, *value)
	*value = resolved
}

func defaultRuntimeConfig() config {
	return config{
		outputHTML:               filepath.Join("dist", "depaudit-license.html"),
		outputJSON:               filepath.Join("dist", "depaudit-license.json"),
		outputLegalNoticeHTML:    filepath.Join("dist", "depaudit-license-legal-notice.html"),
		vulnMode:                 "disabled",
		locale:                   "ja",
		remoteCatalogMode:        "fail-fast",
		httpCacheMode:            "use",
		httpCacheTTL:             24 * time.Hour,
		templatePath:             filepath.Join("templates", "report.html.tmpl"),
		themeCSSPath:             filepath.Join("templates", "report.css"),
		legalTemplatePath:        filepath.Join("templates", "legal_notice.html.tmpl"),
		legalThemeCSSPath:        filepath.Join("templates", "legal_notice.css"),
		vulnTemplatePath:         filepath.Join("templates", "vulnerability_checklist.html.tmpl"),
		vulnThemeCSSPath:         filepath.Join("templates", "vulnerability_checklist.css"),
		osvBaseURL:               vuln.DefaultOSVBaseURL,
		gitHubAdvisoryBaseURL:    vuln.DefaultGitHubAdvisoryBaseURL,
		nvdBaseURL:               vuln.DefaultNVDBaseURL,
		maxPackageArtifactBytes:  scan.DefaultMaxPackageArtifactBytes,
		maxPackageMetadataBytes:  scan.DefaultMaxPackageMetadataBytes,
		maxEmbeddedLicenseBytes:  scan.DefaultMaxEmbeddedLicenseBytes,
		maxPackageArchiveEntries: scan.DefaultMaxPackageArchiveEntries,
		timeout:                  15 * time.Second,
	}
}

func applyRuntimeConfigDefaults(cfg *config, file runtimeConfigFile) error {
	if file.OutputHTML != nil {
		cfg.outputHTML = strings.TrimSpace(*file.OutputHTML)
	}
	if file.OutputJSON != nil {
		cfg.outputJSON = strings.TrimSpace(*file.OutputJSON)
	}
	if file.OutputLegalHTML != nil {
		cfg.outputLegalNoticeHTML = strings.TrimSpace(*file.OutputLegalHTML)
	}
	if file.OutputVulnHTML != nil {
		cfg.outputVulnHTML = strings.TrimSpace(*file.OutputVulnHTML)
	}
	if file.OutputVulnJSON != nil {
		cfg.outputVulnJSON = strings.TrimSpace(*file.OutputVulnJSON)
	}
	if file.VulnMode != nil {
		cfg.vulnMode = strings.TrimSpace(*file.VulnMode)
	}
	if file.Locale != nil {
		cfg.locale = strings.TrimSpace(*file.Locale)
	}
	if file.LicenseTextBundle != nil {
		cfg.licenseTextBundle = strings.TrimSpace(*file.LicenseTextBundle)
	}
	if file.LicenseOverrideFile != nil {
		cfg.licenseOverridePath = strings.TrimSpace(*file.LicenseOverrideFile)
	}
	if file.ExcludePolicy != nil {
		cfg.excludePolicyPath = strings.TrimSpace(*file.ExcludePolicy)
	}
	if file.RemoteCatalogMode != nil {
		cfg.remoteCatalogMode = strings.TrimSpace(*file.RemoteCatalogMode)
	}
	if file.RemoteCatalogCacheDir != nil {
		cfg.remoteCatalogCacheDir = strings.TrimSpace(*file.RemoteCatalogCacheDir)
	}
	if file.HTTPCacheMode != nil {
		cfg.httpCacheMode = strings.TrimSpace(*file.HTTPCacheMode)
	}
	if file.HTTPCacheDir != nil {
		cfg.httpCacheDir = strings.TrimSpace(*file.HTTPCacheDir)
	}
	if file.HTTPCacheTTL != nil {
		duration, err := time.ParseDuration(strings.TrimSpace(*file.HTTPCacheTTL))
		if err != nil {
			return fmt.Errorf("invalid runtime config httpCacheTtl: %w", err)
		}
		cfg.httpCacheTTL = duration
	}
	if file.Template != nil {
		cfg.templatePath = strings.TrimSpace(*file.Template)
	}
	if file.ThemeCSS != nil {
		cfg.themeCSSPath = strings.TrimSpace(*file.ThemeCSS)
	}
	if file.LegalTemplate != nil {
		cfg.legalTemplatePath = strings.TrimSpace(*file.LegalTemplate)
	}
	if file.LegalThemeCSS != nil {
		cfg.legalThemeCSSPath = strings.TrimSpace(*file.LegalThemeCSS)
	}
	if file.VulnTemplate != nil {
		cfg.vulnTemplatePath = strings.TrimSpace(*file.VulnTemplate)
	}
	if file.VulnThemeCSS != nil {
		cfg.vulnThemeCSSPath = strings.TrimSpace(*file.VulnThemeCSS)
	}
	if file.NPMRegistryBaseURL != nil {
		cfg.npmRegistryBaseURL = strings.TrimSpace(*file.NPMRegistryBaseURL)
	}
	if file.NuGetRegistrationBaseURL != nil {
		cfg.nugetRegistrationURL = strings.TrimSpace(*file.NuGetRegistrationBaseURL)
	}
	if file.OSVBaseURL != nil {
		cfg.osvBaseURL = strings.TrimSpace(*file.OSVBaseURL)
	}
	if file.GitHubAdvisoryBaseURL != nil {
		cfg.gitHubAdvisoryBaseURL = strings.TrimSpace(*file.GitHubAdvisoryBaseURL)
	}
	if file.GitHubAdvisoryToken != nil {
		cfg.gitHubAdvisoryToken = strings.TrimSpace(*file.GitHubAdvisoryToken)
	}
	if file.NVDBaseURL != nil {
		cfg.nvdBaseURL = strings.TrimSpace(*file.NVDBaseURL)
	}
	if file.NVDAPIKey != nil {
		cfg.nvdAPIKey = strings.TrimSpace(*file.NVDAPIKey)
	}
	if file.MaxPackageArtifactBytes != nil {
		cfg.maxPackageArtifactBytes = *file.MaxPackageArtifactBytes
	}
	if file.MaxPackageMetadataBytes != nil {
		cfg.maxPackageMetadataBytes = *file.MaxPackageMetadataBytes
	}
	if file.MaxEmbeddedLicenseBytes != nil {
		cfg.maxEmbeddedLicenseBytes = *file.MaxEmbeddedLicenseBytes
	}
	if file.MaxPackageArchiveEntries != nil {
		cfg.maxPackageArchiveEntries = *file.MaxPackageArchiveEntries
	}
	if file.TimeoutSeconds != nil {
		cfg.timeout = time.Duration(*file.TimeoutSeconds) * time.Second
	}
	return nil
}
