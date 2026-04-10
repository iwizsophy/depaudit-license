package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"depaudit-license/internal/catalog"
	"depaudit-license/internal/enrich"
	"depaudit-license/internal/input"
	"depaudit-license/internal/licenseoverride"
	"depaudit-license/internal/policy"
	"depaudit-license/internal/report"
	"depaudit-license/internal/vuln"
)

type config struct {
	inputs                []input.SourceSpec
	outputHTML            string
	outputJSON            string
	outputLegalNoticeHTML string
	outputVulnHTML        string
	outputVulnJSON        string
	vulnMode              string
	licenseCatalogs       []string
	locale                string
	licenseTextBundle     string
	licenseOverridePath   string
	excludePolicyPath     string
	excludePolicy         policy.File
	licenseOverride       licenseoverride.File
	remoteCatalogMode     string
	remoteCatalogCacheDir string
	templatePath          string
	themeCSSPath          string
	legalTemplatePath     string
	legalThemeCSSPath     string
	vulnTemplatePath      string
	vulnThemeCSSPath      string
	osvBaseURL            string
	gitHubAdvisoryBaseURL string
	nvdBaseURL            string
	excludePatterns       []string
	timeout               time.Duration
}

var (
	exitFunc                 = os.Exit
	stderrOut      io.Writer = os.Stderr
	executablePath           = os.Executable
	absPathFunc              = filepath.Abs
	mkdirAllFunc             = os.MkdirAll
	writeFileFunc            = os.WriteFile
)

func main() {
	exitOnError(run(os.Args[1:], os.Stdout))
}

// run keeps the CLI orchestration in one place: load catalog/text resources,
// resolve inputs, apply enrichment, then render report and vulnerability outputs.
func run(args []string, stdout io.Writer) error {
	cfg, err := parseFlags(args)
	if err != nil {
		return err
	}

	client := &http.Client{Timeout: cfg.timeout}

	licenseCatalogSources, err := resolveCatalogSources(cfg.licenseCatalogs)
	if err != nil {
		return err
	}

	templatePath, err := resolveAssetPath(cfg.templatePath)
	if err != nil {
		return err
	}

	themeCSSPath, err := resolveAssetPath(cfg.themeCSSPath)
	if err != nil {
		return err
	}

	legalTemplatePath, err := resolveAssetPath(cfg.legalTemplatePath)
	if err != nil {
		return err
	}

	legalThemeCSSPath, err := resolveAssetPath(cfg.legalThemeCSSPath)
	if err != nil {
		return err
	}

	var vulnTemplatePath string
	var vulnThemeCSSPath string
	if vulnerabilityOutputsEnabled(cfg) {
		vulnTemplatePath, err = resolveAssetPath(cfg.vulnTemplatePath)
		if err != nil {
			return err
		}
		vulnThemeCSSPath, err = resolveAssetPath(cfg.vulnThemeCSSPath)
		if err != nil {
			return err
		}
	}

	loadResult, err := catalog.LoadSourcesWithOptions(catalog.LoadOptions{
		Client:            client,
		RemoteCatalogMode: cfg.remoteCatalogMode,
		CacheDir:          cfg.remoteCatalogCacheDir,
	}, licenseCatalogSources...)
	if err != nil {
		return err
	}
	cat := loadResult.Catalog
	textBundlePath, err := resolveLicenseTextBundle(cfg.locale, cfg.licenseTextBundle)
	if err != nil {
		return err
	}
	textBundle, err := catalog.LoadTextBundle(textBundlePath)
	if err != nil {
		return err
	}
	cat, err = catalog.ApplyTextBundle(cat, textBundle)
	if err != nil {
		return err
	}
	if strings.TrimSpace(cfg.licenseOverridePath) != "" {
		cfg.licenseOverride, err = licenseoverride.LoadFile(cfg.licenseOverridePath, cat)
		if err != nil {
			return err
		}
	}

	inputResult, err := input.Load(input.LoadConfig{
		Sources:       cfg.inputs,
		Client:        client,
		Catalog:       cat,
		SubgraphRules: cfg.excludePolicy.SubgraphExcludes,
	})
	if err != nil {
		return err
	}
	inputResult.Document, err = enrich.Apply(enrich.Config{
		Client:          client,
		Catalog:         cat,
		RepositoryRoots: repositoryScanRoots(cfg.inputs),
	}, inputResult.Document)
	if err != nil {
		return err
	}
	inputResult.Document, err = licenseoverride.Apply(licenseoverride.ApplyConfig{
		Catalog:        cat,
		Rules:          cfg.licenseOverride.LicenseOverrides,
		SourceLocation: cfg.licenseOverridePath,
	}, inputResult.Document)
	if err != nil {
		return err
	}

	view := report.BuildDocument(report.Config{
		Root:            inputResult.Root,
		ExcludePatterns: cfg.excludePatterns,
		ShallowRules:    cfg.excludePolicy.ShallowExcludes,
	}, inputResult.Document, cat)
	view, _, err = report.ExportEmbeddedLicenseTexts(view, report.LicenseTextExportConfig{
		OutputDir: filepath.Join(filepath.Dir(cfg.outputLegalNoticeHTML), "license-texts"),
		LinkBase:  "license-texts",
	})
	if err != nil {
		return err
	}

	html, err := report.RenderHTML(view, templatePath, themeCSSPath)
	if err != nil {
		return err
	}

	if err := writeFile(cfg.outputHTML, html); err != nil {
		return err
	}

	legalNoticeHTML, err := report.RenderLegalNoticeHTML(view, legalTemplatePath, legalThemeCSSPath)
	if err != nil {
		return err
	}
	if err := writeFile(cfg.outputLegalNoticeHTML, legalNoticeHTML); err != nil {
		return err
	}

	output := report.BuildOutput(view, report.OutputConfig{
		InputKind:        inputResult.InputKind,
		CatalogSources:   loadResult.SourceMetadata,
		SelectedLocale:   textBundle.Locale,
		EffectiveCatalog: loadResult.EffectiveCatalog,
	})

	jsonPayload, err := json.MarshalIndent(output, "", "  ")
	if err != nil {
		return err
	}
	if err := writeFile(cfg.outputJSON, jsonPayload); err != nil {
		return err
	}

	if vulnerabilityOutputsEnabled(cfg) {
		vulnInput, err := vuln.BuildAssessmentInput(inputResult.Document)
		if err != nil {
			return err
		}
		pipeline := vuln.RunPipeline(context.Background(), vulnInput, vuln.PipelineConfig{
			Mode:                  cfg.vulnMode,
			Client:                client,
			OSVBaseURL:            cfg.osvBaseURL,
			GitHubAdvisoryBaseURL: cfg.gitHubAdvisoryBaseURL,
			NVDBaseURL:            cfg.nvdBaseURL,
		})
		checklist := vuln.BuildChecklist(vulnInput, pipeline)
		if strings.TrimSpace(cfg.outputVulnHTML) != "" {
			vulnHTML, err := vuln.RenderChecklistHTML(checklist, vulnTemplatePath, vulnThemeCSSPath)
			if err != nil {
				return err
			}
			if err := writeFile(cfg.outputVulnHTML, vulnHTML); err != nil {
				return err
			}
			fmt.Fprintf(stdout, "generated vulnerability HTML: %s\n", cfg.outputVulnHTML)
		}
		if strings.TrimSpace(cfg.outputVulnJSON) != "" {
			vulnJSON, err := json.MarshalIndent(vuln.BuildChecklistOutput(vulnInput, checklist), "", "  ")
			if err != nil {
				return err
			}
			if err := writeFile(cfg.outputVulnJSON, vulnJSON); err != nil {
				return err
			}
			fmt.Fprintf(stdout, "generated vulnerability JSON: %s\n", cfg.outputVulnJSON)
		}
		fmt.Fprintf(stdout, "vulnerability advisories: %d\n", checklist.TotalAdvisories)
	}

	fmt.Fprintf(stdout, "generated HTML: %s\n", cfg.outputHTML)
	fmt.Fprintf(stdout, "generated legal notice HTML: %s\n", cfg.outputLegalNoticeHTML)
	fmt.Fprintf(stdout, "generated JSON: %s\n", cfg.outputJSON)
	fmt.Fprintf(stdout, "packages: %d (production: %d)\n", view.TotalPackages, view.ProductionPackages)
	fmt.Fprintf(stdout, "licenses: %d (production: %d)\n", view.TotalLicenses, view.ProductionLicenses)
	return nil
}

func parseFlags(args []string) (config, error) {
	var cfg config
	var excludePatterns string
	var timeoutSeconds int
	var licenseCatalogs multiStringFlag
	var inputs multiStringFlag

	fs := flag.NewFlagSet("depaudit-license", flag.ContinueOnError)
	fs.Var(&inputs, "input", "input source as kind=location; repeat for multiple sources (repository-scan, cyclonedx-json, spdx-json)")
	fs.StringVar(&cfg.outputHTML, "output-html", filepath.Join("dist", "depaudit-license.html"), "output HTML path")
	fs.StringVar(&cfg.outputJSON, "output-json", filepath.Join("dist", "depaudit-license.json"), "output JSON path")
	fs.StringVar(&cfg.outputLegalNoticeHTML, "output-legal-html", filepath.Join("dist", "depaudit-license-legal-notice.html"), "output legal notice HTML path")
	fs.StringVar(&cfg.outputVulnHTML, "output-vuln-html", "", "output vulnerability checklist HTML path")
	fs.StringVar(&cfg.outputVulnJSON, "output-vuln-json", "", "output vulnerability checklist JSON path")
	fs.StringVar(&cfg.vulnMode, "vuln-mode", vuln.ModeDisabled, "vulnerability pipeline mode: disabled, osv-only, osv+github, or full")
	fs.Var(&licenseCatalogs, "license-catalog", "license catalog JSON path or https URL; specify multiple times to apply later sources as overrides")
	fs.StringVar(&cfg.locale, "locale", "ja", "license description locale")
	fs.StringVar(&cfg.licenseTextBundle, "license-text-bundle", "", "license description bundle JSON path; overrides -locale when specified")
	fs.StringVar(&cfg.licenseOverridePath, "license-override-file", "", "package-level license override JSON path")
	fs.StringVar(&cfg.excludePolicyPath, "exclude-policy", "", "exclude policy JSON path")
	fs.StringVar(&cfg.remoteCatalogMode, "remote-catalog-mode", catalog.RemoteCatalogModeFailFast, "remote catalog mode: fail-fast or stale-fallback")
	fs.StringVar(&cfg.remoteCatalogCacheDir, "remote-catalog-cache-dir", "", "remote catalog cache directory; default is the user cache directory")
	fs.StringVar(&cfg.templatePath, "template", filepath.Join("templates", "report.html.tmpl"), "HTML template path")
	fs.StringVar(&cfg.themeCSSPath, "theme-css", filepath.Join("templates", "report.css"), "theme CSS path")
	fs.StringVar(&cfg.legalTemplatePath, "legal-template", filepath.Join("templates", "legal_notice.html.tmpl"), "legal notice HTML template path")
	fs.StringVar(&cfg.legalThemeCSSPath, "legal-theme-css", filepath.Join("templates", "legal_notice.css"), "legal notice CSS path")
	fs.StringVar(&cfg.vulnTemplatePath, "vuln-template", filepath.Join("templates", "vulnerability_checklist.html.tmpl"), "vulnerability checklist HTML template path")
	fs.StringVar(&cfg.vulnThemeCSSPath, "vuln-theme-css", filepath.Join("templates", "vulnerability_checklist.css"), "vulnerability checklist CSS path")
	fs.StringVar(&cfg.osvBaseURL, "osv-base-url", vuln.DefaultOSVBaseURL, "OSV API base URL")
	fs.StringVar(&cfg.gitHubAdvisoryBaseURL, "github-advisory-base-url", vuln.DefaultGitHubAdvisoryBaseURL, "GitHub Advisory API base URL")
	fs.StringVar(&cfg.nvdBaseURL, "nvd-base-url", vuln.DefaultNVDBaseURL, "NVD API base URL")
	fs.StringVar(&excludePatterns, "exclude-patterns", "", "comma-separated package name fragments to exclude from production notices")
	fs.IntVar(&timeoutSeconds, "timeout-seconds", 15, "HTTP timeout in seconds")
	if err := fs.Parse(args); err != nil {
		return config{}, err
	}

	if len(inputs) == 0 {
		inputs = append(inputs, input.InputKindRepositoryScan+"=.")
	}
	resolvedInputs, err := resolveInputSources(inputs)
	if err != nil {
		return config{}, err
	}
	cfg.inputs = resolvedInputs
	cfg.outputHTML = mustAbs(cfg.outputHTML)
	cfg.outputJSON = mustAbs(cfg.outputJSON)
	cfg.outputLegalNoticeHTML = mustAbs(cfg.outputLegalNoticeHTML)
	if strings.TrimSpace(cfg.outputVulnHTML) != "" {
		cfg.outputVulnHTML = mustAbs(cfg.outputVulnHTML)
	}
	if strings.TrimSpace(cfg.outputVulnJSON) != "" {
		cfg.outputVulnJSON = mustAbs(cfg.outputVulnJSON)
	}
	if len(licenseCatalogs) == 0 {
		licenseCatalogs = append(licenseCatalogs, filepath.Join("configs", "licenses.json"))
	}
	cfg.licenseCatalogs = append([]string(nil), licenseCatalogs...)
	cfg.excludePatterns = splitPatterns(excludePatterns)
	cfg.excludePolicy = policy.File{Version: policy.VersionV1Alpha1}
	cfg.licenseOverride = licenseoverride.File{Version: licenseoverride.VersionV1Alpha1}
	if strings.TrimSpace(cfg.licenseOverridePath) != "" {
		pathValue, err := resolveExistingPath(cfg.licenseOverridePath)
		if err != nil {
			return config{}, err
		}
		cfg.licenseOverridePath = pathValue
	}
	if strings.TrimSpace(cfg.excludePolicyPath) != "" {
		pathValue, err := resolveExistingPath(cfg.excludePolicyPath)
		if err != nil {
			return config{}, err
		}
		cfg.excludePolicyPath = pathValue
		cfg.excludePolicy, err = policy.LoadFile(pathValue)
		if err != nil {
			return config{}, err
		}
	}
	cfg.excludePolicy = policy.MergeLegacyPatterns(cfg.excludePolicy, cfg.excludePatterns)
	if vulnerabilityOutputsEnabled(cfg) && strings.TrimSpace(cfg.vulnMode) == vuln.ModeDisabled {
		cfg.vulnMode = vuln.ModeOSVOnly
	}
	cfg.timeout = time.Duration(timeoutSeconds) * time.Second
	if err := validateConfig(cfg); err != nil {
		return config{}, err
	}
	return cfg, nil
}

func splitPatterns(raw string) []string {
	if strings.TrimSpace(raw) == "" {
		return nil
	}

	parts := strings.Split(raw, ",")
	result := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part != "" {
			result = append(result, strings.ToLower(part))
		}
	}
	return result
}

func resolveAssetPath(pathValue string) (string, error) {
	if filepath.IsAbs(pathValue) {
		if exists(pathValue) {
			return pathValue, nil
		}
		return "", fmt.Errorf("asset not found: %s", pathValue)
	}

	cwdCandidate := mustAbs(pathValue)
	if exists(cwdCandidate) {
		return cwdCandidate, nil
	}

	exePath, err := executablePath()
	if err == nil {
		exeCandidate := filepath.Join(filepath.Dir(exePath), pathValue)
		if exists(exeCandidate) {
			return exeCandidate, nil
		}
	}

	return "", fmt.Errorf("asset not found: %s", pathValue)
}

func resolveExistingPath(pathValue string) (string, error) {
	absolute := mustAbs(pathValue)
	if !exists(absolute) {
		return "", fmt.Errorf("asset not found: %s", pathValue)
	}
	return absolute, nil
}

func resolveAssetPaths(values []string) ([]string, error) {
	paths := make([]string, 0, len(values))
	for _, value := range values {
		path, err := resolveAssetPath(value)
		if err != nil {
			return nil, err
		}
		paths = append(paths, path)
	}
	return paths, nil
}

func resolveCatalogSources(values []string) ([]string, error) {
	sources := make([]string, 0, len(values))
	for _, value := range values {
		if isRemoteCatalogSource(value) {
			sources = append(sources, value)
			continue
		}
		path, err := resolveAssetPath(value)
		if err != nil {
			return nil, err
		}
		sources = append(sources, path)
	}
	return sources, nil
}

func resolveLicenseTextBundle(locale string, explicitPath string) (string, error) {
	if strings.TrimSpace(explicitPath) != "" {
		return resolveAssetPath(explicitPath)
	}

	selectedLocale := strings.TrimSpace(locale)
	if selectedLocale == "" {
		selectedLocale = "ja"
	}
	return resolveAssetPath(filepath.Join("configs", "license-texts."+selectedLocale+".json"))
}

func isRemoteCatalogSource(value string) bool {
	return strings.HasPrefix(strings.ToLower(strings.TrimSpace(value)), "http://") ||
		strings.HasPrefix(strings.ToLower(strings.TrimSpace(value)), "https://")
}

func exists(pathValue string) bool {
	_, err := os.Stat(pathValue)
	return err == nil
}

func mustAbs(pathValue string) string {
	abs, err := absPathFunc(pathValue)
	if err != nil {
		return pathValue
	}
	return abs
}

func writeFile(pathValue string, data []byte) error {
	if err := mkdirAllFunc(filepath.Dir(pathValue), 0o755); err != nil {
		return err
	}
	return writeFileFunc(pathValue, data, 0o644)
}

func validateConfig(cfg config) error {
	if len(cfg.inputs) == 0 {
		return fmt.Errorf("input source list is empty")
	}
	switch strings.TrimSpace(cfg.vulnMode) {
	case "", vuln.ModeDisabled, vuln.ModeOSVOnly, vuln.ModeOSVGitHub, vuln.ModeFull:
	default:
		return fmt.Errorf("unsupported vulnerability mode %q", cfg.vulnMode)
	}
	if strings.TrimSpace(cfg.vulnMode) != "" && strings.TrimSpace(cfg.vulnMode) != vuln.ModeDisabled && !vulnerabilityOutputsEnabled(cfg) {
		return fmt.Errorf("vulnerability outputs must be configured when -vuln-mode is enabled")
	}
	return nil
}

func vulnerabilityOutputsEnabled(cfg config) bool {
	return strings.TrimSpace(cfg.outputVulnHTML) != "" || strings.TrimSpace(cfg.outputVulnJSON) != ""
}

func resolveInputSources(values []string) ([]input.SourceSpec, error) {
	sources := make([]input.SourceSpec, 0, len(values))
	for index, value := range values {
		kind, location, ok := strings.Cut(value, "=")
		if !ok {
			return nil, fmt.Errorf("invalid -input %q: expected kind=location", value)
		}
		location = strings.TrimSpace(location)
		spec := input.SourceSpec{
			ID:              fmt.Sprintf("input-%d", index+1),
			Kind:            strings.TrimSpace(kind),
			DisplayLocation: normalizeDisplayLocation(location),
		}
		// Inputs are normalized at the CLI boundary so downstream loaders can rely
		// on stable IDs, absolute local paths, and display locations.
		switch spec.Kind {
		case input.InputKindRepositoryScan:
			path, err := resolveExistingPath(location)
			if err != nil {
				return nil, err
			}
			spec.Location = path
		case input.InputKindCycloneDXJSON, input.InputKindSPDXJSON:
			path, err := resolveExistingPath(location)
			if err != nil {
				return nil, err
			}
			spec.Location = path
		default:
			return nil, fmt.Errorf("unsupported input kind %q", spec.Kind)
		}
		sources = append(sources, spec)
	}
	return sources, nil
}

func normalizeDisplayLocation(pathValue string) string {
	pathValue = strings.TrimSpace(pathValue)
	if pathValue == "" {
		return ""
	}
	if isRemoteCatalogSource(pathValue) {
		return pathValue
	}
	return filepath.Clean(pathValue)
}

func repositoryScanRoots(inputs []input.SourceSpec) []string {
	roots := make([]string, 0, len(inputs))
	for _, source := range inputs {
		if source.Kind == input.InputKindRepositoryScan {
			roots = append(roots, source.Location)
		}
	}
	return roots
}

func exitOnError(err error) {
	if err == nil {
		return
	}

	fmt.Fprintf(stderrOut, "error: %v\n", err)
	exitFunc(1)
}

type multiStringFlag []string

func (m *multiStringFlag) String() string {
	return strings.Join(*m, ",")
}

func (m *multiStringFlag) Set(value string) error {
	*m = append(*m, value)
	return nil
}
