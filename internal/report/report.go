package report

import (
	"bytes"
	"encoding/json"
	"fmt"
	"html/template"
	"os"
	"path/filepath"
	"sort"
	"strings"
	texttemplate "text/template"
	"time"

	"depaudit-license/internal/catalog"
	"depaudit-license/internal/inventory"
)

var now = time.Now

type Config struct {
	Root            string
	ExcludePatterns []string
}

type View struct {
	GeneratedAt         string                `json:"generatedAt"`
	Root                string                `json:"root"`
	TotalPackages       int                   `json:"totalPackages"`
	ProductionPackages  int                   `json:"productionPackages"`
	TotalLicenses       int                   `json:"totalLicenses"`
	ProductionLicenses  int                   `json:"productionLicenses"`
	Ecosystems          []string              `json:"ecosystems"`
	DependencyTypes     []string              `json:"dependencyTypes"`
	ExcludePatterns     []string              `json:"excludePatterns,omitempty"`
	RiskSummary         []RiskStat            `json:"riskSummary"`
	Groups              []LicenseGroup        `json:"groups"`
	Packages            []inventory.Package   `json:"packages"`
	ProductionInventory []inventory.Package   `json:"productionInventory"`
	LegalNoticeEvidence []LegalNoticeEvidence `json:"legalNoticeEvidence,omitempty"`
}

type RiskStat struct {
	Level string `json:"level"`
	Label string `json:"label"`
	Count int    `json:"count"`
}

type LicenseGroup struct {
	Key                string              `json:"key"`
	Name               string              `json:"name"`
	Color              string              `json:"color"`
	RiskLevel          string              `json:"riskLevel"`
	Description        string              `json:"description"`
	Obligations        []string            `json:"obligations"`
	Permissions        []string            `json:"permissions"`
	Limitations        []string            `json:"limitations"`
	Packages           []inventory.Package `json:"packages"`
	ProductionPackages []inventory.Package `json:"productionPackages"`
	NoticeText         string              `json:"noticeText,omitempty"`
}

type LegalNoticeEvidence struct {
	Kind            string             `json:"kind"`
	Source          string             `json:"source"`
	Title           string             `json:"title"`
	LicenseName     string             `json:"licenseName,omitempty"`
	LicenseFilePath string             `json:"licenseFilePath,omitempty"`
	Text            string             `json:"text"`
	Packages        []NoticePackageRef `json:"packages"`
}

type NoticePackageRef struct {
	Name            string `json:"name"`
	Project         string `json:"project"`
	Ecosystem       string `json:"ecosystem"`
	Version         string `json:"version"`
	CopyrightHolder string `json:"copyrightHolder,omitempty"`
	CopyrightYear   int    `json:"copyrightYear,omitempty"`
	Repository      string `json:"repository,omitempty"`
	Homepage        string `json:"homepage,omitempty"`
}

type htmlView struct {
	View
	ThemeCSS template.CSS
}

type legalNoticeView struct {
	View
	ThemeCSS template.CSS
}

type noticeTemplateData struct {
	Year         int
	Holders      string
	PackageName  string
	PackageList  string
	PackageCount int
	LicenseName  string
}

func Build(cfg Config, packages []inventory.Package, cat *catalog.Catalog) View {
	return BuildDocument(cfg, inventory.Document{Packages: packages}, cat)
}

func BuildDocument(cfg Config, doc inventory.Document, cat *catalog.Catalog) View {
	allPackages := append([]inventory.Package(nil), doc.Packages...)
	productionPackages := filterProductionPackages(doc.Packages, cfg.ExcludePatterns)
	allGroups := buildGroups(allPackages, productionPackages, cat)

	riskSummary := []RiskStat{
		{Level: "high", Label: "High", Count: 0},
		{Level: "medium", Label: "Medium", Count: 0},
		{Level: "low", Label: "Low", Count: 0},
		{Level: "unknown", Label: "Unknown", Count: 0},
	}
	riskLookup := map[string]*RiskStat{}
	for i := range riskSummary {
		riskLookup[riskSummary[i].Level] = &riskSummary[i]
	}

	productionLicenseSet := map[string]struct{}{}
	totalLicenseSet := map[string]struct{}{}
	for _, group := range allGroups {
		totalLicenseSet[group.Key] = struct{}{}
		if len(group.ProductionPackages) > 0 {
			productionLicenseSet[group.Key] = struct{}{}
			if stat, ok := riskLookup[group.RiskLevel]; ok {
				stat.Count += len(group.ProductionPackages)
			}
		}
	}

	return View{
		GeneratedAt:         now().Format(time.RFC3339),
		Root:                cfg.Root,
		TotalPackages:       len(allPackages),
		ProductionPackages:  len(productionPackages),
		TotalLicenses:       len(totalLicenseSet),
		ProductionLicenses:  len(productionLicenseSet),
		Ecosystems:          uniquePackageField(allPackages, func(pkg inventory.Package) string { return pkg.Ecosystem }),
		DependencyTypes:     uniquePackageField(allPackages, func(pkg inventory.Package) string { return pkg.DependencyType }),
		ExcludePatterns:     cfg.ExcludePatterns,
		RiskSummary:         riskSummary,
		Groups:              allGroups,
		Packages:            allPackages,
		ProductionInventory: productionPackages,
		LegalNoticeEvidence: buildLegalNoticeEvidence(allGroups, productionPackages),
	}
}

func RenderHTML(view View, templatePath string, cssPath string) ([]byte, error) {
	return renderTemplate(view, templatePath, cssPath, func(theme template.CSS) any {
		return htmlView{
			View:     view,
			ThemeCSS: theme,
		}
	})
}

func RenderLegalNoticeHTML(view View, templatePath string, cssPath string) ([]byte, error) {
	return renderTemplate(view, templatePath, cssPath, func(theme template.CSS) any {
		return legalNoticeView{
			View:     view,
			ThemeCSS: theme,
		}
	})
}

func renderTemplate(view View, templatePath string, cssPath string, payload func(template.CSS) any) ([]byte, error) {
	cssPayload, templatePayload, err := readRenderAssets(templatePath, cssPath)
	if err != nil {
		return nil, err
	}

	tpl, err := parseRenderTemplate(templatePath, templatePayload)
	if err != nil {
		return nil, err
	}

	var rendered bytes.Buffer
	if err := tpl.Execute(&rendered, payload(template.CSS(string(cssPayload)))); err != nil {
		return nil, fmt.Errorf("render template: %w", err)
	}

	return rendered.Bytes(), nil
}

func readRenderAssets(templatePath string, cssPath string) ([]byte, []byte, error) {
	cssPayload, err := os.ReadFile(cssPath)
	if err != nil {
		return nil, nil, fmt.Errorf("read CSS: %w", err)
	}

	templatePayload, err := os.ReadFile(templatePath)
	if err != nil {
		return nil, nil, fmt.Errorf("read template: %w", err)
	}
	return cssPayload, templatePayload, nil
}

func parseRenderTemplate(templatePath string, templatePayload []byte) (*template.Template, error) {
	tpl, err := template.New(filepath.Base(templatePath)).Funcs(template.FuncMap{
		"slug":                slug,
		"ecosystemLabel":      ecosystemLabel,
		"dependencyTypeLabel": dependencyTypeLabel,
		"prettyJSON": func(value any) string {
			data, _ := json.MarshalIndent(value, "", "  ")
			return string(data)
		},
	}).Parse(string(templatePayload))
	if err != nil {
		return nil, fmt.Errorf("parse template: %w", err)
	}
	return tpl, nil
}

func filterProductionPackages(packages []inventory.Package, excludePatterns []string) []inventory.Package {
	var result []inventory.Package
	for _, pkg := range packages {
		if isDevelopmentDependency(pkg.DependencyType) {
			continue
		}
		if containsPattern(pkg.Name, excludePatterns) {
			continue
		}
		result = append(result, pkg)
	}
	return result
}

func containsPattern(name string, patterns []string) bool {
	name = strings.ToLower(name)
	for _, pattern := range patterns {
		if pattern != "" && strings.Contains(name, pattern) {
			return true
		}
	}
	return false
}

func isDevelopmentDependency(value string) bool {
	return strings.HasPrefix(strings.ToLower(strings.TrimSpace(value)), "dev")
}

func buildGroups(allPackages []inventory.Package, productionPackages []inventory.Package, cat *catalog.Catalog) []LicenseGroup {
	groupByKey := map[string]*LicenseGroup{}

	for _, pkg := range allPackages {
		def := cat.Lookup(pkg.LicenseKey)
		group := groupByKey[pkg.LicenseKey]
		if group == nil {
			group = &LicenseGroup{
				Key:         pkg.LicenseKey,
				Name:        def.Name,
				Color:       def.Color,
				RiskLevel:   def.RiskLevel,
				Description: def.Description,
				Obligations: append([]string(nil), def.Obligations...),
				Permissions: append([]string(nil), def.Permissions...),
				Limitations: append([]string(nil), def.Limitations...),
			}
			groupByKey[pkg.LicenseKey] = group
		}
		group.Packages = append(group.Packages, pkg)
	}

	for _, pkg := range productionPackages {
		if group := groupByKey[pkg.LicenseKey]; group != nil {
			group.ProductionPackages = append(group.ProductionPackages, pkg)
		}
	}

	var groups []LicenseGroup
	for key, group := range groupByKey {
		sortPackages(group.Packages)
		sortPackages(group.ProductionPackages)

		def := cat.Lookup(key)
		if len(group.ProductionPackages) > 0 {
			group.NoticeText = renderNoticeTemplate(def.NoticeTemplate, group.ProductionPackages, def.Name)
		}
		groups = append(groups, *group)
	}

	sort.Slice(groups, func(i, j int) bool {
		left := strings.Join([]string{
			riskOrder(groups[i].RiskLevel),
			groups[i].Name,
		}, "\x00")
		right := strings.Join([]string{
			riskOrder(groups[j].RiskLevel),
			groups[j].Name,
		}, "\x00")
		return left < right
	})

	return groups
}

func renderNoticeTemplate(source string, packages []inventory.Package, licenseName string) string {
	if strings.TrimSpace(source) == "" {
		return ""
	}

	data := buildNoticeTemplateData(packages, licenseName)

	tpl, err := texttemplate.New("notice").Parse(source)
	if err != nil {
		return source
	}

	var rendered bytes.Buffer
	if err := tpl.Execute(&rendered, data); err != nil {
		return source
	}
	return rendered.String()
}

func buildNoticeTemplateData(packages []inventory.Package, licenseName string) noticeTemplateData {
	return noticeTemplateData{
		Year:         minYear(packages),
		Holders:      strings.Join(uniqueHolders(packages), ", "),
		PackageName:  packages[0].Name,
		PackageList:  strings.Join(uniquePackageNames(packages), ", "),
		PackageCount: len(packages),
		LicenseName:  licenseName,
	}
}

func sortPackages(packages []inventory.Package) {
	sort.Slice(packages, func(i, j int) bool {
		return strings.Join([]string{
			packages[i].Ecosystem,
			packages[i].Project,
			packages[i].Name,
			packages[i].Version,
		}, "\x00") < strings.Join([]string{
			packages[j].Ecosystem,
			packages[j].Project,
			packages[j].Name,
			packages[j].Version,
		}, "\x00")
	})
}

func uniqueHolders(packages []inventory.Package) []string {
	return uniqueStrings(func(pkg inventory.Package) string {
		if strings.TrimSpace(pkg.CopyrightHolder) == "" {
			return pkg.Name
		}
		return pkg.CopyrightHolder
	}, packages)
}

func uniquePackageNames(packages []inventory.Package) []string {
	return uniqueStrings(func(pkg inventory.Package) string {
		return pkg.Name
	}, packages)
}

func uniqueStrings(mapper func(inventory.Package) string, packages []inventory.Package) []string {
	seen := map[string]struct{}{}
	var result []string
	for _, pkg := range packages {
		value := strings.TrimSpace(mapper(pkg))
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}

func uniquePackageField(packages []inventory.Package, mapper func(inventory.Package) string) []string {
	return uniqueStrings(mapper, packages)
}

func minYear(packages []inventory.Package) int {
	best := 0
	for _, pkg := range packages {
		if pkg.CopyrightYear == 0 {
			continue
		}
		if best == 0 || pkg.CopyrightYear < best {
			best = pkg.CopyrightYear
		}
	}
	if best == 0 {
		best = now().Year()
	}
	return best
}

func slug(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	var builder strings.Builder
	lastDash := false
	for _, ch := range value {
		if (ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9') {
			builder.WriteRune(ch)
			lastDash = false
			continue
		}
		if !lastDash {
			builder.WriteRune('-')
			lastDash = true
		}
	}
	return strings.Trim(builder.String(), "-")
}

func riskOrder(level string) string {
	switch level {
	case "high":
		return "0"
	case "medium":
		return "1"
	case "low":
		return "2"
	default:
		return "3"
	}
}

func ecosystemLabel(value string) string {
	switch strings.TrimSpace(value) {
	case "node":
		return "Node.js / npm"
	case "dotnet":
		return ".NET / NuGet"
	case "generic":
		return "Generic"
	default:
		if strings.TrimSpace(value) == "" {
			return "Unknown"
		}
		return value
	}
}

func dependencyTypeLabel(value string) string {
	switch strings.TrimSpace(value) {
	case "dependency":
		return "Runtime dependency"
	case "transitiveDependency":
		return "Transitive runtime dependency"
	case "devDependency":
		return "Development dependency"
	case "devTransitiveDependency":
		return "Transitive development dependency"
	case "peerDependency":
		return "Peer dependency"
	default:
		if strings.TrimSpace(value) == "" {
			return "Unknown"
		}
		return value
	}
}

func productionGroups(groups []LicenseGroup) []LicenseGroup {
	result := make([]LicenseGroup, 0, len(groups))
	for _, group := range groups {
		if len(group.ProductionPackages) == 0 {
			continue
		}
		result = append(result, group)
	}
	return result
}

func buildLegalNoticeEvidence(groups []LicenseGroup, packages []inventory.Package) []LegalNoticeEvidence {
	evidence := make([]LegalNoticeEvidence, 0)
	for _, group := range productionGroups(groups) {
		if strings.TrimSpace(group.NoticeText) == "" {
			continue
		}
		evidence = append(evidence, LegalNoticeEvidence{
			Kind:        "license-notice",
			Source:      "catalog-notice-template",
			Title:       group.Name,
			LicenseName: group.Name,
			Text:        group.NoticeText,
			Packages:    noticePackageRefs(group.ProductionPackages),
		})
	}

	for _, pkg := range packages {
		if strings.TrimSpace(pkg.EmbeddedLicenseText) == "" {
			continue
		}
		evidence = append(evidence, LegalNoticeEvidence{
			Kind:            "embedded-license-text",
			Source:          "embedded-license-file",
			Title:           pkg.Name,
			LicenseFilePath: pkg.EmbeddedLicensePath,
			Text:            pkg.EmbeddedLicenseText,
			Packages:        noticePackageRefs([]inventory.Package{pkg}),
		})
	}

	sort.Slice(evidence, func(i, j int) bool {
		left := strings.Join([]string{evidence[i].Kind, evidence[i].Title, noticePackagesKey(evidence[i].Packages)}, "\x00")
		right := strings.Join([]string{evidence[j].Kind, evidence[j].Title, noticePackagesKey(evidence[j].Packages)}, "\x00")
		return left < right
	})
	return evidence
}

func noticePackageRefs(packages []inventory.Package) []NoticePackageRef {
	refs := make([]NoticePackageRef, 0, len(packages))
	for _, pkg := range packages {
		refs = append(refs, NoticePackageRef{
			Name:            pkg.Name,
			Project:         pkg.Project,
			Ecosystem:       pkg.Ecosystem,
			Version:         pkg.Version,
			CopyrightHolder: pkg.CopyrightHolder,
			CopyrightYear:   pkg.CopyrightYear,
			Repository:      pkg.Repository,
			Homepage:        pkg.Homepage,
		})
	}
	return refs
}

func noticePackagesKey(packages []NoticePackageRef) string {
	parts := make([]string, 0, len(packages))
	for _, pkg := range packages {
		parts = append(parts, strings.Join([]string{pkg.Ecosystem, pkg.Project, pkg.Name, pkg.Version}, "\x00"))
	}
	return strings.Join(parts, "\x01")
}
