package licenseoverride

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"

	"depaudit-license/internal/catalog"
	"depaudit-license/internal/inventory"
	"depaudit-license/internal/policy"
)

const (
	VersionV1Alpha1 = "v1alpha1"

	ModeIfMissing = "ifMissing"
	ModeForce     = "force"

	sourceKind = "license-override"
)

type File struct {
	Version          string `json:"version"`
	LicenseOverrides []Rule `json:"licenseOverrides,omitempty"`
}

type Rule struct {
	ID         string          `json:"id,omitempty"`
	Reason     string          `json:"reason,omitempty"`
	Match      policy.Selector `json:"match"`
	LicenseKey string          `json:"licenseKey"`
	RawLicense string          `json:"rawLicense,omitempty"`
	Mode       string          `json:"mode,omitempty"`
	Evidence   Evidence        `json:"evidence,omitempty"`
}

type Evidence struct {
	URL        string `json:"url,omitempty"`
	ReviewedBy string `json:"reviewedBy,omitempty"`
	ReviewedAt string `json:"reviewedAt,omitempty"`
	Note       string `json:"note,omitempty"`
}

type ApplyConfig struct {
	Catalog        *catalog.Catalog
	Rules          []Rule
	SourceLocation string
}

func LoadFile(pathValue string, cat *catalog.Catalog) (File, error) {
	payload, err := os.ReadFile(pathValue)
	if err != nil {
		return File{}, fmt.Errorf("read license override file: %w", err)
	}
	doc, err := Parse(payload, cat)
	if err != nil {
		return File{}, fmt.Errorf("parse license override file: %w", err)
	}
	return doc, nil
}

func Parse(payload []byte, cat *catalog.Catalog) (File, error) {
	var doc File
	if err := json.Unmarshal(payload, &doc); err != nil {
		return File{}, err
	}
	if err := doc.Validate(cat); err != nil {
		return File{}, err
	}
	return doc, nil
}

func (f *File) Validate(cat *catalog.Catalog) error {
	if strings.TrimSpace(f.Version) != VersionV1Alpha1 {
		return fmt.Errorf("unsupported license override version %q", f.Version)
	}
	seenIDs := map[string]struct{}{}
	for index := range f.LicenseOverrides {
		if err := f.LicenseOverrides[index].validate(index, seenIDs, cat); err != nil {
			return err
		}
	}
	return nil
}

func (r *Rule) validate(index int, seenIDs map[string]struct{}, cat *catalog.Catalog) error {
	prefix := fmt.Sprintf("licenseOverrides[%d]", index)

	r.ID = strings.TrimSpace(r.ID)
	if r.ID != "" {
		if _, ok := seenIDs[r.ID]; ok {
			return fmt.Errorf("%s.id %q is duplicated", prefix, r.ID)
		}
		seenIDs[r.ID] = struct{}{}
	}
	r.Reason = strings.TrimSpace(r.Reason)
	r.LicenseKey = strings.TrimSpace(r.LicenseKey)
	if r.LicenseKey == "" {
		return fmt.Errorf("%s.licenseKey is required", prefix)
	}
	if !catalogHasKey(cat, r.LicenseKey) {
		return fmt.Errorf("%s.licenseKey %q is not defined in the license catalog", prefix, r.LicenseKey)
	}

	match, err := policy.ValidateSelector(r.Match)
	if err != nil {
		return fmt.Errorf("%s.%w", prefix, err)
	}
	r.Match = match

	r.RawLicense = strings.TrimSpace(r.RawLicense)
	r.Mode = normalizeMode(r.Mode)
	switch r.Mode {
	case ModeIfMissing, ModeForce:
		return nil
	default:
		return fmt.Errorf("%s.mode must be one of ifMissing, force", prefix)
	}
}

func Apply(cfg ApplyConfig, doc inventory.Document) (inventory.Document, error) {
	if len(cfg.Rules) == 0 {
		return cloneDocument(doc), nil
	}
	result := cloneDocument(doc)
	for index, pkg := range result.Packages {
		matches := matchingRules(pkg, cfg.Rules)
		switch len(matches) {
		case 0:
			continue
		case 1:
			updated, diagnostic, changed := applyRule(pkg, matches[0], cfg.Catalog)
			if !changed {
				continue
			}
			result.Packages[index] = updated
			if !hasSource(result.Sources, diagnostic.SourceID) {
				result.Sources = append(result.Sources, inventory.Source{
					ID:       diagnostic.SourceID,
					Kind:     sourceKind,
					Location: firstNonEmpty(cfg.SourceLocation, matches[0].Evidence.URL, matches[0].Reason, matches[0].ID, sourceKind),
				})
			}
			result.Diagnostics = append(result.Diagnostics, diagnostic)
		default:
			return inventory.Document{}, fmt.Errorf("package %s matches multiple license override rules: %s", packageIdentity(pkg), matchedRuleIDs(matches))
		}
	}
	sort.Slice(result.Sources, func(i, j int) bool {
		return result.Sources[i].ID < result.Sources[j].ID
	})
	sortDiagnostics(result.Diagnostics)
	return result, nil
}

func matchingRules(pkg inventory.Package, rules []Rule) []Rule {
	result := make([]Rule, 0, 1)
	for _, rule := range rules {
		if policy.SelectorMatchesPackage(rule.Match, pkg) {
			result = append(result, rule)
		}
	}
	return result
}

func applyRule(pkg inventory.Package, rule Rule, cat *catalog.Catalog) (inventory.Package, inventory.Diagnostic, bool) {
	currentKey := strings.TrimSpace(pkg.LicenseKey)
	if normalizeMode(rule.Mode) == ModeIfMissing && !isMissingLicenseKey(currentKey, cat) {
		return pkg, inventory.Diagnostic{}, false
	}

	previousKey := currentKey
	previousRawLicense := strings.TrimSpace(pkg.RawLicense)
	origin := sourceID(rule)
	if pkg.Provenance.FieldOrigins == nil {
		pkg.Provenance.FieldOrigins = map[string]string{}
	}
	pkg.LicenseKey = strings.TrimSpace(rule.LicenseKey)
	pkg.Provenance.FieldOrigins["licenseKey"] = origin

	rawLicense := strings.TrimSpace(rule.RawLicense)
	if rawLicense == "" && isMissingLicense(previousRawLicense) {
		rawLicense = pkg.LicenseKey
	}
	if rawLicense != "" && rawLicense != previousRawLicense {
		pkg.RawLicense = rawLicense
		pkg.Provenance.FieldOrigins["rawLicense"] = origin
	}
	pkg.Provenance.SourceIDs = uniqueSorted(append(pkg.Provenance.SourceIDs, origin))

	diagnostic := inventory.Diagnostic{
		SourceID:  origin,
		RuleID:    strings.TrimSpace(rule.ID),
		Code:      "license_override_applied",
		Severity:  "info",
		Message:   fmt.Sprintf("applied license override to %s: %s -> %s", packageIdentity(pkg), firstNonEmpty(previousKey, "<empty>"), pkg.LicenseKey),
		Ecosystem: pkg.Ecosystem,
		Project:   pkg.Project,
	}
	return pkg, diagnostic, true
}

func catalogHasKey(cat *catalog.Catalog, key string) bool {
	if cat == nil {
		return false
	}
	_, ok := cat.Definitions[strings.TrimSpace(key)]
	return ok
}

func isMissingLicenseKey(value string, cat *catalog.Catalog) bool {
	normalized := strings.TrimSpace(value)
	if normalized == "" {
		return true
	}
	return cat != nil && normalized == cat.Fallback
}

func isMissingLicense(value string) bool {
	normalized := strings.TrimSpace(value)
	return normalized == "" || strings.EqualFold(normalized, "unknown")
}

func normalizeMode(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ModeIfMissing
	}
	if strings.EqualFold(value, ModeIfMissing) {
		return ModeIfMissing
	}
	return strings.ToLower(value)
}

func sourceID(rule Rule) string {
	if strings.TrimSpace(rule.ID) != "" {
		return sourceKind + ":" + strings.TrimSpace(rule.ID)
	}
	return sourceKind
}

func packageIdentity(pkg inventory.Package) string {
	parts := []string{
		strings.TrimSpace(pkg.Ecosystem),
		strings.TrimSpace(pkg.Project),
		strings.TrimSpace(pkg.Name),
		strings.TrimSpace(pkg.Version),
	}
	return strings.Join(parts, "/")
}

func matchedRuleIDs(rules []Rule) string {
	ids := make([]string, 0, len(rules))
	for _, rule := range rules {
		ids = append(ids, firstNonEmpty(strings.TrimSpace(rule.ID), "<unnamed>"))
	}
	sort.Strings(ids)
	return strings.Join(ids, ", ")
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func uniqueSorted(values []string) []string {
	seen := map[string]struct{}{}
	result := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
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

func sortDiagnostics(values []inventory.Diagnostic) {
	sort.Slice(values, func(i, j int) bool {
		left := strings.Join([]string{
			values[i].SourceID,
			values[i].RuleID,
			values[i].Code,
			values[i].Project,
			values[i].Message,
		}, "\x00")
		right := strings.Join([]string{
			values[j].SourceID,
			values[j].RuleID,
			values[j].Code,
			values[j].Project,
			values[j].Message,
		}, "\x00")
		return left < right
	})
}

func hasSource(sources []inventory.Source, id string) bool {
	for _, source := range sources {
		if source.ID == id {
			return true
		}
	}
	return false
}

func cloneDocument(doc inventory.Document) inventory.Document {
	return inventory.Document{
		Sources:     append([]inventory.Source(nil), doc.Sources...),
		Packages:    clonePackages(doc.Packages),
		Conflicts:   cloneConflicts(doc.Conflicts),
		Diagnostics: cloneDiagnostics(doc.Diagnostics),
	}
}

func clonePackages(packages []inventory.Package) []inventory.Package {
	if len(packages) == 0 {
		return nil
	}
	cloned := make([]inventory.Package, len(packages))
	for index, pkg := range packages {
		cloned[index] = pkg
		cloned[index].Provenance.SourceIDs = append([]string(nil), pkg.Provenance.SourceIDs...)
		cloned[index].Provenance.ConflictFields = append([]string(nil), pkg.Provenance.ConflictFields...)
		if pkg.Provenance.FieldOrigins != nil {
			cloned[index].Provenance.FieldOrigins = make(map[string]string, len(pkg.Provenance.FieldOrigins))
			for field, origin := range pkg.Provenance.FieldOrigins {
				cloned[index].Provenance.FieldOrigins[field] = origin
			}
		}
	}
	return cloned
}

func cloneConflicts(conflicts []inventory.Conflict) []inventory.Conflict {
	if len(conflicts) == 0 {
		return nil
	}
	cloned := make([]inventory.Conflict, len(conflicts))
	for index, conflict := range conflicts {
		cloned[index] = conflict
		cloned[index].Values = append([]inventory.ConflictValue(nil), conflict.Values...)
	}
	return cloned
}

func cloneDiagnostics(diagnostics []inventory.Diagnostic) []inventory.Diagnostic {
	if len(diagnostics) == 0 {
		return nil
	}
	cloned := make([]inventory.Diagnostic, len(diagnostics))
	for index, diagnostic := range diagnostics {
		cloned[index] = diagnostic
		cloned[index].MatchedRoots = append([]string(nil), diagnostic.MatchedRoots...)
		cloned[index].RemovedPackages = append([]string(nil), diagnostic.RemovedPackages...)
		cloned[index].PreservedPackages = append([]string(nil), diagnostic.PreservedPackages...)
	}
	return cloned
}
