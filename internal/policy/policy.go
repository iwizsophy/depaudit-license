package policy

import (
	"encoding/json"
	"fmt"
	"os"
	"path"
	"slices"
	"strings"
)

const (
	VersionV1Alpha1 = "v1alpha1"

	OnUnsupportedWarn   = "warn"
	OnUnsupportedError  = "error"
	OnUnsupportedIgnore = "ignore"

	legacyExcludePatternsRuleID = "legacy-exclude-patterns"
)

type File struct {
	Version          string `json:"version"`
	ShallowExcludes  []Rule `json:"shallowExcludes,omitempty"`
	SubgraphExcludes []Rule `json:"subgraphExcludes,omitempty"`
}

type Rule struct {
	ID            string   `json:"id,omitempty"`
	Reason        string   `json:"reason,omitempty"`
	Match         Selector `json:"match"`
	OnUnsupported string   `json:"onUnsupported,omitempty"`
}

type Selector struct {
	Ecosystems       []string `json:"ecosystems,omitempty"`
	Names            []string `json:"names,omitempty"`
	NameGlobs        []string `json:"nameGlobs,omitempty"`
	Versions         []string `json:"versions,omitempty"`
	Projects         []string `json:"projects,omitempty"`
	DependencyTypes  []string `json:"dependencyTypes,omitempty"`
	HasRuntimeAssets *bool    `json:"hasRuntimeAssets,omitempty"`
	PURLs            []string `json:"purls,omitempty"`
}

func LoadFile(pathValue string) (File, error) {
	payload, err := os.ReadFile(pathValue)
	if err != nil {
		return File{}, fmt.Errorf("read exclude policy: %w", err)
	}
	doc, err := Parse(payload)
	if err != nil {
		return File{}, fmt.Errorf("parse exclude policy: %w", err)
	}
	return doc, nil
}

func Parse(payload []byte) (File, error) {
	var doc File
	if err := json.Unmarshal(payload, &doc); err != nil {
		return File{}, err
	}
	if err := doc.Validate(); err != nil {
		return File{}, err
	}
	return doc, nil
}

func (f *File) Validate() error {
	if strings.TrimSpace(f.Version) != VersionV1Alpha1 {
		return fmt.Errorf("unsupported exclude policy version %q", f.Version)
	}

	seenIDs := map[string]struct{}{}
	for index := range f.ShallowExcludes {
		if err := f.ShallowExcludes[index].validate(ruleContext{
			kind:    "shallowExcludes",
			index:   index,
			seenIDs: seenIDs,
		}); err != nil {
			return err
		}
	}
	for index := range f.SubgraphExcludes {
		if err := f.SubgraphExcludes[index].validate(ruleContext{
			kind:             "subgraphExcludes",
			index:            index,
			allowUnsupported: true,
			seenIDs:          seenIDs,
		}); err != nil {
			return err
		}
	}

	return nil
}

func MergeLegacyPatterns(doc File, patterns []string) File {
	normalized := normalizeStrings(patterns)
	if len(normalized) == 0 {
		return doc
	}
	doc.ShallowExcludes = append(doc.ShallowExcludes, Rule{
		ID:     legacyExcludePatternsRuleID,
		Reason: "synthesized from -exclude-patterns",
		Match: Selector{
			NameGlobs: legacyPatternGlobs(normalized),
		},
	})
	return doc
}

func legacyPatternGlobs(patterns []string) []string {
	result := make([]string, 0, len(patterns))
	for _, pattern := range patterns {
		result = append(result, "*"+pattern+"*")
	}
	return result
}

type ruleContext struct {
	kind             string
	index            int
	allowUnsupported bool
	seenIDs          map[string]struct{}
}

func (r *Rule) validate(ctx ruleContext) error {
	prefix := fmt.Sprintf("%s[%d]", ctx.kind, ctx.index)

	r.ID = strings.TrimSpace(r.ID)
	if r.ID != "" {
		if _, ok := ctx.seenIDs[r.ID]; ok {
			return fmt.Errorf("%s.id %q is duplicated", prefix, r.ID)
		}
		ctx.seenIDs[r.ID] = struct{}{}
	}
	r.Reason = strings.TrimSpace(r.Reason)
	if err := r.Match.validate(prefix + ".match"); err != nil {
		return err
	}

	r.OnUnsupported = strings.TrimSpace(strings.ToLower(r.OnUnsupported))
	if ctx.allowUnsupported {
		if r.OnUnsupported == "" {
			return nil
		}
		if !slices.Contains([]string{OnUnsupportedWarn, OnUnsupportedError, OnUnsupportedIgnore}, r.OnUnsupported) {
			return fmt.Errorf("%s.onUnsupported must be one of warn, error, ignore", prefix)
		}
		return nil
	}
	if r.OnUnsupported != "" {
		return fmt.Errorf("%s.onUnsupported is only supported for subgraphExcludes", prefix)
	}
	return nil
}

func (s *Selector) validate(prefix string) error {
	s.Ecosystems = normalizeStrings(s.Ecosystems)
	s.Names = normalizeStrings(s.Names)
	s.NameGlobs = normalizeStrings(s.NameGlobs)
	s.Versions = normalizeStrings(s.Versions)
	s.Projects = normalizeStrings(s.Projects)
	s.DependencyTypes = normalizeStrings(s.DependencyTypes)
	s.PURLs = normalizeStrings(s.PURLs)

	if len(s.Ecosystems) == 0 &&
		len(s.Names) == 0 &&
		len(s.NameGlobs) == 0 &&
		len(s.Versions) == 0 &&
		len(s.Projects) == 0 &&
		len(s.DependencyTypes) == 0 &&
		s.HasRuntimeAssets == nil &&
		len(s.PURLs) == 0 {
		return fmt.Errorf("%s must define at least one selector field", prefix)
	}

	for _, glob := range s.NameGlobs {
		if _, err := path.Match(glob, "sample"); err != nil {
			return fmt.Errorf("%s.nameGlobs contains invalid glob %q: %w", prefix, glob, err)
		}
	}
	return nil
}

func ValidateSelector(selector Selector) (Selector, error) {
	if err := selector.validate("match"); err != nil {
		return Selector{}, err
	}
	return selector, nil
}

func normalizeStrings(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	result := make([]string, 0, len(values))
	for _, value := range values {
		trimmed := strings.TrimSpace(value)
		if trimmed == "" {
			continue
		}
		result = append(result, trimmed)
	}
	return result
}
