package catalog

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
)

type Definition struct {
	Key                  string   `json:"key"`
	Name                 string   `json:"name"`
	Family               string   `json:"family"`
	Version              string   `json:"version"`
	CopyleftStrength     string   `json:"copyleft_strength"`
	RequiresManualReview bool     `json:"requires_manual_review"`
	SPDXIDs              []string `json:"spdx_ids"`
	Names                []string `json:"names"`
	ExactURLs            []string `json:"exact_urls"`
	URLPrefixes          []string `json:"url_prefixes"`
	Contains             []string `json:"contains"`
	TextMatchers         []string `json:"text_matchers"`
	TextMatchThreshold   int      `json:"text_match_threshold,omitempty"`
	RequiredPhrases      []string `json:"required_phrases"`
	Description          string   `json:"description"`
	Obligations          []string `json:"obligations"`
	Permissions          []string `json:"permissions"`
	Limitations          []string `json:"limitations"`
	Color                string   `json:"color"`
	RiskLevel            string   `json:"risk_level"`
	NoticeTemplate       string   `json:"notice_template"`
}

type fileFormat struct {
	Fallback string       `json:"fallback"`
	Licenses []Definition `json:"licenses"`
}

type Catalog struct {
	Fallback    string
	Definitions map[string]Definition
	exact       map[string]string
	contains    []aliasMatch
	text        []textMatch
}

type aliasMatch struct {
	alias string
	key   string
}

type textMatch struct {
	key         string
	required    []string
	phrases     []string
	threshold   int
	specificity int
}

func Load(path string) (*Catalog, error) {
	return LoadPaths(path)
}

func LoadPaths(paths ...string) (*Catalog, error) {
	result, err := LoadSources(nil, paths...)
	if err != nil {
		return nil, err
	}
	return result.Catalog, nil
}

func LoadSources(client *http.Client, sources ...string) (*LoadResult, error) {
	return LoadSourcesWithOptions(LoadOptions{Client: client}, sources...)
}

func LoadSourcesWithOptions(options LoadOptions, sources ...string) (*LoadResult, error) {
	if len(sources) == 0 {
		return nil, fmt.Errorf("license catalog path list is empty")
	}
	options = normalizeLoadOptions(options)
	if err := validateLoadOptions(options); err != nil {
		return nil, err
	}

	merged, metadata, err := mergeCatalogFiles(options, sources)
	if err != nil {
		return nil, err
	}

	cat, err := newCatalog(merged)
	if err != nil {
		return nil, err
	}
	return buildLoadResult(cat, merged, metadata), nil
}

func mergeCatalogFiles(options LoadOptions, sources []string) (fileFormat, []SourceMetadata, error) {
	var merged fileFormat
	merged.Licenses = []Definition{}
	indexByKey := map[string]int{}
	metadata := make([]SourceMetadata, 0, len(sources))

	for _, source := range sources {
		file, sourceName, sourceMetadata, err := loadFileFormatFromSource(options, source)
		if err != nil {
			return fileFormat{}, nil, err
		}
		seenInFile := map[string]struct{}{}
		metadata = append(metadata, sourceMetadata)

		if strings.TrimSpace(file.Fallback) != "" {
			merged.Fallback = file.Fallback
		}

		for _, def := range file.Licenses {
			if _, exists := seenInFile[def.Key]; exists {
				return fileFormat{}, nil, fmt.Errorf("duplicate license definition key %q in %s", def.Key, sourceName)
			}
			seenInFile[def.Key] = struct{}{}

			if idx, ok := indexByKey[def.Key]; ok {
				merged.Licenses[idx] = def
				continue
			}
			indexByKey[def.Key] = len(merged.Licenses)
			merged.Licenses = append(merged.Licenses, def)
		}
	}

	return merged, metadata, nil
}

func loadFileFormat(path string) (fileFormat, error) {
	file, _, _, err := loadFileFormatFromSource(LoadOptions{}, path)
	return file, err
}

func loadFileFormatFromSource(options LoadOptions, source string) (fileFormat, string, SourceMetadata, error) {
	payload, sourceName, sourceMetadata, err := loadCatalogPayload(options, source)
	if err != nil {
		return fileFormat{}, "", SourceMetadata{}, err
	}

	var file fileFormat
	if err := json.Unmarshal(payload, &file); err != nil {
		return fileFormat{}, "", SourceMetadata{}, fmt.Errorf("parse catalog JSON %s: %w", sourceName, err)
	}

	if len(file.Licenses) == 0 {
		return fileFormat{}, "", SourceMetadata{}, fmt.Errorf("license catalog %s is empty", sourceName)
	}

	return file, sourceName, sourceMetadata, nil
}

func loadCatalogPayload(options LoadOptions, source string) ([]byte, string, SourceMetadata, error) {
	if isRemoteSource(source) {
		return fetchRemoteCatalog(options, source)
	}

	payload, err := os.ReadFile(source)
	if err != nil {
		return nil, "", SourceMetadata{}, fmt.Errorf("read catalog %s: %w", filepath.Base(source), err)
	}
	return payload, filepath.Base(source), localSourceMetadata(source, sha256Hex(payload)), nil
}

func fetchRemoteCatalog(options LoadOptions, source string) ([]byte, string, SourceMetadata, error) {
	httpClient := options.Client
	if httpClient == nil {
		httpClient = http.DefaultClient
	}

	spec, err := parseSourceSpec(source)
	if err != nil {
		return nil, "", SourceMetadata{}, err
	}

	payload, metadata, err := fetchRemoteCatalogFromNetwork(httpClient, spec, source)
	if err == nil {
		cacheDir := firstNonEmptyString(options.CacheDir, defaultRemoteCatalogCacheDir())
		if writeErr := writeRemoteCatalogCache(cacheDir, metadata, payload); writeErr != nil && options.RemoteCatalogMode == RemoteCatalogModeFailFast {
			return nil, "", SourceMetadata{}, fmt.Errorf("write remote catalog cache %s: %w", source, writeErr)
		}
		return payload, source, metadata, nil
	}

	if options.RemoteCatalogMode != RemoteCatalogModeStaleFallback {
		return nil, "", SourceMetadata{}, err
	}

	cachedPayload, cachedMetadata, cacheErr := readRemoteCatalogCache(firstNonEmptyString(options.CacheDir, defaultRemoteCatalogCacheDir()), spec)
	if cacheErr != nil {
		return nil, "", SourceMetadata{}, err
	}
	return cachedPayload, source, cachedMetadata, nil
}

func fetchRemoteCatalogFromNetwork(client *http.Client, spec sourceSpec, source string) ([]byte, SourceMetadata, error) {
	req, err := http.NewRequest(http.MethodGet, spec.RequestURL, nil)
	if err != nil {
		return nil, SourceMetadata{}, fmt.Errorf("build catalog request %s: %w", source, err)
	}
	req.Header.Set("User-Agent", "depaudit-license")
	req.Header.Set("Accept", "application/json, text/plain;q=0.9, */*;q=0.1")

	resp, err := client.Do(req)
	if err != nil {
		return nil, SourceMetadata{}, fmt.Errorf("fetch catalog %s: %w", source, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, SourceMetadata{}, fmt.Errorf("fetch catalog %s: unexpected status %d", source, resp.StatusCode)
	}
	if err := validateRemoteContentType(resp.Header.Get("Content-Type")); err != nil {
		return nil, SourceMetadata{}, fmt.Errorf("fetch catalog %s: %w", source, err)
	}

	payload, err := io.ReadAll(io.LimitReader(resp.Body, 10<<20))
	if err != nil {
		return nil, SourceMetadata{}, fmt.Errorf("read catalog %s: %w", source, err)
	}
	actualHash := sha256Hex(payload)
	if err := verifyRequestedSHA256(spec.RequestedSHA256, actualHash, source); err != nil {
		return nil, SourceMetadata{}, err
	}
	metadata := remoteSourceMetadata(spec, actualHash, resp.Header.Get("ETag"), firstNonEmptyString(resp.Header.Get("X-Revision"), resp.Header.Get("Last-Modified")))
	return payload, metadata, nil
}

func isRemoteSource(source string) bool {
	parsed, err := url.Parse(strings.TrimSpace(source))
	if err != nil {
		return false
	}
	switch strings.ToLower(parsed.Scheme) {
	case "http", "https":
		return parsed.Host != ""
	default:
		return false
	}
}

func validateRemoteContentType(raw string) error {
	value := strings.ToLower(strings.TrimSpace(strings.Split(raw, ";")[0]))
	switch value {
	case "", "application/json", "text/json", "text/plain", "application/octet-stream":
		return nil
	case "text/html":
		return fmt.Errorf("unexpected content type %q", raw)
	default:
		return nil
	}
}

func newCatalog(file fileFormat) (*Catalog, error) {
	cat := &Catalog{
		Fallback:    file.Fallback,
		Definitions: make(map[string]Definition, len(file.Licenses)),
		exact:       map[string]string{},
	}

	for _, def := range file.Licenses {
		if err := validateDefinition(def); err != nil {
			return nil, err
		}
		if _, exists := cat.Definitions[def.Key]; exists {
			return nil, fmt.Errorf("duplicate license definition key %q", def.Key)
		}

		cat.Definitions[def.Key] = def
		cat.registerExact(def.Key, def.Key)
		cat.registerExact(def.Name, def.Key)

		for _, id := range def.SPDXIDs {
			cat.registerExact(id, def.Key)
		}
		for _, name := range def.Names {
			cat.registerExact(name, def.Key)
		}
		for _, exactURL := range def.ExactURLs {
			cat.registerExact(exactURL, def.Key)
		}
		for _, prefix := range def.URLPrefixes {
			cat.registerContains(prefix, def.Key)
		}
		for _, contains := range def.Contains {
			cat.registerContains(contains, def.Key)
		}
		cat.registerTextMatchers(def)
	}

	if strings.TrimSpace(cat.Fallback) == "" {
		return nil, fmt.Errorf("license catalog fallback is empty")
	}

	if _, ok := cat.Definitions[cat.Fallback]; !ok {
		return nil, fmt.Errorf("fallback license %q is not defined in catalog", cat.Fallback)
	}

	slices.SortFunc(cat.contains, func(a, b aliasMatch) int {
		return len(b.alias) - len(a.alias)
	})
	slices.SortFunc(cat.text, func(a, b textMatch) int {
		return b.specificity - a.specificity
	})

	return cat, nil
}

func (c *Catalog) Normalize(raw string) (string, Definition) {
	candidates := normalizationCandidates(raw)
	if len(candidates) == 0 {
		return c.Fallback, c.Definitions[c.Fallback]
	}

	for _, candidate := range candidates {
		if key, ok := c.exact[candidate]; ok {
			return key, c.Definitions[key]
		}
	}

	for _, normalized := range candidates {
		for _, candidate := range c.contains {
			if strings.Contains(normalized, candidate.alias) {
				return candidate.key, c.Definitions[candidate.key]
			}
		}
	}

	return c.Fallback, c.Definitions[c.Fallback]
}

func (c *Catalog) NormalizeText(raw string) (string, Definition) {
	normalized := normalizeLicenseText(raw)
	if normalized == "" {
		return c.Fallback, c.Definitions[c.Fallback]
	}

	var best textMatch
	found := false
	bestScore := -1
	for _, candidate := range c.text {
		if !requiredPhrasesMatch(normalized, candidate.required) {
			continue
		}
		score := phraseMatchScore(normalized, candidate.phrases)
		if score < candidate.threshold {
			continue
		}
		if !found || score > bestScore || (score == bestScore && candidate.specificity > best.specificity) {
			best = candidate
			found = true
			bestScore = score
		}
	}

	if found {
		return best.key, c.Definitions[best.key]
	}
	return c.Fallback, c.Definitions[c.Fallback]
}

func (c *Catalog) Lookup(key string) Definition {
	if def, ok := c.Definitions[key]; ok {
		return def
	}
	return c.Definitions[c.Fallback]
}

func (c *Catalog) registerExact(value string, key string) {
	normalized := normalizeText(value)
	if normalized == "" {
		return
	}

	c.exact[normalized] = key
}

func (c *Catalog) registerContains(value string, key string) {
	normalized := normalizeText(value)
	if normalized == "" {
		return
	}

	if len(normalized) >= 4 {
		c.contains = append(c.contains, aliasMatch{alias: normalized, key: key})
	}
}

func (c *Catalog) registerTextMatchers(def Definition) {
	if def.Key == c.Fallback {
		return
	}

	if len(def.TextMatchers) > 0 || len(def.RequiredPhrases) > 0 {
		c.registerTextMatch(def.Key, def.RequiredPhrases, def.TextMatchers, def.TextMatchThreshold)
	}

	for _, value := range noticeTemplateTextMatchers(def.NoticeTemplate) {
		c.registerTextMatch(def.Key, nil, []string{value}, 1)
	}
}

func (c *Catalog) registerTextMatch(key string, required []string, phrases []string, threshold int) {
	match := textMatch{
		key:       key,
		required:  normalizeTextPhrases(required),
		phrases:   normalizeTextPhrases(phrases),
		threshold: threshold,
	}
	if len(match.phrases) == 0 && len(match.required) == 0 {
		return
	}
	if len(match.phrases) == 0 {
		match.threshold = 0
	} else if match.threshold <= 0 {
		match.threshold = len(match.phrases)
	} else if match.threshold > len(match.phrases) {
		match.threshold = len(match.phrases)
	}
	match.specificity = textMatchSpecificity(match)
	c.text = append(c.text, match)
}

func normalizeTextPhrases(values []string) []string {
	result := make([]string, 0, len(values))
	seen := map[string]struct{}{}
	for _, value := range values {
		normalized := normalizeLicenseText(value)
		if len(normalized) < 8 {
			continue
		}
		if _, ok := seen[normalized]; ok {
			continue
		}
		seen[normalized] = struct{}{}
		result = append(result, normalized)
	}
	return result
}

func requiredPhrasesMatch(normalized string, phrases []string) bool {
	for _, phrase := range phrases {
		if !strings.Contains(normalized, phrase) {
			return false
		}
	}
	return true
}

func phraseMatchScore(normalized string, phrases []string) int {
	score := 0
	for _, phrase := range phrases {
		if strings.Contains(normalized, phrase) {
			score++
		}
	}
	return score
}

func textMatchSpecificity(match textMatch) int {
	total := 0
	for _, phrase := range match.required {
		total += len(phrase)
	}
	for _, phrase := range match.phrases {
		total += len(phrase)
	}
	return total
}

func normalizeText(value string) string {
	value = strings.TrimSpace(strings.ToLower(value))
	value = strings.ReplaceAll(value, "_", "-")
	value = strings.ReplaceAll(value, "\"", "")
	value = strings.ReplaceAll(value, "'", "")
	return value
}

func normalizeLicenseText(value string) string {
	value = normalizeText(value)
	return strings.Join(strings.Fields(value), " ")
}

func noticeTemplateTextMatchers(value string) []string {
	var matchers []string
	for _, segment := range literalTemplateSegments(value) {
		normalized := normalizeLicenseText(segment)
		if len(normalized) < 16 {
			continue
		}
		if strings.HasPrefix(normalized, "covered software in this report") ||
			strings.HasPrefix(normalized, "packages:") ||
			strings.HasPrefix(normalized, "copyright holders:") {
			continue
		}
		matchers = append(matchers, normalized)
		if header, _, ok := strings.Cut(normalized, " copyright"); ok && len(header) >= 16 {
			matchers = append(matchers, header)
		}
		return matchers
	}
	return nil
}

func literalTemplateSegments(value string) []string {
	var segments []string
	remaining := value
	for {
		start := strings.Index(remaining, "{{")
		if start < 0 {
			segments = append(segments, remaining)
			break
		}
		segments = append(segments, remaining[:start])
		remaining = remaining[start+2:]
		end := strings.Index(remaining, "}}")
		if end < 0 {
			break
		}
		remaining = remaining[end+2:]
	}
	return segments
}

func normalizationCandidates(raw string) []string {
	value := strings.TrimSpace(raw)
	if value == "" {
		return nil
	}

	var candidates []string
	seen := map[string]struct{}{}
	add := func(input string) {
		normalized := normalizeText(input)
		if normalized == "" {
			return
		}
		if _, ok := seen[normalized]; ok {
			return
		}
		seen[normalized] = struct{}{}
		candidates = append(candidates, normalized)
	}

	add(value)

	trimmedParens := strings.Trim(strings.TrimSpace(value), "() ")
	if trimmedParens != value {
		add(trimmedParens)
	}

	if parsed, err := url.Parse(value); err == nil && parsed.Scheme != "" && parsed.Host != "" {
		withoutQuery := *parsed
		withoutQuery.RawQuery = ""
		withoutQuery.Fragment = ""
		add(withoutQuery.String())
	}

	normalizedRaw := normalizeText(value)
	if head, _, ok := strings.Cut(normalizedRaw, " with "); ok {
		add(head)
	}

	return candidates
}

func validateDefinition(def Definition) error {
	if strings.TrimSpace(def.Key) == "" {
		return fmt.Errorf("license definition key is empty")
	}
	if strings.TrimSpace(def.Name) == "" {
		return fmt.Errorf("license %q name is empty", def.Key)
	}
	if strings.TrimSpace(def.Family) == "" {
		return fmt.Errorf("license %q family is empty", def.Key)
	}
	if !isAllowedRiskLevel(def.RiskLevel) {
		return fmt.Errorf("license %q has invalid risk_level %q", def.Key, def.RiskLevel)
	}
	if !isAllowedCopyleftStrength(def.CopyleftStrength) {
		return fmt.Errorf("license %q has invalid copyleft_strength %q", def.Key, def.CopyleftStrength)
	}
	if !hasMatchers(def) {
		return fmt.Errorf("license %q does not define any matchers", def.Key)
	}
	if def.TextMatchThreshold < 0 {
		return fmt.Errorf("license %q has invalid text_match_threshold %d", def.Key, def.TextMatchThreshold)
	}
	if def.TextMatchThreshold > 0 && len(def.TextMatchers) == 0 {
		return fmt.Errorf("license %q text_match_threshold requires text_matchers", def.Key)
	}
	if def.TextMatchThreshold > len(def.TextMatchers) {
		return fmt.Errorf("license %q text_match_threshold exceeds text_matchers length", def.Key)
	}

	for _, exactURL := range def.ExactURLs {
		if err := validateAbsoluteURL(exactURL); err != nil {
			return fmt.Errorf("license %q exact_urls: %w", def.Key, err)
		}
	}
	for _, prefix := range def.URLPrefixes {
		if err := validateAbsoluteURL(prefix); err != nil {
			return fmt.Errorf("license %q url_prefixes: %w", def.Key, err)
		}
	}

	return nil
}

func hasMatchers(def Definition) bool {
	return len(def.SPDXIDs) > 0 ||
		len(def.Names) > 0 ||
		len(def.ExactURLs) > 0 ||
		len(def.URLPrefixes) > 0 ||
		len(def.Contains) > 0 ||
		len(def.TextMatchers) > 0 ||
		len(def.RequiredPhrases) > 0
}

func isAllowedRiskLevel(value string) bool {
	switch strings.TrimSpace(value) {
	case "low", "medium", "high", "unknown":
		return true
	default:
		return false
	}
}

func isAllowedCopyleftStrength(value string) bool {
	switch strings.TrimSpace(value) {
	case "none", "file", "library", "strong", "network", "custom", "unknown":
		return true
	default:
		return false
	}
}

func validateAbsoluteURL(raw string) error {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return fmt.Errorf("invalid url %q: %w", raw, err)
	}
	if parsed.Scheme == "" || parsed.Host == "" {
		return fmt.Errorf("invalid absolute url %q", raw)
	}
	return nil
}
