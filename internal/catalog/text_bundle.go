package catalog

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

type TextBundle struct {
	Locale   string                   `json:"locale"`
	Licenses []LocalizedText          `json:"licenses"`
	ByKey    map[string]LocalizedText `json:"-"`
}

type LocalizedText struct {
	Key         string   `json:"key"`
	Description string   `json:"description"`
	Obligations []string `json:"obligations"`
	Permissions []string `json:"permissions"`
	Limitations []string `json:"limitations"`
}

func LoadTextBundle(path string) (*TextBundle, error) {
	payload, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read text bundle %s: %w", filepath.Base(path), err)
	}

	var bundle TextBundle
	if err := json.Unmarshal(payload, &bundle); err != nil {
		return nil, fmt.Errorf("parse text bundle JSON %s: %w", filepath.Base(path), err)
	}
	if strings.TrimSpace(bundle.Locale) == "" {
		return nil, fmt.Errorf("text bundle %s locale is empty", filepath.Base(path))
	}
	if len(bundle.Licenses) == 0 {
		return nil, fmt.Errorf("text bundle %s is empty", filepath.Base(path))
	}

	bundle.ByKey = make(map[string]LocalizedText, len(bundle.Licenses))
	for _, item := range bundle.Licenses {
		if err := validateLocalizedText(item); err != nil {
			return nil, err
		}
		if _, exists := bundle.ByKey[item.Key]; exists {
			return nil, fmt.Errorf("duplicate localized text key %q", item.Key)
		}
		bundle.ByKey[item.Key] = item
	}

	return &bundle, nil
}

func ApplyTextBundle(cat *Catalog, bundle *TextBundle) (*Catalog, error) {
	if cat == nil {
		return nil, fmt.Errorf("catalog is nil")
	}
	if bundle == nil {
		return nil, fmt.Errorf("text bundle is nil")
	}

	missing := make([]string, 0)
	for key := range cat.Definitions {
		if _, ok := bundle.ByKey[key]; !ok {
			missing = append(missing, key)
		}
	}
	extra := make([]string, 0)
	for key := range bundle.ByKey {
		if _, ok := cat.Definitions[key]; !ok {
			extra = append(extra, key)
		}
	}
	sort.Strings(missing)
	sort.Strings(extra)
	if len(missing) > 0 {
		return nil, fmt.Errorf("text bundle locale %q is missing keys: %s", bundle.Locale, strings.Join(missing, ", "))
	}
	if len(extra) > 0 {
		return nil, fmt.Errorf("text bundle locale %q defines unknown keys: %s", bundle.Locale, strings.Join(extra, ", "))
	}

	clone := &Catalog{
		Fallback:    cat.Fallback,
		Definitions: make(map[string]Definition, len(cat.Definitions)),
		exact:       mapsClone(cat.exact),
		contains:    append([]aliasMatch(nil), cat.contains...),
	}
	for key, def := range cat.Definitions {
		text := bundle.ByKey[key]
		def.Description = text.Description
		def.Obligations = append([]string(nil), text.Obligations...)
		def.Permissions = append([]string(nil), text.Permissions...)
		def.Limitations = append([]string(nil), text.Limitations...)
		clone.Definitions[key] = def
	}
	return clone, nil
}

func mapsClone(source map[string]string) map[string]string {
	if source == nil {
		return nil
	}
	clone := make(map[string]string, len(source))
	for key, value := range source {
		clone[key] = value
	}
	return clone
}

func validateLocalizedText(item LocalizedText) error {
	if strings.TrimSpace(item.Key) == "" {
		return fmt.Errorf("localized text key is empty")
	}
	if strings.TrimSpace(item.Description) == "" {
		return fmt.Errorf("localized text %q description is empty", item.Key)
	}
	if len(item.Obligations) == 0 {
		return fmt.Errorf("localized text %q obligations are empty", item.Key)
	}
	if len(item.Permissions) == 0 {
		return fmt.Errorf("localized text %q permissions are empty", item.Key)
	}
	if len(item.Limitations) == 0 {
		return fmt.Errorf("localized text %q limitations are empty", item.Key)
	}
	return nil
}
