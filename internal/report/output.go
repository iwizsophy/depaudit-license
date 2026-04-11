package report

import (
	"encoding/json"
	"strings"

	"depaudit-license/internal/catalog"
	"depaudit-license/internal/externalaccess"
)

const JSONSchemaVersion = "1"

type Output struct {
	SchemaVersion string     `json:"schemaVersion"`
	Provenance    Provenance `json:"provenance"`
	Report        View       `json:"report"`
}

type Provenance struct {
	InputKind        string                   `json:"inputKind"`
	CatalogSources   []catalog.SourceMetadata `json:"catalogSources,omitempty"`
	ExternalSources  []externalaccess.Service `json:"externalSources,omitempty"`
	SelectedLocale   string                   `json:"selectedLocale,omitempty"`
	EffectiveCatalog json.RawMessage          `json:"effectiveCatalog,omitempty"`
}

type OutputConfig struct {
	InputKind        string
	CatalogSources   []catalog.SourceMetadata
	ExternalSources  []externalaccess.Service
	SelectedLocale   string
	EffectiveCatalog json.RawMessage
}

func BuildOutput(view View, cfg OutputConfig) Output {
	return Output{
		SchemaVersion: JSONSchemaVersion,
		Provenance: Provenance{
			InputKind:        firstNonEmpty(strings.TrimSpace(cfg.InputKind), "repository-scan"),
			CatalogSources:   displayCatalogSources(cfg.CatalogSources),
			ExternalSources:  externalaccess.Normalize(cfg.ExternalSources),
			SelectedLocale:   strings.TrimSpace(cfg.SelectedLocale),
			EffectiveCatalog: append(json.RawMessage(nil), cfg.EffectiveCatalog...),
		},
		Report: view,
	}
}

func displayCatalogSources(values []catalog.SourceMetadata) []catalog.SourceMetadata {
	if len(values) == 0 {
		return nil
	}
	result := make([]catalog.SourceMetadata, 0, len(values))
	for _, value := range values {
		cloned := value
		cloned.Location = firstNonEmpty(strings.TrimSpace(value.DisplayLocation), strings.TrimSpace(value.Location))
		result = append(result, cloned)
	}
	return result
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}
