package input

import (
	"fmt"
	"net/http"
	"path/filepath"
	"strings"

	"depaudit-license/internal/catalog"
	"depaudit-license/internal/inventory"
	"depaudit-license/internal/merge"
	"depaudit-license/internal/policy"
	"depaudit-license/internal/sbom"
	"depaudit-license/internal/scan"
)

const (
	InputKindRepositoryScan = "repository-scan"
	InputKindCycloneDXJSON  = "cyclonedx-json"
	InputKindSPDXJSON       = "spdx-json"
	InputKindMultiSource    = "multi-source"
)

type SourceSpec struct {
	ID              string
	Kind            string
	Location        string
	DisplayLocation string
}

type LoadConfig struct {
	Sources       []SourceSpec
	Client        *http.Client
	Catalog       *catalog.Catalog
	SubgraphRules []policy.Rule
}

type Result struct {
	InputKind string
	Root      string
	Document  inventory.Document
}

func Load(cfg LoadConfig) (Result, error) {
	if len(cfg.Sources) == 0 {
		return Result{}, fmt.Errorf("input source list is empty")
	}

	documents := make([]inventory.Document, 0, len(cfg.Sources))
	displayLocations := make([]string, 0, len(cfg.Sources))
	for index, source := range cfg.Sources {
		document, displayLocation, err := loadSource(cfg, source, index)
		if err != nil {
			return Result{}, err
		}
		documents = append(documents, document)
		displayLocations = append(displayLocations, displayLocation)
	}

	merged := merge.Documents(merge.Config{}, documents...)
	if err := merge.ValidateDocument(merged); err != nil {
		return Result{}, err
	}

	inputKind := InputKindMultiSource
	if len(cfg.Sources) == 1 {
		inputKind = strings.TrimSpace(cfg.Sources[0].Kind)
	}
	return Result{
		InputKind: inputKind,
		Root:      strings.Join(displayLocations, " + "),
		Document:  merged,
	}, nil
}

func loadSource(cfg LoadConfig, source SourceSpec, index int) (inventory.Document, string, error) {
	id := strings.TrimSpace(source.ID)
	if id == "" {
		id = fmt.Sprintf("%s-%d", strings.TrimSpace(source.Kind), index+1)
	}
	switch strings.TrimSpace(source.Kind) {
	case InputKindRepositoryScan:
		scanResult, err := scan.CollectResult(scan.Config{
			Root: source.Location,
		})
		if err != nil {
			return inventory.Document{}, "", err
		}
		scanResult, err = scan.ApplySubgraphExcludes(scan.SubgraphExcludeConfig{
			Root:     source.Location,
			SourceID: id,
			Rules:    cfg.SubgraphRules,
		}, scanResult)
		if err != nil {
			return inventory.Document{}, "", err
		}
		return merge.SingleSourceDocument(
			merge.NewSource(id, InputKindRepositoryScan, source.Location, sourceDisplayLocation(source)),
			scan.ToInventory(scanResult.Packages),
			scanResult.Diagnostics...,
		), sourceDisplayLocation(source), nil
	case InputKindCycloneDXJSON:
		packages, err := sbom.LoadCycloneDXJSON(source.Location, cfg.Catalog)
		if err != nil {
			return inventory.Document{}, "", err
		}
		return merge.SingleSourceDocument(
			merge.NewSource(id, InputKindCycloneDXJSON, filepath.Clean(source.Location), sourceDisplayLocation(source)),
			packages,
		), sourceDisplayLocation(source), nil
	case InputKindSPDXJSON:
		packages, err := sbom.LoadSPDXJSON(source.Location, cfg.Catalog)
		if err != nil {
			return inventory.Document{}, "", err
		}
		return merge.SingleSourceDocument(
			merge.NewSource(id, InputKindSPDXJSON, filepath.Clean(source.Location), sourceDisplayLocation(source)),
			packages,
		), sourceDisplayLocation(source), nil
	default:
		return inventory.Document{}, "", fmt.Errorf("unsupported input kind %q", source.Kind)
	}
}

func sourceDisplayLocation(source SourceSpec) string {
	if strings.TrimSpace(source.DisplayLocation) != "" {
		return strings.TrimSpace(source.DisplayLocation)
	}
	return strings.TrimSpace(source.Location)
}
