package enrich

import (
	"fmt"
	"net/http"
	"slices"
	"strings"

	"depaudit-license/internal/catalog"
	"depaudit-license/internal/inventory"
	"depaudit-license/internal/scan"
)

type Config struct {
	Client                   *http.Client
	Catalog                  *catalog.Catalog
	RepositoryRoots          []string
	NodeRegistryBaseURL      string
	NuGetGlobalPackagesRoot  string
	NuGetRegistrationBaseURL string
}

func ApplyLocal(cfg Config, doc inventory.Document) (inventory.Document, error) {
	return applyWithMode(cfg, doc, scan.MetadataLookupModeLocal)
}

func ApplyRemote(cfg Config, doc inventory.Document) (inventory.Document, error) {
	return applyWithMode(cfg, doc, scan.MetadataLookupModeRemote)
}

func applyWithMode(cfg Config, doc inventory.Document, mode string) (inventory.Document, error) {
	service, err := scan.NewMetadataLookupService(scan.MetadataLookupConfig{
		Client:                   cfg.Client,
		Catalog:                  cfg.Catalog,
		RepositoryRoots:          cfg.RepositoryRoots,
		NodeRegistryBaseURL:      cfg.NodeRegistryBaseURL,
		NuGetGlobalPackagesRoot:  cfg.NuGetGlobalPackagesRoot,
		NuGetRegistrationBaseURL: cfg.NuGetRegistrationBaseURL,
		Mode:                     mode,
	})
	if err != nil {
		return inventory.Document{}, err
	}

	result := cloneDocument(doc)

	for index, pkg := range result.Packages {
		enriched, source, changed := service.EnrichPackage(pkg)
		if !changed {
			continue
		}
		result.Packages[index] = enriched
		if source != nil && !hasSource(result.Sources, source.ID) {
			result.Sources = append(result.Sources, *source)
		}
		if diagnostic, ok := remoteResolutionFallbackDiagnostic(enriched, source); ok {
			result.Diagnostics = append(result.Diagnostics, diagnostic)
		}
	}

	slices.SortFunc(result.Sources, func(a inventory.Source, b inventory.Source) int {
		switch {
		case a.ID < b.ID:
			return -1
		case a.ID > b.ID:
			return 1
		default:
			return 0
		}
	})
	return result, nil
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
		if pkg.Provenance.ArtifactResolution != nil {
			resolution := *pkg.Provenance.ArtifactResolution
			cloned[index].Provenance.ArtifactResolution = &resolution
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

func hasSource(sources []inventory.Source, id string) bool {
	for _, source := range sources {
		if source.ID == id {
			return true
		}
	}
	return false
}

func remoteResolutionFallbackDiagnostic(pkg inventory.Package, source *inventory.Source) (inventory.Diagnostic, bool) {
	if pkg.Provenance.ArtifactResolution == nil || !pkg.Provenance.ArtifactResolution.ReviewRequired {
		return inventory.Diagnostic{}, false
	}

	sourceID := ""
	if source != nil {
		sourceID = strings.TrimSpace(source.ID)
	}
	packageName := strings.TrimSpace(pkg.Name)
	if version := strings.TrimSpace(pkg.Version); version != "" {
		packageName += "@" + version
	}

	return inventory.Diagnostic{
		SourceID:  sourceID,
		Code:      "remote_resolution_fallback_used",
		Severity:  "warning",
		Message:   fmt.Sprintf("%s used remote resolution fallback (%s); manual review required", packageName, strings.TrimSpace(pkg.Provenance.ArtifactResolution.ReviewReason)),
		Ecosystem: strings.TrimSpace(pkg.Ecosystem),
		Project:   strings.TrimSpace(pkg.Project),
	}, true
}
