package enrich

import (
	"net/http"
	"slices"

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

func Apply(cfg Config, doc inventory.Document) (inventory.Document, error) {
	service := scan.NewMetadataLookupService(scan.MetadataLookupConfig{
		Client:                   cfg.Client,
		Catalog:                  cfg.Catalog,
		RepositoryRoots:          cfg.RepositoryRoots,
		NodeRegistryBaseURL:      cfg.NodeRegistryBaseURL,
		NuGetGlobalPackagesRoot:  cfg.NuGetGlobalPackagesRoot,
		NuGetRegistrationBaseURL: cfg.NuGetRegistrationBaseURL,
	})

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
		Sources:   append([]inventory.Source(nil), doc.Sources...),
		Packages:  clonePackages(doc.Packages),
		Conflicts: cloneConflicts(doc.Conflicts),
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

func hasSource(sources []inventory.Source, id string) bool {
	for _, source := range sources {
		if source.ID == id {
			return true
		}
	}
	return false
}
