package scan

import "depaudit-license/internal/inventory"

func ToInventory(packages []Package) []inventory.Package {
	result := make([]inventory.Package, 0, len(packages))
	for _, pkg := range packages {
		result = append(result, inventory.Package{
			Ecosystem:           pkg.Ecosystem,
			Project:             pkg.Project,
			Name:                pkg.Name,
			Version:             pkg.Version,
			PURL:                pkg.PURL,
			DependencyType:      pkg.DependencyType,
			HasRuntimeAssets:    pkg.HasRuntimeAssets,
			RawLicense:          pkg.RawLicense,
			LicenseKey:          pkg.LicenseKey,
			Repository:          pkg.Repository,
			Homepage:            pkg.Homepage,
			CopyrightHolder:     pkg.CopyrightHolder,
			CopyrightYear:       pkg.CopyrightYear,
			MetadataSource:      pkg.MetadataSource,
			EmbeddedLicensePath: pkg.EmbeddedLicensePath,
			EmbeddedLicenseText: pkg.EmbeddedLicenseText,
		})
	}
	return result
}
