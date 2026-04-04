package scan

import "testing"

func TestToInventoryCopiesScannerPackages(t *testing.T) {
	t.Parallel()

	source := []Package{
		{
			Ecosystem:           "node",
			Project:             "web",
			Name:                "react",
			Version:             "18.3.0",
			DependencyType:      "dependency",
			HasRuntimeAssets:    true,
			RawLicense:          "MIT",
			LicenseKey:          "MIT",
			Repository:          "https://example.test/repo",
			Homepage:            "https://example.test",
			CopyrightHolder:     "Example",
			CopyrightYear:       2024,
			MetadataSource:      "npm-registry",
			EmbeddedLicensePath: "LICENSE",
			EmbeddedLicenseText: "body",
		},
	}

	got := ToInventory(source)
	if len(got) != 1 {
		t.Fatalf("expected 1 package, got %d", len(got))
	}
	if got[0].Name != source[0].Name || got[0].EmbeddedLicenseText != source[0].EmbeddedLicenseText {
		t.Fatalf("unexpected conversion result: %#v", got[0])
	}
	if got[0].DependencyType != "dependency" || !got[0].HasRuntimeAssets {
		t.Fatalf("unexpected dependency metadata: %#v", got[0])
	}
}

func TestToInventoryHandlesEmptyInputAndCopiesValues(t *testing.T) {
	t.Parallel()

	if got := ToInventory(nil); len(got) != 0 {
		t.Fatalf("expected empty inventory, got %#v", got)
	}

	source := []Package{{Name: "pkg", Version: "1.0.0", Repository: "https://example.test/repo"}}
	got := ToInventory(source)
	source[0].Name = "changed"
	source[0].Repository = ""

	if got[0].Name != "pkg" {
		t.Fatalf("unexpected copied name = %q", got[0].Name)
	}
	if got[0].Repository != "https://example.test/repo" {
		t.Fatalf("unexpected copied repository = %q", got[0].Repository)
	}
}
