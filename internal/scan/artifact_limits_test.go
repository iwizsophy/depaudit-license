package scan

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestValidateArtifactReadLimitsAndNormalizeDefaults(t *testing.T) {
	t.Parallel()

	if err := ValidateArtifactReadLimits(ArtifactReadLimits{
		MaxPackageArtifactBytes:  1,
		MaxPackageMetadataBytes:  1,
		MaxEmbeddedLicenseBytes:  1,
		MaxPackageArchiveEntries: 1,
	}); err != nil {
		t.Fatalf("ValidateArtifactReadLimits: %v", err)
	}
	if err := ValidateArtifactReadLimits(ArtifactReadLimits{}); err == nil {
		t.Fatal("expected validation error for zero values")
	}

	got := NormalizeArtifactReadLimits(ArtifactReadLimits{})
	if got.MaxPackageArtifactBytes != DefaultMaxPackageArtifactBytes ||
		got.MaxPackageMetadataBytes != DefaultMaxPackageMetadataBytes ||
		got.MaxEmbeddedLicenseBytes != DefaultMaxEmbeddedLicenseBytes ||
		got.MaxPackageArchiveEntries != DefaultMaxPackageArchiveEntries {
		t.Fatalf("normalized defaults = %#v", got)
	}
}

func TestArtifactSafetyErrorFormattingAndWrap(t *testing.T) {
	t.Parallel()

	err := wrapArtifactSafetyError("Sample.Package", "1.2.3", "pkg.nupkg", "NuGet package artifact", &artifactLimitExceededError{reason: "payload size exceeds limit 16 bytes"})
	var safetyErr *ArtifactSafetyError
	if !errors.As(err, &safetyErr) {
		t.Fatalf("expected ArtifactSafetyError, got %T", err)
	}
	if got := safetyErr.Error(); !strings.Contains(got, "Sample.Package@1.2.3") || !strings.Contains(got, "pkg.nupkg") {
		t.Fatalf("error string = %q", got)
	}

	if err := wrapArtifactSafetyError("", "", "", "subject", errors.New("ordinary error")); err != nil {
		t.Fatalf("expected non-limit error to stay nil, got %v", err)
	}
	if got := (&ArtifactSafetyError{Reason: "payload size exceeds limit 16 bytes"}).Error(); !strings.Contains(got, "package artifact") {
		t.Fatalf("default error string = %q", got)
	}
}

func TestReadAllLimitedAndReadFileLimited(t *testing.T) {
	t.Parallel()

	payload, err := readAllLimited(strings.NewReader("abcd"), 4)
	if err != nil || string(payload) != "abcd" {
		t.Fatalf("readAllLimited = %q %v", string(payload), err)
	}
	if _, err := readAllLimited(strings.NewReader("abcde"), 4); err == nil {
		t.Fatal("expected readAllLimited to reject oversized payload")
	}

	dir := t.TempDir()
	path := filepath.Join(dir, "payload.txt")
	if err := os.WriteFile(path, []byte("abcd"), 0o644); err != nil {
		t.Fatalf("write payload: %v", err)
	}
	payload, err = readFileLimited(path, 4)
	if err != nil || string(payload) != "abcd" {
		t.Fatalf("readFileLimited = %q %v", string(payload), err)
	}
	if _, err := readFileLimited(path, 3); err == nil {
		t.Fatal("expected readFileLimited to reject oversized file")
	}
}
