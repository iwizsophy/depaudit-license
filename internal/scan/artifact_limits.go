package scan

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
)

const (
	DefaultMaxPackageArtifactBytes  = 256 << 20
	DefaultMaxPackageMetadataBytes  = 1 << 20
	DefaultMaxEmbeddedLicenseBytes  = 4 << 20
	DefaultMaxPackageArchiveEntries = 10000
)

type ArtifactReadLimits struct {
	MaxPackageArtifactBytes  int64
	MaxPackageMetadataBytes  int64
	MaxEmbeddedLicenseBytes  int64
	MaxPackageArchiveEntries int
}

type ArtifactSafetyError struct {
	PackageName string
	Version     string
	Source      string
	Reason      string
}

type artifactLimitExceededError struct {
	reason string
}

func (e *artifactLimitExceededError) Error() string {
	return e.reason
}

func (e *ArtifactSafetyError) Error() string {
	label := strings.TrimSpace(e.PackageName)
	if version := strings.TrimSpace(e.Version); version != "" {
		label += "@" + version
	}
	if label == "" {
		label = "package artifact"
	}
	if source := strings.TrimSpace(e.Source); source != "" {
		return fmt.Sprintf("%s failed artifact safety checks at %s: %s", label, source, e.Reason)
	}
	return fmt.Sprintf("%s failed artifact safety checks: %s", label, e.Reason)
}

func ValidateArtifactReadLimits(limits ArtifactReadLimits) error {
	switch {
	case limits.MaxPackageArtifactBytes <= 0:
		return fmt.Errorf("max package artifact bytes must be greater than zero")
	case limits.MaxPackageMetadataBytes <= 0:
		return fmt.Errorf("max package metadata bytes must be greater than zero")
	case limits.MaxEmbeddedLicenseBytes <= 0:
		return fmt.Errorf("max embedded license bytes must be greater than zero")
	case limits.MaxPackageArchiveEntries <= 0:
		return fmt.Errorf("max package archive entries must be greater than zero")
	default:
		return nil
	}
}

func NormalizeArtifactReadLimits(limits ArtifactReadLimits) ArtifactReadLimits {
	if limits.MaxPackageArtifactBytes <= 0 {
		limits.MaxPackageArtifactBytes = DefaultMaxPackageArtifactBytes
	}
	if limits.MaxPackageMetadataBytes <= 0 {
		limits.MaxPackageMetadataBytes = DefaultMaxPackageMetadataBytes
	}
	if limits.MaxEmbeddedLicenseBytes <= 0 {
		limits.MaxEmbeddedLicenseBytes = DefaultMaxEmbeddedLicenseBytes
	}
	if limits.MaxPackageArchiveEntries <= 0 {
		limits.MaxPackageArchiveEntries = DefaultMaxPackageArchiveEntries
	}
	return limits
}

func readFileLimited(path string, maxBytes int64) ([]byte, error) {
	handle, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer handle.Close()

	if info, err := handle.Stat(); err == nil && maxBytes > 0 && info.Size() > maxBytes {
		return nil, &artifactLimitExceededError{reason: fmt.Sprintf("file size %d bytes exceeds limit %d bytes", info.Size(), maxBytes)}
	}
	return readAllLimited(handle, maxBytes)
}

func readAllLimited(reader io.Reader, maxBytes int64) ([]byte, error) {
	if maxBytes <= 0 {
		return io.ReadAll(reader)
	}

	limited := io.LimitReader(reader, maxBytes+1)
	payload, err := io.ReadAll(limited)
	if err != nil {
		return nil, err
	}
	if int64(len(payload)) > maxBytes {
		return nil, &artifactLimitExceededError{reason: fmt.Sprintf("payload size exceeds limit %d bytes", maxBytes)}
	}
	return payload, nil
}

func wrapArtifactSafetyError(packageName string, version string, source string, subject string, err error) error {
	if err == nil {
		return nil
	}
	var limitErr *artifactLimitExceededError
	if !errors.As(err, &limitErr) {
		return nil
	}
	return &ArtifactSafetyError{
		PackageName: packageName,
		Version:     version,
		Source:      strings.TrimSpace(source),
		Reason:      fmt.Sprintf("%s: %v", strings.TrimSpace(subject), limitErr),
	}
}
