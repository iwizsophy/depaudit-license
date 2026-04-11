package scan

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	"depaudit-license/internal/externalaccess"
	"depaudit-license/internal/httpcache"
	"depaudit-license/internal/inventory"
)

type nugetResolver struct {
	client              *http.Client
	cache               map[string]metadata
	globalPackagesRoot  string
	registrationBaseURL string
	artifactReadLimits  ArtifactReadLimits
}

type nugetCatalogEntry struct {
	Authors           string `json:"authors"`
	Copyright         string `json:"copyright"`
	LicenseExpression string `json:"licenseExpression"`
	LicenseURL        string `json:"licenseUrl"`
	ProjectURL        string `json:"projectUrl"`
	Repository        string `json:"repository"`
	Published         string `json:"published"`
}

type nugetNuspec struct {
	Metadata struct {
		Authors    string `xml:"authors"`
		Owners     string `xml:"owners"`
		ProjectURL string `xml:"projectUrl"`
		LicenseURL string `xml:"licenseUrl"`
		Copyright  string `xml:"copyright"`
		Repository struct {
			URL string `xml:"url,attr"`
		} `xml:"repository"`
		License struct {
			Type  string `xml:"type,attr"`
			Value string `xml:",chardata"`
		} `xml:"license"`
	} `xml:"metadata"`
}

const DefaultNuGetRegistrationBaseURL = "https://api.nuget.org/v3/registration5-gz-semver2"

func (r *nugetResolver) resolve(packageName string, version string) metadata {
	cacheKey := makeNugetPackageKey(strings.ToLower(packageName), strings.ToLower(strings.TrimSpace(version)))
	if cached, ok := r.cache[cacheKey]; ok {
		return cached
	}

	meta := metadata{
		RawLicense: "Unknown",
		Holder:     packageName,
		Year:       now().Year(),
		Source:     "fallback",
	}

	if localMeta, ok, err := r.resolveFromGlobalPackages(packageName, version); err == nil && ok {
		r.cache[cacheKey] = localMeta
		return localMeta
	}

	if remoteMeta, ok, err := r.resolveFromRegistration(packageName, version); err == nil && ok {
		r.cache[cacheKey] = remoteMeta
		return remoteMeta
	}

	r.cache[cacheKey] = meta
	return meta
}

func (r *nugetResolver) resolveFromGlobalPackages(packageName string, version string) (metadata, bool, error) {
	root, ok := r.resolveGlobalPackagesRoot()
	if !ok {
		return metadata{}, false, nil
	}
	limits := NormalizeArtifactReadLimits(r.artifactReadLimits)

	packageDir := filepath.Join(root, strings.ToLower(packageName), strings.ToLower(strings.TrimSpace(version)))
	entries, err := os.ReadDir(packageDir)
	if err != nil {
		if os.IsNotExist(err) {
			return metadata{}, false, nil
		}
		return metadata{}, false, nil
	}

	var nuspecPath string
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		if strings.EqualFold(filepath.Ext(entry.Name()), ".nuspec") {
			nuspecPath = filepath.Join(packageDir, entry.Name())
			break
		}
	}
	if nuspecPath == "" {
		return metadata{}, false, nil
	}

	payload, err := readFileLimited(nuspecPath, limits.MaxPackageMetadataBytes)
	if err != nil {
		if safetyErr := wrapArtifactSafetyError(packageName, version, nuspecPath, "NuGet metadata file", err); safetyErr != nil {
			return metadata{}, false, safetyErr
		}
		return metadata{}, false, nil
	}

	var nuspec nugetNuspec
	if err := xml.Unmarshal(payload, &nuspec); err != nil {
		return metadata{}, false, nil
	}

	licenseValue, licensePath, licenseText, err := resolveNuspecLicense(
		nuspec.Metadata.License.Type,
		nuspec.Metadata.License.Value,
		nuspec.Metadata.LicenseURL,
		packageDir,
		nil,
		limits,
	)
	if err != nil {
		if safetyErr := wrapArtifactSafetyError(packageName, version, packageDir, "NuGet embedded license file", err); safetyErr != nil {
			return metadata{}, false, safetyErr
		}
		return metadata{}, false, nil
	}

	meta := metadata{
		RawLicense:          firstNonEmpty(licenseValue, "Unknown"),
		Repository:          strings.TrimSpace(nuspec.Metadata.Repository.URL),
		Homepage:            strings.TrimSpace(nuspec.Metadata.ProjectURL),
		Holder:              firstNonEmpty(firstCSVValue(nuspec.Metadata.Authors), firstCSVValue(nuspec.Metadata.Owners), packageName),
		Year:                extractCopyrightYear(nuspec.Metadata.Copyright, now().Year()),
		Source:              "nuget-global-packages",
		EmbeddedLicensePath: licensePath,
		EmbeddedLicenseText: licenseText,
		ArtifactResolution: &inventory.ArtifactResolution{
			Kind:   "local-package-manager",
			Detail: "nuget-global-packages",
		},
	}
	return meta, true, nil
}

func (r *nugetResolver) resolveFromRegistration(packageName string, version string) (metadata, bool, error) {
	if strings.TrimSpace(version) == "" || r.client == nil {
		return metadata{}, false, nil
	}
	limits := NormalizeArtifactReadLimits(r.artifactReadLimits)

	endpoint := fmt.Sprintf(
		"%s/%s/%s.json",
		strings.TrimRight(r.resolveRegistrationBaseURL(), "/"),
		urlPathEscapeLower(packageName),
		urlPathEscapeLower(version),
	)

	service := externalaccess.Service{
		ID:      "nuget-registration",
		Purpose: MetadataEnrichmentSourceKind,
		BaseURL: r.resolveRegistrationBaseURL(),
	}
	body, err := requestJSON(r.client, endpoint, service, limits.MaxPackageMetadataBytes)
	if err != nil {
		if safetyErr := wrapArtifactSafetyError(packageName, version, endpoint, "NuGet registration metadata", err); safetyErr != nil {
			return metadata{}, false, safetyErr
		}
		return metadata{}, false, nil
	}

	var leaf struct {
		CatalogEntry   string `json:"catalogEntry"`
		PackageContent string `json:"packageContent"`
	}
	if err := json.Unmarshal(body, &leaf); err != nil || strings.TrimSpace(leaf.CatalogEntry) == "" {
		return metadata{}, false, nil
	}

	catalogBody, err := requestJSON(r.client, leaf.CatalogEntry, service, limits.MaxPackageMetadataBytes)
	if err != nil {
		if safetyErr := wrapArtifactSafetyError(packageName, version, leaf.CatalogEntry, "NuGet catalog metadata", err); safetyErr != nil {
			return metadata{}, false, safetyErr
		}
		return metadata{}, false, nil
	}

	var entry nugetCatalogEntry
	if err := json.Unmarshal(catalogBody, &entry); err != nil {
		return metadata{}, false, nil
	}

	licenseValue := firstNonEmpty(entry.LicenseExpression, entry.LicenseURL)
	licensePath := ""
	licenseText := ""
	artifactResolution := &inventory.ArtifactResolution{
		Kind:           "remote-metadata",
		Detail:         "nuget-registration",
		ReviewRequired: true,
		ReviewReason:   "local-package-manager-artifact-not-available",
	}
	if strings.TrimSpace(entry.LicenseExpression) == "" && strings.TrimSpace(leaf.PackageContent) != "" {
		var err error
		licensePath, licenseText, err = r.resolveEmbeddedLicenseFromPackageContent(packageName, version, leaf.PackageContent)
		if err != nil {
			if safetyErr := wrapArtifactSafetyError(packageName, version, leaf.PackageContent, "NuGet package artifact", err); safetyErr != nil {
				return metadata{}, false, safetyErr
			}
			err = nil
		}
		if err == nil && licenseText != "" {
			licenseValue = licensePath
			artifactResolution = &inventory.ArtifactResolution{
				Kind:           "remote-package-content",
				Detail:         "nuget-package-content",
				ReviewRequired: true,
				ReviewReason:   "local-package-manager-artifact-not-available",
			}
		}
	}

	meta := metadata{
		RawLicense:          firstNonEmpty(licenseValue, "Unknown"),
		Repository:          strings.TrimSpace(entry.Repository),
		Homepage:            strings.TrimSpace(entry.ProjectURL),
		Holder:              firstNonEmpty(firstCSVValue(entry.Authors), packageName),
		Year:                parseMetadataYear(entry.Published),
		Source:              "nuget-registration",
		EmbeddedLicensePath: licensePath,
		EmbeddedLicenseText: licenseText,
		ArtifactResolution:  artifactResolution,
	}
	if strings.TrimSpace(meta.Repository) == "" {
		meta.Repository = meta.Homepage
	}
	return meta, true, nil
}

func nugetGlobalPackagesRoot() (string, bool) {
	return nugetGlobalPackagesRootWith(os.Getenv, os.UserHomeDir)
}

func nugetGlobalPackagesRootWith(getenv func(string) string, userHomeDir func() (string, error)) (string, bool) {
	if value := strings.TrimSpace(getenv("NUGET_PACKAGES")); value != "" {
		return filepath.Clean(value), true
	}

	homeDir, err := userHomeDir()
	if err != nil || strings.TrimSpace(homeDir) == "" {
		return "", false
	}

	return filepath.Join(homeDir, ".nuget", "packages"), true
}

func (r *nugetResolver) resolveGlobalPackagesRoot() (string, bool) {
	if strings.TrimSpace(r.globalPackagesRoot) != "" {
		return r.globalPackagesRoot, true
	}
	return nugetGlobalPackagesRoot()
}

func (r *nugetResolver) resolveRegistrationBaseURL() string {
	if strings.TrimSpace(r.registrationBaseURL) != "" {
		return r.registrationBaseURL
	}
	return DefaultNuGetRegistrationBaseURL
}

func resolveNuspecLicense(kind string, value string, licenseURL string, packageDir string, zipFile *zip.Reader, limits ArtifactReadLimits) (string, string, string, error) {
	switch strings.ToLower(strings.TrimSpace(kind)) {
	case "expression":
		return strings.TrimSpace(value), "", "", nil
	case "file":
		licensePath := strings.TrimSpace(value)
		licenseText := ""
		var err error
		if zipFile != nil {
			licenseText, err = readEmbeddedLicenseFromZip(zipFile, licensePath, NormalizeArtifactReadLimits(limits).MaxEmbeddedLicenseBytes)
		} else if packageDir != "" {
			licenseText, err = readEmbeddedLicenseFromDirectory(packageDir, licensePath, NormalizeArtifactReadLimits(limits).MaxEmbeddedLicenseBytes)
		}
		return firstNonEmpty(licensePath, licenseURL), licensePath, licenseText, err
	default:
		return firstNonEmpty(strings.TrimSpace(value), strings.TrimSpace(licenseURL)), "", "", nil
	}
}

func parseMetadataYear(value string) int {
	if parsed, err := time.Parse(time.RFC3339, value); err == nil {
		return parsed.Year()
	}
	return now().Year()
}

func extractCopyrightYear(value string, fallback int) int {
	for _, part := range strings.FieldsFunc(value, func(r rune) bool {
		return r < '0' || r > '9'
	}) {
		if len(part) == 4 {
			if year, err := time.Parse("2006", part); err == nil {
				return year.Year()
			}
		}
	}
	return fallback
}

func urlPathEscapeLower(value string) string {
	return url.PathEscape(strings.ToLower(strings.TrimSpace(value)))
}

func (r *nugetResolver) resolveEmbeddedLicenseFromPackageContent(packageName string, version string, packageContentURL string) (string, string, error) {
	req, err := http.NewRequest(http.MethodGet, packageContentURL, nil)
	if err != nil {
		return "", "", err
	}
	req = externalaccess.WithRequestService(req, externalaccess.Service{
		ID:      "nuget-registration",
		Purpose: MetadataEnrichmentSourceKind,
		BaseURL: externalaccess.OriginFromURL(packageContentURL),
	})
	req = httpcache.WithMaxResponseBytes(req, NormalizeArtifactReadLimits(r.artifactReadLimits).MaxPackageArtifactBytes)
	req.Header.Set("User-Agent", "depaudit-license")

	resp, err := r.client.Do(req)
	if err != nil {
		return "", "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", "", fmt.Errorf("unexpected status %d", resp.StatusCode)
	}
	limits := NormalizeArtifactReadLimits(r.artifactReadLimits)
	if resp.ContentLength > 0 && resp.ContentLength > limits.MaxPackageArtifactBytes {
		return "", "", &artifactLimitExceededError{reason: fmt.Sprintf("content length %d bytes exceeds limit %d bytes", resp.ContentLength, limits.MaxPackageArtifactBytes)}
	}

	payload, err := readAllLimited(resp.Body, limits.MaxPackageArtifactBytes)
	if err != nil {
		return "", "", err
	}

	zipReader, err := zip.NewReader(bytes.NewReader(payload), int64(len(payload)))
	if err != nil {
		return "", "", err
	}
	if len(zipReader.File) > limits.MaxPackageArchiveEntries {
		return "", "", &artifactLimitExceededError{reason: fmt.Sprintf("archive entry count %d exceeds limit %d", len(zipReader.File), limits.MaxPackageArchiveEntries)}
	}

	var nuspecPayload []byte
	for _, file := range zipReader.File {
		if strings.EqualFold(filepath.Ext(file.Name), ".nuspec") {
			nuspecPayload, err = readZipFile(file, limits.MaxPackageMetadataBytes)
			if err != nil {
				return "", "", err
			}
			break
		}
	}
	if len(nuspecPayload) == 0 {
		return "", "", fmt.Errorf("nuspec not found in package archive")
	}

	var nuspec nugetNuspec
	if err := xml.Unmarshal(nuspecPayload, &nuspec); err != nil {
		return "", "", err
	}

	_, licensePath, licenseText, err := resolveNuspecLicense(
		nuspec.Metadata.License.Type,
		nuspec.Metadata.License.Value,
		nuspec.Metadata.LicenseURL,
		"",
		zipReader,
		limits,
	)
	if err != nil {
		return "", "", err
	}
	if licensePath == "" || licenseText == "" {
		return "", "", fmt.Errorf("embedded license file not found in package archive")
	}
	return licensePath, licenseText, nil
}

func readEmbeddedLicenseFromDirectory(packageDir string, licensePath string, maxBytes int64) (string, error) {
	normalized := normalizeEmbeddedLicensePath(licensePath)
	if strings.TrimSpace(packageDir) == "" || normalized == "" {
		return "", nil
	}
	payload, err := readFileLimited(filepath.Join(packageDir, filepath.FromSlash(normalized)), maxBytes)
	if err != nil {
		if os.IsNotExist(err) {
			return "", nil
		}
		return "", err
	}
	return string(payload), nil
}

func readEmbeddedLicenseFromZip(reader *zip.Reader, licensePath string, maxBytes int64) (string, error) {
	normalized := normalizeEmbeddedLicensePath(licensePath)
	if normalized == "" {
		return "", nil
	}
	for _, file := range reader.File {
		if normalizeEmbeddedLicensePath(file.Name) != normalized {
			continue
		}
		payload, err := readZipFile(file, maxBytes)
		if err != nil {
			return "", err
		}
		return string(payload), nil
	}
	return "", nil
}

func normalizeEmbeddedLicensePath(licensePath string) string {
	value := strings.ReplaceAll(filepath.ToSlash(strings.TrimSpace(licensePath)), "\\", "/")
	if strings.HasPrefix(value, "//") || hasWindowsVolumePrefix(value) || filepath.VolumeName(filepath.FromSlash(value)) != "" {
		return ""
	}

	normalized := path.Clean(strings.TrimLeft(value, "/"))
	if normalized == "." || normalized == ".." || strings.HasPrefix(normalized, "../") {
		return ""
	}
	platformPath := filepath.FromSlash(normalized)
	if hasWindowsVolumePrefix(normalized) || filepath.VolumeName(platformPath) != "" || filepath.IsAbs(platformPath) {
		return ""
	}
	return normalized
}

func hasWindowsVolumePrefix(value string) bool {
	if len(value) < 2 || value[1] != ':' {
		return false
	}
	drive := value[0]
	return (drive >= 'A' && drive <= 'Z') || (drive >= 'a' && drive <= 'z')
}

func readZipFile(file *zip.File, maxBytes int64) ([]byte, error) {
	handle, err := file.Open()
	if err != nil {
		return nil, err
	}
	defer handle.Close()
	if maxBytes > 0 && file.UncompressedSize64 > uint64(maxBytes) {
		return nil, fmt.Errorf("zip entry size %d bytes exceeds limit %d bytes", file.UncompressedSize64, maxBytes)
	}
	return readAllLimited(handle, maxBytes)
}
