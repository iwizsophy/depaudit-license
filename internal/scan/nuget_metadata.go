package scan

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type nugetResolver struct {
	client              *http.Client
	cache               map[string]metadata
	globalPackagesRoot  string
	registrationBaseURL string
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

	if localMeta, ok := r.resolveFromGlobalPackages(packageName, version); ok {
		r.cache[cacheKey] = localMeta
		return localMeta
	}

	if remoteMeta, ok := r.resolveFromRegistration(packageName, version); ok {
		r.cache[cacheKey] = remoteMeta
		return remoteMeta
	}

	r.cache[cacheKey] = meta
	return meta
}

func (r *nugetResolver) resolveFromGlobalPackages(packageName string, version string) (metadata, bool) {
	root, ok := r.resolveGlobalPackagesRoot()
	if !ok {
		return metadata{}, false
	}

	packageDir := filepath.Join(root, strings.ToLower(packageName), strings.ToLower(strings.TrimSpace(version)))
	entries, err := os.ReadDir(packageDir)
	if err != nil {
		return metadata{}, false
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
		return metadata{}, false
	}

	payload, err := os.ReadFile(nuspecPath)
	if err != nil {
		return metadata{}, false
	}

	var nuspec nugetNuspec
	if err := xml.Unmarshal(payload, &nuspec); err != nil {
		return metadata{}, false
	}

	licenseValue, licensePath, licenseText := resolveNuspecLicense(
		nuspec.Metadata.License.Type,
		nuspec.Metadata.License.Value,
		nuspec.Metadata.LicenseURL,
		packageDir,
		nil,
	)

	meta := metadata{
		RawLicense:          firstNonEmpty(licenseValue, "Unknown"),
		Repository:          strings.TrimSpace(nuspec.Metadata.Repository.URL),
		Homepage:            strings.TrimSpace(nuspec.Metadata.ProjectURL),
		Holder:              firstNonEmpty(firstCSVValue(nuspec.Metadata.Authors), firstCSVValue(nuspec.Metadata.Owners), packageName),
		Year:                extractCopyrightYear(nuspec.Metadata.Copyright, now().Year()),
		Source:              "nuget-global-packages",
		EmbeddedLicensePath: licensePath,
		EmbeddedLicenseText: licenseText,
	}
	return meta, true
}

func (r *nugetResolver) resolveFromRegistration(packageName string, version string) (metadata, bool) {
	if strings.TrimSpace(version) == "" || r.client == nil {
		return metadata{}, false
	}

	endpoint := fmt.Sprintf(
		"%s/%s/%s.json",
		strings.TrimRight(r.resolveRegistrationBaseURL(), "/"),
		urlPathEscapeLower(packageName),
		urlPathEscapeLower(version),
	)

	body, err := requestJSON(r.client, endpoint)
	if err != nil {
		return metadata{}, false
	}

	var leaf struct {
		CatalogEntry   string `json:"catalogEntry"`
		PackageContent string `json:"packageContent"`
	}
	if err := json.Unmarshal(body, &leaf); err != nil || strings.TrimSpace(leaf.CatalogEntry) == "" {
		return metadata{}, false
	}

	catalogBody, err := requestJSON(r.client, leaf.CatalogEntry)
	if err != nil {
		return metadata{}, false
	}

	var entry nugetCatalogEntry
	if err := json.Unmarshal(catalogBody, &entry); err != nil {
		return metadata{}, false
	}

	licenseValue := firstNonEmpty(entry.LicenseExpression, entry.LicenseURL)
	licensePath := ""
	licenseText := ""
	if licenseValue == "" && strings.TrimSpace(leaf.PackageContent) != "" {
		var err error
		licensePath, licenseText, err = r.resolveEmbeddedLicenseFromPackageContent(leaf.PackageContent)
		if err == nil && licenseText != "" {
			licenseValue = licensePath
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
	}
	if strings.TrimSpace(meta.Repository) == "" {
		meta.Repository = meta.Homepage
	}
	return meta, true
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
	return "https://api.nuget.org/v3/registration5-gz-semver2"
}

func resolveNuspecLicense(kind string, value string, licenseURL string, packageDir string, zipFile *zip.Reader) (string, string, string) {
	switch strings.ToLower(strings.TrimSpace(kind)) {
	case "expression":
		return strings.TrimSpace(value), "", ""
	case "file":
		licensePath := strings.TrimSpace(value)
		licenseText := ""
		if zipFile != nil {
			licenseText = readEmbeddedLicenseFromZip(zipFile, licensePath)
		} else if packageDir != "" {
			licenseText = readEmbeddedLicenseFromDirectory(packageDir, licensePath)
		}
		return firstNonEmpty(licensePath, licenseURL), licensePath, licenseText
	default:
		return firstNonEmpty(strings.TrimSpace(value), strings.TrimSpace(licenseURL)), "", ""
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

func (r *nugetResolver) resolveEmbeddedLicenseFromPackageContent(packageContentURL string) (string, string, error) {
	req, err := http.NewRequest(http.MethodGet, packageContentURL, nil)
	if err != nil {
		return "", "", err
	}
	req.Header.Set("User-Agent", "depaudit-license")

	resp, err := r.client.Do(req)
	if err != nil {
		return "", "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", "", fmt.Errorf("unexpected status %d", resp.StatusCode)
	}

	payload, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", "", err
	}

	zipReader, err := zip.NewReader(bytes.NewReader(payload), int64(len(payload)))
	if err != nil {
		return "", "", err
	}

	var nuspecPayload []byte
	for _, file := range zipReader.File {
		if strings.EqualFold(filepath.Ext(file.Name), ".nuspec") {
			nuspecPayload, err = readZipFile(file)
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

	_, licensePath, licenseText := resolveNuspecLicense(
		nuspec.Metadata.License.Type,
		nuspec.Metadata.License.Value,
		nuspec.Metadata.LicenseURL,
		"",
		zipReader,
	)
	if licensePath == "" || licenseText == "" {
		return "", "", fmt.Errorf("embedded license file not found in package archive")
	}
	return licensePath, licenseText, nil
}

func readEmbeddedLicenseFromDirectory(packageDir string, licensePath string) string {
	payload, err := os.ReadFile(filepath.Join(packageDir, filepath.FromSlash(strings.TrimSpace(licensePath))))
	if err != nil {
		return ""
	}
	return string(payload)
}

func readEmbeddedLicenseFromZip(reader *zip.Reader, licensePath string) string {
	normalized := strings.TrimLeft(filepath.ToSlash(strings.TrimSpace(licensePath)), "/")
	for _, file := range reader.File {
		if filepath.ToSlash(file.Name) != normalized {
			continue
		}
		payload, err := readZipFile(file)
		if err != nil {
			return ""
		}
		return string(payload)
	}
	return ""
}

func readZipFile(file *zip.File) ([]byte, error) {
	handle, err := file.Open()
	if err != nil {
		return nil, err
	}
	defer handle.Close()
	return io.ReadAll(handle)
}
