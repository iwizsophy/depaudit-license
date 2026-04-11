package scan

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"depaudit-license/internal/externalaccess"
	"depaudit-license/internal/inventory"
)

const DefaultNodeRegistryBaseURL = "https://registry.npmjs.org"

var now = time.Now

func (r *nodeResolver) resolve(packageName string, version string, projectDir string) metadata {
	cacheKey := makeNodePackageKey(packageName, version)
	if cached, ok := r.cache[cacheKey]; ok {
		return cached
	}

	if local, ok := r.resolveFromInstalledPackage(packageName, version, projectDir); ok {
		r.cache[cacheKey] = local
		return local
	}

	remote := r.resolveRemote(packageName, version)
	r.cache[cacheKey] = remote
	return remote
}

func (r *nodeResolver) resolveRemote(packageName string, version string) metadata {
	cacheKey := makeNodePackageKey(packageName, version)
	if cached, ok := r.cache[cacheKey]; ok {
		return cached
	}

	meta := metadata{
		RawLicense: "Unknown",
		Holder:     packageName,
		Year:       now().Year(),
		Source:     "fallback",
	}

	if !isExactNodeVersion(version) {
		return meta
	}
	if r.client == nil {
		return meta
	}

	endpoint := strings.TrimRight(firstNonEmpty(r.registryBaseURL, DefaultNodeRegistryBaseURL), "/") +
		"/" + url.PathEscape(packageName) + "/" + url.PathEscape(version)
	body, err := requestJSON(r.client, endpoint, externalaccess.Service{
		ID:      "npm-registry",
		Purpose: MetadataEnrichmentSourceKind,
		BaseURL: firstNonEmpty(r.registryBaseURL, DefaultNodeRegistryBaseURL),
	})
	if err != nil {
		return meta
	}

	var versionPayload npmVersionPayload
	if err := json.Unmarshal(body, &versionPayload); err != nil {
		return meta
	}

	meta.RawLicense = parseLicense(versionPayload.License)
	if meta.RawLicense == "" {
		meta.RawLicense = "Unknown"
	}

	meta.Repository = parseRepository(versionPayload.Repository)
	meta.Homepage = versionPayload.Homepage
	meta.Holder = firstNonEmpty(
		parsePerson(versionPayload.Author),
		firstNonEmpty(parsePeople(versionPayload.Maintainers)...),
		firstNonEmpty(parsePeople(versionPayload.Contributors)...),
		packageName,
	)
	meta.Source = "npm-registry-version"
	meta.ArtifactResolution = &inventory.ArtifactResolution{
		Kind:           "remote-metadata",
		Detail:         "npm-registry-version",
		ReviewRequired: true,
		ReviewReason:   "local-package-manager-artifact-not-available",
	}
	return meta
}

func requestJSON(client *http.Client, endpoint string, service externalaccess.Service) ([]byte, error) {
	req, err := http.NewRequest(http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	req = externalaccess.WithRequestService(req, service)
	req.Header.Set("User-Agent", "depaudit-license")
	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("unexpected status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	return body, nil
}

func sanitizeVersion(value string) string {
	return strings.Trim(strings.TrimSpace(value), "^~<>= ")
}
