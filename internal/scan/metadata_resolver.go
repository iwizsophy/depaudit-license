package scan

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"depaudit-license/internal/externalaccess"
	"depaudit-license/internal/inventory"
)

const DefaultNodeRegistryBaseURL = "https://registry.npmjs.org"

var now = time.Now

func (r *nodeResolver) resolveRemote(packageName string, version string) (metadata, error) {
	cacheKey := makeNodePackageKey(packageName, version)
	if cached, ok := r.cache[cacheKey]; ok {
		return cached, nil
	}

	meta := metadata{
		RawLicense: "Unknown",
		Holder:     packageName,
		Year:       now().Year(),
		Source:     "fallback",
	}

	if !isExactNodeVersion(version) {
		return meta, nil
	}
	if r.client == nil {
		return meta, nil
	}

	limits := NormalizeArtifactReadLimits(r.artifactReadLimits)
	endpoint := strings.TrimRight(firstNonEmpty(r.registryBaseURL, DefaultNodeRegistryBaseURL), "/") +
		"/" + url.PathEscape(packageName) + "/" + url.PathEscape(version)
	body, err := requestJSON(r.client, endpoint, externalaccess.Service{
		ID:      "npm-registry",
		Purpose: MetadataEnrichmentSourceKind,
		BaseURL: firstNonEmpty(r.registryBaseURL, DefaultNodeRegistryBaseURL),
	}, limits.MaxPackageMetadataBytes)
	if err != nil {
		if safetyErr := wrapArtifactSafetyError(packageName, version, endpoint, "npm registry metadata", err); safetyErr != nil {
			return metadata{}, safetyErr
		}
		return meta, nil
	}

	var versionPayload npmVersionPayload
	if err := json.Unmarshal(body, &versionPayload); err != nil {
		return meta, nil
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
	return meta, nil
}

func requestJSON(client *http.Client, endpoint string, service externalaccess.Service, maxBytes int64) ([]byte, error) {
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

	if maxBytes > 0 && resp.ContentLength > maxBytes {
		return nil, &artifactLimitExceededError{reason: fmt.Sprintf("content length %d bytes exceeds limit %d bytes", resp.ContentLength, maxBytes)}
	}

	body, err := readAllLimited(resp.Body, maxBytes)
	if err != nil {
		return nil, err
	}
	return body, nil
}

func sanitizeVersion(value string) string {
	return strings.Trim(strings.TrimSpace(value), "^~<>= ")
}
