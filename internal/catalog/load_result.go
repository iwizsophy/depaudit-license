package catalog

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
	"path/filepath"
	"strings"
)

type LoadResult struct {
	Catalog          *Catalog
	SourceMetadata   []SourceMetadata
	EffectiveCatalog json.RawMessage
}

type SourceMetadata struct {
	Kind            string `json:"kind"`
	Location        string `json:"location"`
	DisplayLocation string `json:"displayLocation,omitempty"`
	ResolvedURL     string `json:"resolvedUrl,omitempty"`
	PinningMode     string `json:"pinningMode"`
	CacheStatus     string `json:"cacheStatus,omitempty"`
	RequestedSHA256 string `json:"requestedSha256,omitempty"`
	ContentSHA256   string `json:"contentSha256"`
	RetrievedAt     string `json:"retrievedAt,omitempty"`
	ETag            string `json:"etag,omitempty"`
	Revision        string `json:"revision,omitempty"`
}

type sourceSpec struct {
	OriginalURL     string
	RequestURL      string
	RequestedSHA256 string
}

func buildLoadResult(cat *Catalog, snapshot fileFormat, sources []SourceMetadata) *LoadResult {
	payload, _ := json.Marshal(snapshot)
	return &LoadResult{
		Catalog:          cat,
		SourceMetadata:   sources,
		EffectiveCatalog: payload,
	}
}

func parseSourceSpec(source string) (sourceSpec, error) {
	spec := sourceSpec{
		OriginalURL: strings.TrimSpace(source),
		RequestURL:  strings.TrimSpace(source),
	}
	parsed, err := url.Parse(spec.OriginalURL)
	if err != nil || parsed.Host == "" {
		return spec, nil
	}
	switch strings.ToLower(parsed.Scheme) {
	case "http", "https":
	default:
		return spec, nil
	}
	if parsed.Fragment == "" {
		return spec, nil
	}

	values, err := url.ParseQuery(strings.ReplaceAll(parsed.Fragment, ";", "&"))
	if err != nil {
		return sourceSpec{}, err
	}
	spec.RequestedSHA256 = strings.TrimSpace(values.Get("sha256"))
	parsed.Fragment = ""
	spec.RequestURL = parsed.String()
	return spec, nil
}

func sha256Hex(payload []byte) string {
	sum := sha256.Sum256(payload)
	return hex.EncodeToString(sum[:])
}

func verifyRequestedSHA256(requested string, actual string, source string) error {
	if strings.TrimSpace(requested) == "" {
		return nil
	}
	if !strings.EqualFold(strings.TrimSpace(requested), actual) {
		return fmt.Errorf("fetch catalog %s: sha256 mismatch", source)
	}
	return nil
}

func remoteSourceMetadata(spec sourceSpec, actualHash string, etag string, revision string) SourceMetadata {
	return SourceMetadata{
		Kind:            "remote",
		Location:        spec.OriginalURL,
		DisplayLocation: spec.OriginalURL,
		ResolvedURL:     spec.RequestURL,
		PinningMode:     remotePinningMode(spec),
		CacheStatus:     "network",
		RequestedSHA256: strings.TrimSpace(spec.RequestedSHA256),
		ContentSHA256:   actualHash,
		RetrievedAt:     nowRFC3339(),
		ETag:            strings.TrimSpace(etag),
		Revision:        strings.TrimSpace(revision),
	}
}

func localSourceMetadata(location string, actualHash string) SourceMetadata {
	return SourceMetadata{
		Kind:            "file",
		Location:        location,
		DisplayLocation: filepath.Base(location),
		PinningMode:     "implicit",
		ContentSHA256:   actualHash,
	}
}

func firstNonEmptyString(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}
