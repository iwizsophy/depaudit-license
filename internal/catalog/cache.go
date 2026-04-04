package catalog

import (
	"crypto/sha1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

var now = time.Now

const (
	RemoteCatalogModeFailFast      = "fail-fast"
	RemoteCatalogModeStaleFallback = "stale-fallback"
)

type LoadOptions struct {
	Client            *http.Client
	RemoteCatalogMode string
	CacheDir          string
}

type cachedRemoteCatalog struct {
	Source        string `json:"source"`
	DisplaySource string `json:"displaySource,omitempty"`
	ResolvedURL   string `json:"resolvedUrl"`
	ContentSHA256 string `json:"contentSha256"`
	RetrievedAt   string `json:"retrievedAt"`
	ETag          string `json:"etag,omitempty"`
	Revision      string `json:"revision,omitempty"`
	PayloadBase64 string `json:"payloadBase64"`
}

func normalizeLoadOptions(opts LoadOptions) LoadOptions {
	mode := opts.RemoteCatalogMode
	if mode == "" {
		mode = RemoteCatalogModeFailFast
	}
	return LoadOptions{
		Client:            opts.Client,
		RemoteCatalogMode: mode,
		CacheDir:          strings.TrimSpace(opts.CacheDir),
	}
}

func validateLoadOptions(opts LoadOptions) error {
	switch opts.RemoteCatalogMode {
	case RemoteCatalogModeFailFast, RemoteCatalogModeStaleFallback:
		return nil
	default:
		return fmt.Errorf("invalid remote catalog mode %q", opts.RemoteCatalogMode)
	}
}

func defaultRemoteCatalogCacheDir() string {
	dir, err := os.UserCacheDir()
	if err != nil || dir == "" {
		return filepath.Join(os.TempDir(), "depaudit-license", "catalog-cache")
	}
	return filepath.Join(dir, "depaudit-license", "catalog-cache")
}

func cacheFilePath(cacheDir string, source string) string {
	sum := sha1.Sum([]byte(source))
	return filepath.Join(cacheDir, hex.EncodeToString(sum[:])+".json")
}

func writeRemoteCatalogCache(cacheDir string, metadata SourceMetadata, payload []byte) error {
	if strings.TrimSpace(cacheDir) == "" {
		return nil
	}
	if err := os.MkdirAll(cacheDir, 0o755); err != nil {
		return err
	}
	record := cachedRemoteCatalog{
		Source:        metadata.Location,
		DisplaySource: metadata.DisplayLocation,
		ResolvedURL:   metadata.ResolvedURL,
		ContentSHA256: metadata.ContentSHA256,
		RetrievedAt:   metadata.RetrievedAt,
		ETag:          metadata.ETag,
		Revision:      metadata.Revision,
		PayloadBase64: base64.StdEncoding.EncodeToString(payload),
	}
	serialized, err := json.Marshal(record)
	if err != nil {
		return err
	}
	return os.WriteFile(cacheFilePath(cacheDir, metadata.Location), serialized, 0o644)
}

func readRemoteCatalogCache(cacheDir string, spec sourceSpec) ([]byte, SourceMetadata, error) {
	if strings.TrimSpace(cacheDir) == "" {
		return nil, SourceMetadata{}, fmt.Errorf("cache is disabled")
	}
	payload, err := os.ReadFile(cacheFilePath(cacheDir, spec.OriginalURL))
	if err != nil {
		return nil, SourceMetadata{}, err
	}

	var record cachedRemoteCatalog
	if err := json.Unmarshal(payload, &record); err != nil {
		return nil, SourceMetadata{}, err
	}
	decoded, err := base64.StdEncoding.DecodeString(record.PayloadBase64)
	if err != nil {
		return nil, SourceMetadata{}, err
	}
	actualHash := sha256Hex(decoded)
	if actualHash != record.ContentSHA256 {
		return nil, SourceMetadata{}, fmt.Errorf("cached remote catalog payload hash mismatch")
	}
	if err := verifyRequestedSHA256(spec.RequestedSHA256, actualHash, spec.OriginalURL); err != nil {
		return nil, SourceMetadata{}, err
	}

	metadata := SourceMetadata{
		Kind:            "remote",
		Location:        record.Source,
		DisplayLocation: firstNonEmptyString(record.DisplaySource, record.Source),
		ResolvedURL:     record.ResolvedURL,
		PinningMode:     remotePinningMode(spec),
		RequestedSHA256: spec.RequestedSHA256,
		ContentSHA256:   actualHash,
		RetrievedAt:     record.RetrievedAt,
		ETag:            record.ETag,
		Revision:        record.Revision,
		CacheStatus:     "stale-cache",
	}
	return decoded, metadata, nil
}

func remotePinningMode(spec sourceSpec) string {
	if strings.TrimSpace(spec.RequestedSHA256) != "" {
		return "pinned"
	}
	return "floating"
}

func nowRFC3339() string {
	return now().Format(time.RFC3339)
}
