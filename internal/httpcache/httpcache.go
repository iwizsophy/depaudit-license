package httpcache

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

var now = time.Now

const (
	ModeOff       = "off"
	ModeUse       = "use"
	ModeRefresh   = "refresh"
	ModeCacheOnly = "cache-only"
)

type Config struct {
	Mode          string
	Dir           string
	TTL           time.Duration
	WarningWriter io.Writer
}

type cachedResponse struct {
	Method            string      `json:"method"`
	URL               string      `json:"url"`
	RequestBodySHA256 string      `json:"requestBodySha256"`
	StatusCode        int         `json:"statusCode"`
	Header            http.Header `json:"header"`
	BodyBase64        string      `json:"bodyBase64"`
	StoredAt          string      `json:"storedAt"`
}

type transport struct {
	base http.RoundTripper
	cfg  Config
}

type requestInfo struct {
	method   string
	url      string
	body     []byte
	bodyHash string
	varyHash string
}

func DefaultDir() string {
	dir, err := os.UserCacheDir()
	if err != nil || strings.TrimSpace(dir) == "" {
		return filepath.Join(os.TempDir(), "depaudit-license", "http-cache")
	}
	return filepath.Join(dir, "depaudit-license", "http-cache")
}

func NormalizeConfig(cfg Config) Config {
	mode := strings.ToLower(strings.TrimSpace(cfg.Mode))
	if mode == "" {
		mode = ModeUse
	}
	dir := strings.TrimSpace(cfg.Dir)
	if mode != ModeOff && dir == "" {
		dir = DefaultDir()
	}
	return Config{
		Mode:          mode,
		Dir:           dir,
		TTL:           cfg.TTL,
		WarningWriter: cfg.WarningWriter,
	}
}

func ValidateConfig(cfg Config) error {
	cfg = NormalizeConfig(cfg)
	switch cfg.Mode {
	case ModeOff, ModeUse, ModeRefresh, ModeCacheOnly:
	default:
		return fmt.Errorf("invalid HTTP cache mode %q", cfg.Mode)
	}
	if cfg.TTL < 0 {
		return fmt.Errorf("http cache TTL must be zero or greater")
	}
	return nil
}

func WrapClient(client *http.Client, cfg Config) *http.Client {
	cfg = NormalizeConfig(cfg)
	if client == nil {
		client = &http.Client{}
	}
	clone := *client
	baseTransport := clone.Transport
	if baseTransport == nil {
		baseTransport = http.DefaultTransport
	}
	clone.Transport = &transport{
		base: baseTransport,
		cfg:  cfg,
	}
	return &clone
}

func (t *transport) RoundTrip(req *http.Request) (*http.Response, error) {
	cfg := NormalizeConfig(t.cfg)
	if cfg.Mode == ModeOff {
		return t.base.RoundTrip(req)
	}

	info, ok, err := cacheableRequestInfo(req)
	if err != nil {
		return nil, err
	}
	if !ok {
		return t.base.RoundTrip(req)
	}

	cachePath := cacheFilePath(cfg.Dir, info)
	var stale *cachedResponse
	if cfg.Mode != ModeRefresh {
		record, recordErr := readCache(cachePath)
		if recordErr == nil {
			if !isExpired(record, cfg.TTL) {
				return responseFromCache(record, req)
			}
			stale = &record
		} else if cfg.Mode == ModeCacheOnly {
			return nil, fmt.Errorf("http cache miss for %s %s", info.method, info.url)
		}
	}
	if cfg.Mode == ModeCacheOnly {
		return nil, fmt.Errorf("http cache entry expired for %s %s", info.method, info.url)
	}

	networkReq := cloneRequestWithBody(req, info.body)
	resp, err := t.base.RoundTrip(networkReq)
	if err != nil {
		if cfg.Mode == ModeUse && stale != nil {
			return responseFromCache(*stale, req)
		}
		return nil, err
	}

	body, readErr := io.ReadAll(resp.Body)
	resp.Body.Close()
	if readErr != nil {
		return nil, readErr
	}

	if cfg.Mode == ModeUse && stale != nil && shouldUseStale(resp.StatusCode) {
		return responseFromCache(*stale, req)
	}

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		record := cachedResponse{
			Method:            info.method,
			URL:               info.url,
			RequestBodySHA256: info.bodyHash,
			StatusCode:        resp.StatusCode,
			Header:            cloneHeader(resp.Header),
			BodyBase64:        base64.StdEncoding.EncodeToString(body),
			StoredAt:          now().UTC().Format(time.RFC3339),
		}
		if writeErr := writeCache(cachePath, record); writeErr != nil {
			writeWarning(cfg.WarningWriter, "http cache write failed for %s %s: %v", info.method, info.url, writeErr)
		}
	}

	return cloneResponse(resp, req, body), nil
}

func cacheableRequestInfo(req *http.Request) (requestInfo, bool, error) {
	if req == nil || req.URL == nil {
		return requestInfo{}, false, nil
	}
	scheme := strings.ToLower(strings.TrimSpace(req.URL.Scheme))
	if scheme != "http" && scheme != "https" {
		return requestInfo{}, false, nil
	}
	method := strings.ToUpper(strings.TrimSpace(req.Method))
	if method != http.MethodGet && method != http.MethodPost {
		return requestInfo{}, false, nil
	}

	body, err := readRequestBody(req)
	if err != nil {
		return requestInfo{}, false, err
	}
	return requestInfo{
		method:   method,
		url:      req.URL.String(),
		body:     body,
		bodyHash: sha256Hex(body),
		varyHash: requestVaryHash(req),
	}, true, nil
}

func readRequestBody(req *http.Request) ([]byte, error) {
	if req == nil || req.Body == nil {
		return nil, nil
	}
	if req.GetBody != nil {
		reader, err := req.GetBody()
		if err != nil {
			return nil, err
		}
		defer reader.Close()
		return io.ReadAll(reader)
	}
	body, err := io.ReadAll(req.Body)
	if err != nil {
		return nil, err
	}
	req.Body.Close()
	req.Body = io.NopCloser(bytes.NewReader(body))
	req.ContentLength = int64(len(body))
	return body, nil
}

func cloneRequestWithBody(req *http.Request, body []byte) *http.Request {
	clone := req.Clone(req.Context())
	if body == nil {
		clone.Body = nil
		clone.GetBody = nil
		clone.ContentLength = 0
		return clone
	}
	clone.Body = io.NopCloser(bytes.NewReader(body))
	clone.GetBody = func() (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader(body)), nil
	}
	clone.ContentLength = int64(len(body))
	return clone
}

func cloneResponse(resp *http.Response, req *http.Request, body []byte) *http.Response {
	if resp == nil {
		return nil
	}
	clone := *resp
	clone.Request = req
	clone.Header = cloneHeader(resp.Header)
	clone.Body = io.NopCloser(bytes.NewReader(body))
	clone.ContentLength = int64(len(body))
	return &clone
}

func responseFromCache(record cachedResponse, req *http.Request) (*http.Response, error) {
	body, err := base64.StdEncoding.DecodeString(record.BodyBase64)
	if err != nil {
		return nil, err
	}
	return &http.Response{
		StatusCode:    record.StatusCode,
		Status:        fmt.Sprintf("%d %s", record.StatusCode, http.StatusText(record.StatusCode)),
		Header:        cloneHeader(record.Header),
		Body:          io.NopCloser(bytes.NewReader(body)),
		ContentLength: int64(len(body)),
		Request:       req,
		Proto:         "HTTP/1.1",
		ProtoMajor:    1,
		ProtoMinor:    1,
	}, nil
}

func isExpired(record cachedResponse, ttl time.Duration) bool {
	if ttl == 0 {
		return false
	}
	storedAt, err := time.Parse(time.RFC3339, strings.TrimSpace(record.StoredAt))
	if err != nil {
		return true
	}
	return now().After(storedAt.Add(ttl))
}

func shouldUseStale(statusCode int) bool {
	return statusCode == http.StatusTooManyRequests || statusCode >= 500
}

func cacheFilePath(cacheDir string, info requestInfo) string {
	key := sha256Hex([]byte(info.method + "\n" + info.url + "\n" + info.bodyHash + "\n" + info.varyHash))
	return filepath.Join(cacheDir, key[:2], key+".json")
}

func writeCache(path string, record cachedResponse) error {
	if strings.TrimSpace(path) == "" {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	record.Header = sanitizeResponseHeader(record.Header)
	payload, err := json.Marshal(record)
	if err != nil {
		return err
	}
	tempPath := path + ".tmp"
	if err := os.WriteFile(tempPath, payload, 0o600); err != nil {
		return err
	}
	if err := os.Rename(tempPath, path); err == nil {
		return nil
	}
	_ = os.Remove(path)
	return os.Rename(tempPath, path)
}

func readCache(path string) (cachedResponse, error) {
	payload, err := os.ReadFile(path)
	if err != nil {
		return cachedResponse{}, err
	}
	var record cachedResponse
	if err := json.Unmarshal(payload, &record); err != nil {
		return cachedResponse{}, err
	}
	return record, nil
}

func cloneHeader(header http.Header) http.Header {
	if header == nil {
		return make(http.Header)
	}
	cloned := make(http.Header, len(header))
	for key, values := range header {
		cloned[key] = append([]string(nil), values...)
	}
	return cloned
}

func sanitizeResponseHeader(header http.Header) http.Header {
	sanitized := cloneHeader(header)
	delete(sanitized, "Set-Cookie")
	delete(sanitized, "Set-Cookie2")
	return sanitized
}

func requestVaryHash(req *http.Request) string {
	if req == nil {
		return sha256Hex(nil)
	}
	parts := []string{
		"accept:" + strings.TrimSpace(req.Header.Get("Accept")),
		"content-type:" + strings.TrimSpace(req.Header.Get("Content-Type")),
		"x-github-api-version:" + strings.TrimSpace(req.Header.Get("X-GitHub-Api-Version")),
		"authorization-sha256:" + hashSecretHeader(req.Header.Get("Authorization")),
		"apikey-sha256:" + hashSecretHeader(req.Header.Get("apiKey")),
		"cookie-sha256:" + hashSecretHeader(req.Header.Get("Cookie")),
	}
	return sha256Hex([]byte(strings.Join(parts, "\n")))
}

func hashSecretHeader(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	return sha256Hex([]byte(value))
}

func writeWarning(writer io.Writer, format string, args ...any) {
	if writer == nil {
		return
	}
	_, _ = fmt.Fprintf(writer, "warning: "+format+"\n", args...)
}

func sha256Hex(payload []byte) string {
	sum := sha256.Sum256(payload)
	return hex.EncodeToString(sum[:])
}
