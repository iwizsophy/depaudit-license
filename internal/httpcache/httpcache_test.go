package httpcache

import (
	"bytes"
	"encoding/base64"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"depaudit-license/internal/testutil"
)

type roundTripFunc = testutil.RoundTripFunc

func TestWrapClientCachesGETResponses(t *testing.T) {
	t.Parallel()

	cacheDir := t.TempDir()
	callCount := 0
	client := WrapClient(&http.Client{
		Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			callCount++
			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     http.Header{"Content-Type": []string{"application/json"}},
				Body:       io.NopCloser(bytes.NewBufferString(`{"ok":true}`)),
			}, nil
		}),
	}, Config{Mode: ModeUse, Dir: cacheDir, TTL: time.Hour})

	for i := 0; i < 2; i++ {
		resp, err := client.Get("https://example.test/pkg/react")
		if err != nil {
			t.Fatalf("get response %d: %v", i, err)
		}
		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			t.Fatalf("read response %d: %v", i, err)
		}
		if string(body) != `{"ok":true}` {
			t.Fatalf("body %d = %q", i, string(body))
		}
	}

	if callCount != 1 {
		t.Fatalf("call count = %d", callCount)
	}
}

func TestWrapClientCachesPOSTResponses(t *testing.T) {
	t.Parallel()

	cacheDir := t.TempDir()
	callCount := 0
	client := WrapClient(&http.Client{
		Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			callCount++
			payload, err := io.ReadAll(req.Body)
			if err != nil {
				t.Fatalf("read request body: %v", err)
			}
			if string(payload) != `{"query":"pkg:npm/react@19.2.4"}` {
				t.Fatalf("request body = %q", string(payload))
			}
			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     http.Header{"Content-Type": []string{"application/json"}},
				Body:       io.NopCloser(bytes.NewBufferString(`{"results":[]}`)),
			}, nil
		}),
	}, Config{Mode: ModeUse, Dir: cacheDir, TTL: time.Hour})

	for i := 0; i < 2; i++ {
		req, err := http.NewRequest(http.MethodPost, "https://api.example.test/query", bytes.NewBufferString(`{"query":"pkg:npm/react@19.2.4"}`))
		if err != nil {
			t.Fatalf("new request %d: %v", i, err)
		}
		req.Header.Set("Content-Type", "application/json")
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("do request %d: %v", i, err)
		}
		_, _ = io.ReadAll(resp.Body)
		resp.Body.Close()
	}

	if callCount != 1 {
		t.Fatalf("call count = %d", callCount)
	}
}

func TestWrapClientRefreshBypassesCache(t *testing.T) {
	t.Parallel()

	cacheDir := t.TempDir()
	callCount := 0
	client := WrapClient(&http.Client{
		Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			callCount++
			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     make(http.Header),
				Body:       io.NopCloser(bytes.NewBufferString(`{"count":` + strconv.Itoa(callCount) + `}`)),
			}, nil
		}),
	}, Config{Mode: ModeRefresh, Dir: cacheDir, TTL: time.Hour})

	for i := 0; i < 2; i++ {
		resp, err := client.Get("https://example.test/pkg/react")
		if err != nil {
			t.Fatalf("get response %d: %v", i, err)
		}
		_, _ = io.ReadAll(resp.Body)
		resp.Body.Close()
	}

	if callCount != 2 {
		t.Fatalf("call count = %d", callCount)
	}
}

func TestWrapClientCacheOnlyUsesStoredResponse(t *testing.T) {
	t.Parallel()

	cacheDir := t.TempDir()
	warmClient := WrapClient(&http.Client{
		Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     make(http.Header),
				Body:       io.NopCloser(bytes.NewBufferString(`{"cached":true}`)),
			}, nil
		}),
	}, Config{Mode: ModeUse, Dir: cacheDir, TTL: time.Hour})

	resp, err := warmClient.Get("https://example.test/pkg/react")
	if err != nil {
		t.Fatalf("warm cache: %v", err)
	}
	resp.Body.Close()

	coldClient := WrapClient(&http.Client{
		Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			return nil, errors.New("network should not be used")
		}),
	}, Config{Mode: ModeCacheOnly, Dir: cacheDir, TTL: time.Hour})

	resp, err = coldClient.Get("https://example.test/pkg/react")
	if err != nil {
		t.Fatalf("cache-only get: %v", err)
	}
	body, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		t.Fatalf("read cache-only body: %v", err)
	}
	if string(body) != `{"cached":true}` {
		t.Fatalf("cache-only body = %q", string(body))
	}
}

func TestWrapClientCacheOnlyRejectsExpiredEntry(t *testing.T) {
	t.Parallel()

	cacheDir := t.TempDir()
	req, err := http.NewRequest(http.MethodGet, "https://example.test/pkg/react", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	info := requestInfo{method: http.MethodGet, url: req.URL.String(), bodyHash: sha256Hex(nil), varyHash: requestVaryHash(req)}
	path := cacheFilePath(cacheDir, info)
	if err := writeCache(path, cachedResponse{
		Method:            http.MethodGet,
		URL:               info.url,
		RequestBodySHA256: info.bodyHash,
		StatusCode:        http.StatusOK,
		Header:            make(http.Header),
		BodyBase64:        base64String(`{"cached":true}`),
		StoredAt:          time.Now().Add(-2 * time.Hour).UTC().Format(time.RFC3339),
	}); err != nil {
		t.Fatalf("write cache: %v", err)
	}

	client := WrapClient(&http.Client{
		Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			return nil, errors.New("network should not be used")
		}),
	}, Config{Mode: ModeCacheOnly, Dir: cacheDir, TTL: time.Hour})

	if _, err := client.Get("https://example.test/pkg/react"); err == nil {
		t.Fatal("expected expired cache error")
	}
}

func TestWrapClientUsesStaleCacheOnRateLimit(t *testing.T) {
	t.Parallel()

	cacheDir := t.TempDir()
	req, err := http.NewRequest(http.MethodGet, "https://example.test/pkg/react", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	info := requestInfo{method: http.MethodGet, url: req.URL.String(), bodyHash: sha256Hex(nil), varyHash: requestVaryHash(req)}
	path := cacheFilePath(cacheDir, info)
	if err := writeCache(path, cachedResponse{
		Method:            http.MethodGet,
		URL:               info.url,
		RequestBodySHA256: info.bodyHash,
		StatusCode:        http.StatusOK,
		Header:            make(http.Header),
		BodyBase64:        base64String(`{"cached":true}`),
		StoredAt:          time.Now().Add(-2 * time.Hour).UTC().Format(time.RFC3339),
	}); err != nil {
		t.Fatalf("write cache: %v", err)
	}

	client := WrapClient(&http.Client{
		Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusTooManyRequests,
				Header:     make(http.Header),
				Body:       io.NopCloser(bytes.NewBufferString(`rate limited`)),
			}, nil
		}),
	}, Config{Mode: ModeUse, Dir: cacheDir, TTL: time.Hour})

	resp, err := client.Get("https://example.test/pkg/react")
	if err != nil {
		t.Fatalf("use stale cache: %v", err)
	}
	body, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		t.Fatalf("read stale cache body: %v", err)
	}
	if string(body) != `{"cached":true}` {
		t.Fatalf("stale cache body = %q", string(body))
	}
}

func TestWrapClientSeparatesCacheEntriesByAuthorization(t *testing.T) {
	t.Parallel()

	cacheDir := t.TempDir()
	callCount := 0
	client := WrapClient(&http.Client{
		Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			callCount++
			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     make(http.Header),
				Body:       io.NopCloser(bytes.NewBufferString(req.Header.Get("Authorization"))),
			}, nil
		}),
	}, Config{Mode: ModeUse, Dir: cacheDir, TTL: time.Hour})

	requests := []string{"Bearer token-a", "Bearer token-b", "Bearer token-a"}
	for _, authorization := range requests {
		req, err := http.NewRequest(http.MethodGet, "https://api.example.test/resource", nil)
		if err != nil {
			t.Fatalf("new request: %v", err)
		}
		req.Header.Set("Authorization", authorization)
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("do request: %v", err)
		}
		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			t.Fatalf("read body: %v", err)
		}
		if string(body) != authorization {
			t.Fatalf("body = %q, want %q", string(body), authorization)
		}
	}

	if callCount != 2 {
		t.Fatalf("call count = %d", callCount)
	}
}

func TestWriteCacheUsesRestrictedPermissionsAndSanitizedHeaders(t *testing.T) {
	t.Parallel()

	cacheDir := t.TempDir()
	info := requestInfo{method: http.MethodGet, url: "https://example.test/pkg/react", bodyHash: sha256Hex(nil), varyHash: sha256Hex(nil)}
	path := cacheFilePath(cacheDir, info)
	if err := writeCache(path, cachedResponse{
		Method:            http.MethodGet,
		URL:               info.url,
		RequestBodySHA256: info.bodyHash,
		StatusCode:        http.StatusOK,
		Header: http.Header{
			"Content-Type": []string{"application/json"},
			"Set-Cookie":   []string{"secret=value"},
		},
		BodyBase64: base64String(`{"cached":true}`),
		StoredAt:   time.Now().UTC().Format(time.RFC3339),
	}); err != nil {
		t.Fatalf("write cache: %v", err)
	}

	record, err := readCache(path)
	if err != nil {
		t.Fatalf("read cache: %v", err)
	}
	if got := record.Header.Get("Set-Cookie"); got != "" {
		t.Fatalf("set-cookie = %q", got)
	}

	if runtime.GOOS != "windows" {
		stat, err := os.Stat(path)
		if err != nil {
			t.Fatalf("stat cache file: %v", err)
		}
		if stat.Mode().Perm()&0o077 != 0 {
			t.Fatalf("cache file perms = %o", stat.Mode().Perm())
		}
	}
}

func TestWrapClientWarnsWhenCacheWriteFails(t *testing.T) {
	t.Parallel()

	cacheParent := t.TempDir()
	cacheFile := filepath.Join(cacheParent, "not-a-directory")
	if err := os.WriteFile(cacheFile, []byte("occupied"), 0o644); err != nil {
		t.Fatalf("write occupied file: %v", err)
	}

	var warnings bytes.Buffer
	client := WrapClient(&http.Client{
		Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     make(http.Header),
				Body:       io.NopCloser(bytes.NewBufferString(`{"ok":true}`)),
			}, nil
		}),
	}, Config{Mode: ModeUse, Dir: cacheFile, TTL: time.Hour, WarningWriter: &warnings})

	resp, err := client.Get("https://example.test/pkg/react")
	if err != nil {
		t.Fatalf("get response: %v", err)
	}
	resp.Body.Close()

	if got := warnings.String(); !strings.Contains(got, "http cache write failed") {
		t.Fatalf("warnings = %q", got)
	}
}

func TestWrapClientInvokesRequestObserverOnCacheHit(t *testing.T) {
	t.Parallel()

	cacheDir := t.TempDir()
	observed := 0
	client := WrapClient(&http.Client{
		Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     make(http.Header),
				Body:       io.NopCloser(bytes.NewBufferString(`{"ok":true}`)),
			}, nil
		}),
	}, Config{
		Mode: ModeUse,
		Dir:  cacheDir,
		TTL:  time.Hour,
		RequestObserver: func(req *http.Request) {
			observed++
		},
	})

	for i := 0; i < 2; i++ {
		resp, err := client.Get("https://example.test/pkg/react")
		if err != nil {
			t.Fatalf("get response %d: %v", i, err)
		}
		resp.Body.Close()
	}

	if observed != 2 {
		t.Fatalf("observer count = %d", observed)
	}
}

func TestWrapClientInvokesRequestObserverWhenCacheDisabled(t *testing.T) {
	t.Parallel()

	observed := 0
	client := WrapClient(&http.Client{
		Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     make(http.Header),
				Body:       io.NopCloser(bytes.NewBufferString(`{"ok":true}`)),
			}, nil
		}),
	}, Config{
		Mode: ModeOff,
		RequestObserver: func(req *http.Request) {
			observed++
		},
	})

	resp, err := client.Get("https://example.test/pkg/react")
	if err != nil {
		t.Fatalf("get response: %v", err)
	}
	resp.Body.Close()

	if observed != 1 {
		t.Fatalf("observer count = %d", observed)
	}
}

func TestValidateConfigRejectsInvalidValues(t *testing.T) {
	t.Parallel()

	if err := ValidateConfig(Config{Mode: "weird"}); err == nil {
		t.Fatal("expected invalid mode error")
	}
	if err := ValidateConfig(Config{Mode: ModeUse, TTL: -time.Second}); err == nil {
		t.Fatal("expected invalid ttl error")
	}
}

func TestNormalizeConfigDefaultsDirAndMode(t *testing.T) {
	t.Parallel()

	cfg := NormalizeConfig(Config{})
	if cfg.Mode != ModeUse {
		t.Fatalf("mode = %q", cfg.Mode)
	}
	if filepath.Base(cfg.Dir) != "http-cache" {
		t.Fatalf("dir = %q", cfg.Dir)
	}
}

func base64String(value string) string {
	return base64.StdEncoding.EncodeToString([]byte(value))
}
