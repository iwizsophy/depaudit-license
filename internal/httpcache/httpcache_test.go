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

func TestWrapClientRejectsOversizedResponseBeforeCaching(t *testing.T) {
	t.Parallel()

	cacheDir := t.TempDir()
	callCount := 0
	client := WrapClient(&http.Client{
		Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			callCount++
			return &http.Response{
				StatusCode:    http.StatusOK,
				ContentLength: 32,
				Header:        make(http.Header),
				Body:          io.NopCloser(bytes.NewBufferString(`{"payload":"01234567890123456789"}`)),
			}, nil
		}),
	}, Config{Mode: ModeUse, Dir: cacheDir, TTL: time.Hour, MaxResponseBytes: 16})

	if _, err := client.Get("https://example.test/pkg/react"); err == nil {
		t.Fatal("expected oversized response error")
	}
	if callCount != 1 {
		t.Fatalf("call count = %d", callCount)
	}

	req, err := http.NewRequest(http.MethodGet, "https://example.test/pkg/react", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	info, ok, err := cacheableRequestInfo(req)
	if err != nil || !ok {
		t.Fatalf("cacheableRequestInfo = %#v %v %v", info, ok, err)
	}
	if _, err := readCache(cacheFilePath(cacheDir, info)); err == nil {
		t.Fatal("expected no cache entry to be written")
	}
}

func TestWrapClientUsesRequestSpecificMaxResponseBytes(t *testing.T) {
	t.Parallel()

	client := WrapClient(&http.Client{
		Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     make(http.Header),
				Body:       io.NopCloser(bytes.NewBufferString(`123456789`)),
			}, nil
		}),
	}, Config{Mode: ModeUse, Dir: t.TempDir(), TTL: time.Hour, MaxResponseBytes: 64})

	req, err := http.NewRequest(http.MethodGet, "https://example.test/pkg/react", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req = WithMaxResponseBytes(req, 8)
	if _, err := client.Do(req); err == nil {
		t.Fatal("expected request-specific response limit error")
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

func TestWrapClientNilClientAndUnsupportedRequestsBypassCache(t *testing.T) {
	t.Parallel()

	client := WrapClient(nil, Config{Mode: ModeUse, Dir: t.TempDir(), TTL: time.Hour})
	if client == nil || client.Transport == nil {
		t.Fatalf("wrapped client = %#v", client)
	}

	if info, ok, err := cacheableRequestInfo(nil); err != nil || ok || info.method != "" {
		t.Fatalf("nil request info = %#v %v %v", info, ok, err)
	}

	req, err := http.NewRequest(http.MethodPut, "https://example.test/pkg/react", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	if _, ok, err := cacheableRequestInfo(req); err != nil || ok {
		t.Fatalf("put request should bypass cache: %v %v", ok, err)
	}

	req, err = http.NewRequest(http.MethodGet, "ftp://example.test/pkg/react", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	if _, ok, err := cacheableRequestInfo(req); err != nil || ok {
		t.Fatalf("ftp request should bypass cache: %v %v", ok, err)
	}

	req = &http.Request{Method: http.MethodGet}
	if _, ok, err := cacheableRequestInfo(req); err != nil || ok {
		t.Fatalf("nil URL request should bypass cache: %v %v", ok, err)
	}
}

func TestReadRequestBodyAndCacheHelpersHandleErrorPaths(t *testing.T) {
	t.Parallel()

	if body, err := readRequestBody(nil); err != nil || body != nil {
		t.Fatalf("nil request body = %#v %v", body, err)
	}

	req, err := http.NewRequest(http.MethodPost, "https://example.test/query", bytes.NewBufferString(`{"q":1}`))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.GetBody = func() (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewBufferString(`{"q":1}`)), nil
	}
	body, err := readRequestBody(req)
	if err != nil || string(body) != `{"q":1}` {
		t.Fatalf("getbody request body = %q %v", string(body), err)
	}

	req, err = http.NewRequest(http.MethodPost, "https://example.test/query", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Body = io.NopCloser(bytes.NewBuffer(nil))
	req.GetBody = func() (io.ReadCloser, error) {
		return nil, errors.New("boom")
	}
	if _, err := readRequestBody(req); err == nil {
		t.Fatal("expected getbody error")
	}

	req, err = http.NewRequest(http.MethodPost, "https://example.test/query", bytes.NewBufferString(`{"q":2}`))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.GetBody = nil
	body, err = readRequestBody(req)
	if err != nil || string(body) != `{"q":2}` {
		t.Fatalf("read body path = %q %v", string(body), err)
	}

	path := filepath.Join(t.TempDir(), "broken.json")
	if err := os.WriteFile(path, []byte("{not-json"), 0o644); err != nil {
		t.Fatalf("write broken cache: %v", err)
	}
	if _, err := readCache(path); err == nil {
		t.Fatal("expected invalid cache json error")
	}

	if _, err := responseFromCache(cachedResponse{BodyBase64: "%%%invalid%%%"}, req); err == nil {
		t.Fatal("expected invalid base64 error")
	}
	if !isExpired(cachedResponse{StoredAt: "not-a-time"}, time.Hour) {
		t.Fatal("expected invalid timestamp to be expired")
	}

	writeWarning(nil, "ignored %s", "warning")
}

func TestDefaultDirAndVaryHashHelpers(t *testing.T) {
	t.Parallel()

	if got := DefaultDir(); filepath.Base(got) != "http-cache" {
		t.Fatalf("DefaultDir = %q", got)
	}
	if got := requestVaryHash(nil); got == "" {
		t.Fatal("expected nil request vary hash")
	}

	reqA, err := http.NewRequest(http.MethodGet, "https://example.test", nil)
	if err != nil {
		t.Fatalf("new request A: %v", err)
	}
	reqA.Header.Set("Authorization", "Bearer token-a")
	reqA.Header.Set("Content-Type", "application/json")

	reqB, err := http.NewRequest(http.MethodGet, "https://example.test", nil)
	if err != nil {
		t.Fatalf("new request B: %v", err)
	}
	reqB.Header.Set("Authorization", "Bearer token-b")
	reqB.Header.Set("Content-Type", "application/json")

	if requestVaryHash(reqA) == requestVaryHash(reqB) {
		t.Fatal("expected secret-sensitive vary hash to change")
	}
	if hashSecretHeader("") != "" {
		t.Fatal("expected empty secret hash")
	}
}

func TestWriteCacheIgnoresBlankPath(t *testing.T) {
	t.Parallel()

	err := writeCache("", cachedResponse{StatusCode: http.StatusOK})
	if err != nil {
		t.Fatalf("writeCache blank path: %v", err)
	}
}

func base64String(value string) string {
	return base64.StdEncoding.EncodeToString([]byte(value))
}
