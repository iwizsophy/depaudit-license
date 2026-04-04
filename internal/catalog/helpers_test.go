package catalog

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"depaudit-license/internal/testutil"
)

func setTestNow(t *testing.T, instant time.Time) {
	t.Helper()
	previous := now
	now = func() time.Time { return instant }
	t.Cleanup(func() {
		now = previous
	})
}

func TestBuildLoadResultCapturesSnapshotAndMetadata(t *testing.T) {
	t.Parallel()

	cat := &Catalog{Fallback: "Unknown"}
	snapshot := fileFormat{
		Fallback: "Unknown",
		Licenses: []Definition{{
			Key:              "MIT",
			Name:             "MIT License",
			Family:           "MIT",
			CopyleftStrength: "none",
			RiskLevel:        "low",
			SPDXIDs:          []string{"MIT"},
		}},
	}
	sources := []SourceMetadata{{Kind: "file", Location: "licenses.json", PinningMode: "implicit", ContentSHA256: "abc"}}

	result := buildLoadResult(cat, snapshot, sources)
	if result.Catalog != cat {
		t.Fatal("expected catalog pointer to be preserved")
	}
	if len(result.SourceMetadata) != 1 || result.SourceMetadata[0].Location != "licenses.json" {
		t.Fatalf("source metadata = %#v", result.SourceMetadata)
	}
	if !strings.Contains(string(result.EffectiveCatalog), `"fallback":"Unknown"`) {
		t.Fatalf("effective catalog = %s", string(result.EffectiveCatalog))
	}
}

func TestCatalogCacheHelpers(t *testing.T) {
	t.Parallel()
	setTestNow(t, time.Date(2026, time.April, 4, 9, 0, 0, 0, time.UTC))

	payload := []byte(`{"fallback":"Unknown","licenses":[{"key":"Unknown","name":"Unknown","family":"Unknown","copyleft_strength":"unknown","requires_manual_review":true,"spdx_ids":["Unknown"],"contains":["unknown"],"risk_level":"unknown"}]}`)

	metadata := SourceMetadata{
		Kind:            "remote",
		Location:        "https://example.test/licenses.json",
		DisplayLocation: "licenses.json",
		ResolvedURL:     "https://example.test/licenses.json",
		PinningMode:     "pinned",
		RequestedSHA256: "",
		ContentSHA256:   sha256Hex(payload),
		RetrievedAt:     "2026-04-03T00:00:00Z",
		ETag:            "v1",
		Revision:        "r1",
	}

	if err := writeRemoteCatalogCache("", metadata, payload); err != nil {
		t.Fatalf("writeRemoteCatalogCache disabled: %v", err)
	}
	if err := writeRemoteCatalogCache(" \t ", metadata, payload); err != nil {
		t.Fatalf("writeRemoteCatalogCache whitespace-disabled: %v", err)
	}

	cacheDir := t.TempDir()
	if err := writeRemoteCatalogCache(cacheDir, metadata, payload); err != nil {
		t.Fatalf("writeRemoteCatalogCache: %v", err)
	}

	spec, err := parseSourceSpec(metadata.Location)
	if err != nil {
		t.Fatalf("parseSourceSpec: %v", err)
	}

	cachedPayload, cachedMetadata, err := readRemoteCatalogCache(cacheDir, spec)
	if err != nil {
		t.Fatalf("readRemoteCatalogCache: %v", err)
	}
	if string(cachedPayload) != string(payload) {
		t.Fatalf("cached payload = %q", string(cachedPayload))
	}
	if cachedMetadata.CacheStatus != "stale-cache" {
		t.Fatalf("cache status = %q", cachedMetadata.CacheStatus)
	}
	if cachedMetadata.DisplayLocation != metadata.DisplayLocation {
		t.Fatalf("display location = %q", cachedMetadata.DisplayLocation)
	}

	filePath := cacheFilePath(cacheDir, metadata.Location)
	rawRecord, err := os.ReadFile(filePath)
	if err != nil {
		t.Fatalf("read cache record: %v", err)
	}

	var record cachedRemoteCatalog
	if err := json.Unmarshal(rawRecord, &record); err != nil {
		t.Fatalf("unmarshal cache record: %v", err)
	}
	record.DisplaySource = ""
	record.PayloadBase64 = base64.StdEncoding.EncodeToString(payload)
	record.ContentSHA256 = sha256Hex(payload)

	serialized, err := json.Marshal(record)
	if err != nil {
		t.Fatalf("marshal cache record: %v", err)
	}
	if err := os.WriteFile(filePath, serialized, 0o644); err != nil {
		t.Fatalf("rewrite cache record: %v", err)
	}

	_, cachedMetadata, err = readRemoteCatalogCache(cacheDir, spec)
	if err != nil {
		t.Fatalf("read cache record with empty display source: %v", err)
	}
	if cachedMetadata.DisplayLocation != metadata.Location {
		t.Fatalf("display location fallback = %q", cachedMetadata.DisplayLocation)
	}

	blockingFile := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(blockingFile, []byte("x"), 0o644); err != nil {
		t.Fatalf("write blocking file: %v", err)
	}
	if err := writeRemoteCatalogCache(blockingFile, metadata, payload); err == nil {
		t.Fatal("expected writeRemoteCatalogCache mkdir error")
	}
}

func TestReadRemoteCatalogCacheRejectsInvalidRecords(t *testing.T) {
	t.Parallel()

	cacheDir := t.TempDir()
	spec, err := parseSourceSpec("https://example.test/licenses.json#sha256=deadbeef")
	if err != nil {
		t.Fatalf("parseSourceSpec: %v", err)
	}

	if _, _, err := readRemoteCatalogCache("", spec); err == nil {
		t.Fatal("expected disabled cache error")
	}
	if _, _, err := readRemoteCatalogCache(cacheDir, spec); err == nil {
		t.Fatal("expected missing cache file error")
	}

	filePath := cacheFilePath(cacheDir, spec.OriginalURL)
	if err := os.WriteFile(filePath, []byte("{"), 0o644); err != nil {
		t.Fatalf("write invalid json: %v", err)
	}
	if _, _, err := readRemoteCatalogCache(cacheDir, spec); err == nil {
		t.Fatal("expected invalid json error")
	}

	record := cachedRemoteCatalog{
		Source:        spec.OriginalURL,
		ResolvedURL:   spec.RequestURL,
		ContentSHA256: "deadbeef",
		PayloadBase64: "%%%bad-base64%%%",
	}
	serialized, err := json.Marshal(record)
	if err != nil {
		t.Fatalf("marshal invalid base64 record: %v", err)
	}
	if err := os.WriteFile(filePath, serialized, 0o644); err != nil {
		t.Fatalf("write invalid base64 record: %v", err)
	}
	if _, _, err := readRemoteCatalogCache(cacheDir, spec); err == nil {
		t.Fatal("expected invalid base64 error")
	}

	record.PayloadBase64 = base64.StdEncoding.EncodeToString([]byte("payload"))
	serialized, err = json.Marshal(record)
	if err != nil {
		t.Fatalf("marshal mismatched hash record: %v", err)
	}
	if err := os.WriteFile(filePath, serialized, 0o644); err != nil {
		t.Fatalf("write mismatched hash record: %v", err)
	}
	if _, _, err := readRemoteCatalogCache(cacheDir, spec); err == nil || !strings.Contains(err.Error(), "payload hash mismatch") {
		t.Fatalf("expected payload hash mismatch, got %v", err)
	}

	record.PayloadBase64 = base64.StdEncoding.EncodeToString([]byte("payload"))
	record.ContentSHA256 = sha256Hex([]byte("payload"))
	serialized, err = json.Marshal(record)
	if err != nil {
		t.Fatalf("marshal pinned mismatch record: %v", err)
	}
	if err := os.WriteFile(filePath, serialized, 0o644); err != nil {
		t.Fatalf("write pinned mismatch record: %v", err)
	}
	if _, _, err := readRemoteCatalogCache(cacheDir, spec); err == nil || !strings.Contains(err.Error(), "sha256 mismatch") {
		t.Fatalf("expected sha256 mismatch, got %v", err)
	}
}

func TestCatalogLoadHelpers(t *testing.T) {
	t.Parallel()

	if err := validateLoadOptions(LoadOptions{RemoteCatalogMode: "mystery"}); err == nil {
		t.Fatal("expected invalid remote catalog mode")
	}

	dir := t.TempDir()
	path := filepath.Join(dir, "licenses.json")
	if _, _, _, err := loadCatalogPayload(LoadOptions{}, path); err == nil {
		t.Fatal("expected local read error")
	}

	if _, _, _, err := loadFileFormatFromSource(LoadOptions{}, path); err == nil {
		t.Fatal("expected loadFileFormatFromSource read error")
	}

	if err := os.WriteFile(path, []byte("{"), 0o644); err != nil {
		t.Fatalf("write invalid catalog: %v", err)
	}
	if _, _, _, err := loadFileFormatFromSource(LoadOptions{}, path); err == nil || !strings.Contains(err.Error(), "parse catalog JSON") {
		t.Fatalf("expected parse error, got %v", err)
	}

	if err := os.WriteFile(path, []byte(`{"fallback":"Unknown","licenses":[]}`), 0o644); err != nil {
		t.Fatalf("write empty catalog: %v", err)
	}
	if _, _, _, err := loadFileFormatFromSource(LoadOptions{}, path); err == nil || !strings.Contains(err.Error(), "is empty") {
		t.Fatalf("expected empty catalog error, got %v", err)
	}

	spec, err := parseSourceSpec("https://example.test/licenses.json#sha256=abc123")
	if err != nil {
		t.Fatalf("parseSourceSpec remote: %v", err)
	}
	if spec.RequestURL != "https://example.test/licenses.json" {
		t.Fatalf("request url = %q", spec.RequestURL)
	}
	if spec.RequestedSHA256 != "abc123" {
		t.Fatalf("requested sha256 = %q", spec.RequestedSHA256)
	}

	localSpec, err := parseSourceSpec(" licenses.json ")
	if err != nil {
		t.Fatalf("parseSourceSpec local: %v", err)
	}
	if localSpec.RequestURL != "licenses.json" {
		t.Fatalf("local request url = %q", localSpec.RequestURL)
	}
	missingHostSpec, err := parseSourceSpec("http:///licenses.json#sha256=abc123")
	if err != nil {
		t.Fatalf("parseSourceSpec missing host: %v", err)
	}
	if missingHostSpec.RequestURL != "http:///licenses.json#sha256=abc123" || missingHostSpec.RequestedSHA256 != "" {
		t.Fatalf("missing host spec = %#v", missingHostSpec)
	}
	unsupportedSchemeSpec, err := parseSourceSpec("ftp://example.test/licenses.json#sha256=abc123")
	if err != nil {
		t.Fatalf("parseSourceSpec unsupported scheme: %v", err)
	}
	if unsupportedSchemeSpec.RequestURL != "ftp://example.test/licenses.json#sha256=abc123" || unsupportedSchemeSpec.RequestedSHA256 != "" {
		t.Fatalf("unsupported scheme spec = %#v", unsupportedSchemeSpec)
	}

	noHashSpec, err := parseSourceSpec("https://example.test/licenses.json#etag=v1")
	if err != nil {
		t.Fatalf("parseSourceSpec non-sha fragment: %v", err)
	}
	if noHashSpec.RequestedSHA256 != "" {
		t.Fatalf("unexpected requested sha256 = %q", noHashSpec.RequestedSHA256)
	}
	semicolonSpec, err := parseSourceSpec("https://example.test/licenses.json#sha256=abc123;etag=v1")
	if err != nil {
		t.Fatalf("parseSourceSpec semicolon fragment: %v", err)
	}
	if semicolonSpec.RequestedSHA256 != "abc123" {
		t.Fatalf("semicolon requested sha256 = %q", semicolonSpec.RequestedSHA256)
	}

	if !isRemoteSource("https://example.test/licenses.json") {
		t.Fatal("expected remote source")
	}
	if isRemoteSource("http:///missing-host") {
		t.Fatal("expected missing host to be non-remote")
	}
	if isRemoteSource("://bad-url") {
		t.Fatal("expected invalid url to be non-remote")
	}

	if err := validateRemoteContentType(""); err != nil {
		t.Fatalf("validateRemoteContentType empty: %v", err)
	}
	if err := validateRemoteContentType("application/octet-stream"); err != nil {
		t.Fatalf("validateRemoteContentType octet-stream: %v", err)
	}
	if err := validateRemoteContentType(" text/html; charset=utf-8 "); err == nil || !strings.Contains(err.Error(), "unexpected content type") {
		t.Fatalf("expected html content type error, got %v", err)
	}
	if err := validateRemoteContentType("application/xml"); err != nil {
		t.Fatalf("validateRemoteContentType xml: %v", err)
	}
}

func TestDefaultRemoteCatalogCacheDirFallsBackToTempDir(t *testing.T) {
	t.Setenv("LocalAppData", "")
	t.Setenv("AppData", "")
	t.Setenv("XDG_CACHE_HOME", "")

	got := defaultRemoteCatalogCacheDir()
	wantSuffix := filepath.Join("depaudit-license", "catalog-cache")
	if !strings.HasSuffix(got, wantSuffix) {
		t.Fatalf("defaultRemoteCatalogCacheDir = %q, want suffix %q", got, wantSuffix)
	}
	if !filepath.IsAbs(got) {
		t.Fatalf("defaultRemoteCatalogCacheDir should be absolute: %q", got)
	}
}

func TestNowRFC3339UsesPackageClockSeam(t *testing.T) {
	t.Parallel()
	setTestNow(t, time.Date(2026, time.April, 4, 10, 30, 0, 0, time.UTC))

	if got := nowRFC3339(); got != "2026-04-04T10:30:00Z" {
		t.Fatalf("nowRFC3339 = %q", got)
	}
}

func TestCatalogFetchHelpers(t *testing.T) {
	t.Parallel()

	if _, _, _, err := fetchRemoteCatalog(LoadOptions{}, "http://127.0.0.1:1/%zz"); err == nil {
		t.Fatal("expected fetchRemoteCatalog parse error")
	}

	cacheDir := t.TempDir()
	blockingFile := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(blockingFile, []byte("x"), 0o644); err != nil {
		t.Fatalf("write blocking file: %v", err)
	}

	httpServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"fallback":"Unknown","licenses":[{"key":"Unknown","name":"Unknown","family":"Unknown","copyleft_strength":"unknown","requires_manual_review":true,"spdx_ids":["Unknown"],"contains":["unknown"],"risk_level":"unknown"}]}`))
	}))
	defer httpServer.Close()

	if _, _, _, err := fetchRemoteCatalog(LoadOptions{
		Client:            httpServer.Client(),
		RemoteCatalogMode: RemoteCatalogModeFailFast,
		CacheDir:          blockingFile,
	}, httpServer.URL); err == nil || !strings.Contains(err.Error(), "write remote catalog cache") {
		t.Fatalf("expected cache write error, got %v", err)
	}

	if _, _, _, err := fetchRemoteCatalog(LoadOptions{
		Client:            httpServer.Client(),
		RemoteCatalogMode: RemoteCatalogModeStaleFallback,
		CacheDir:          blockingFile,
	}, httpServer.URL); err != nil {
		t.Fatalf("expected stale fallback mode to ignore cache write error: %v", err)
	}

	if _, _, _, err := fetchRemoteCatalog(LoadOptions{
		Client:            httpServer.Client(),
		RemoteCatalogMode: RemoteCatalogModeStaleFallback,
		CacheDir:          cacheDir,
	}, "http://127.0.0.1:1/licenses.json"); err == nil {
		t.Fatal("expected network error when stale cache is unavailable")
	}

	if _, _, err := fetchRemoteCatalogFromNetwork(http.DefaultClient, sourceSpec{
		RequestURL: "http://127.0.0.1:1/%zz",
	}, "broken"); err == nil || !strings.Contains(err.Error(), "build catalog request") {
		t.Fatalf("expected build request error, got %v", err)
	}

	statusServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "nope", http.StatusBadGateway)
	}))
	defer statusServer.Close()
	if _, _, err := fetchRemoteCatalogFromNetwork(statusServer.Client(), sourceSpec{RequestURL: statusServer.URL}, statusServer.URL); err == nil || !strings.Contains(err.Error(), "unexpected status") {
		t.Fatalf("expected unexpected status error, got %v", err)
	}

	bodyErrClient := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     http.Header{"Content-Type": []string{"application/json"}},
			Body:       testutil.ErrorBody(errors.New("boom")),
		}, nil
	})}
	if _, _, err := fetchRemoteCatalogFromNetwork(bodyErrClient, sourceSpec{RequestURL: "https://example.test/licenses.json"}, "https://example.test/licenses.json"); err == nil || !strings.Contains(err.Error(), "read catalog") {
		t.Fatalf("expected body read error, got %v", err)
	}
}

func TestFetchRemoteCatalogUsesDefaultClientAndCapturesPreferredRevisionHeaders(t *testing.T) {
	t.Parallel()

	var gotUserAgent string
	var gotAccept string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotUserAgent = r.Header.Get("User-Agent")
		gotAccept = r.Header.Get("Accept")
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.Header().Set("ETag", `"catalog-v1"`)
		w.Header().Set("X-Revision", "revision-from-header")
		w.Header().Set("Last-Modified", "Fri, 04 Apr 2026 09:00:00 GMT")
		_, _ = w.Write([]byte(`{"fallback":"Unknown","licenses":[{"key":"Unknown","name":"Unknown","family":"Unknown","copyleft_strength":"unknown","requires_manual_review":true,"spdx_ids":["Unknown"],"contains":["unknown"],"risk_level":"unknown"}]}`))
	}))
	defer server.Close()

	payload, sourceName, metadata, err := fetchRemoteCatalog(LoadOptions{
		CacheDir: t.TempDir(),
	}, server.URL+"/licenses.json")
	if err != nil {
		t.Fatalf("fetchRemoteCatalog: %v", err)
	}

	if sourceName != server.URL+"/licenses.json" {
		t.Fatalf("source name = %q", sourceName)
	}
	if gotUserAgent != "depaudit-license" {
		t.Fatalf("user agent = %q", gotUserAgent)
	}
	if !strings.Contains(gotAccept, "application/json") {
		t.Fatalf("accept = %q", gotAccept)
	}
	if metadata.ETag != `"catalog-v1"` {
		t.Fatalf("etag = %q", metadata.ETag)
	}
	if metadata.Revision != "revision-from-header" {
		t.Fatalf("revision = %q", metadata.Revision)
	}
	if metadata.ResolvedURL != server.URL+"/licenses.json" {
		t.Fatalf("resolved url = %q", metadata.ResolvedURL)
	}
	if metadata.ContentSHA256 != sha256Hex(payload) {
		t.Fatalf("content sha256 = %q", metadata.ContentSHA256)
	}
}

func TestCatalogLookupAndMatcherHelpers(t *testing.T) {
	t.Parallel()

	cat := loadCatalogFixture(t, `{
  "fallback": "Unknown",
  "licenses": [
    {
      "key": "MIT",
      "name": "MIT License",
      "family": "MIT",
      "version": "",
      "copyleft_strength": "none",
      "requires_manual_review": false,
      "spdx_ids": ["MIT"],
      "names": [],
      "exact_urls": [],
      "url_prefixes": [],
      "contains": ["opensource.org/licenses/mit"],
      "description": "desc",
      "obligations": ["notice"],
      "permissions": ["commercial"],
      "limitations": ["warranty"],
      "color": "#2f855a",
      "risk_level": "low",
      "notice_template": "template"
    },
    {
      "key": "Unknown",
      "name": "Unknown",
      "family": "Unknown",
      "version": "",
      "copyleft_strength": "unknown",
      "requires_manual_review": true,
      "spdx_ids": ["unknown"],
      "names": [],
      "exact_urls": [],
      "url_prefixes": [],
      "contains": [],
      "description": "desc",
      "obligations": ["review"],
      "permissions": ["unknown"],
      "limitations": ["unknown"],
      "color": "#718096",
      "risk_level": "unknown",
      "notice_template": "template"
    }
  ]
}`)

	if got := cat.Lookup("missing"); got.Key != "Unknown" {
		t.Fatalf("Lookup fallback = %q", got.Key)
	}

	raw := &Catalog{
		Fallback:    "Unknown",
		Definitions: map[string]Definition{"Unknown": {Key: "Unknown"}},
		exact:       map[string]string{},
	}
	raw.registerExact("   ", "ignored")
	raw.registerExact("\"MIT_License\"", "mit")
	raw.registerContains("abc", "ignored")
	if got := raw.exact["mit-license"]; got != "mit" {
		t.Fatalf("registerExact should normalize keys, got %q", got)
	}
	if len(raw.contains) != 0 {
		t.Fatalf("unexpected contains matchers: %#v", raw.contains)
	}

	candidates := normalizationCandidates("(MIT)")
	if len(candidates) < 2 {
		t.Fatalf("expected paren-trimmed candidates, got %#v", candidates)
	}

	candidates = normalizationCandidates(` "GPL-2.0-only" WITH Classpath-exception-2.0 `)
	if len(candidates) < 2 {
		t.Fatalf("expected quoted/WITH candidates, got %#v", candidates)
	}
	candidates = normalizationCandidates("MIT with Exception with Exception")
	if len(candidates) < 2 {
		t.Fatalf("expected duplicate-pruned WITH candidates, got %#v", candidates)
	}
	candidates = normalizationCandidates("https://example.test/license?id=1#top")
	if len(candidates) < 2 {
		t.Fatalf("expected url normalization candidates, got %#v", candidates)
	}
	if got := normalizationCandidates("   "); got != nil {
		t.Fatalf("expected nil candidates for blank input, got %#v", got)
	}

	raw.registerContains("abcd", "accepted")
	if len(raw.contains) != 1 || raw.contains[0].key != "accepted" {
		t.Fatalf("expected accepted contains matcher, got %#v", raw.contains)
	}
	raw.registerContains("'ABCD'", "normalized")
	if len(raw.contains) != 2 || raw.contains[1].alias != "abcd" || raw.contains[1].key != "normalized" {
		t.Fatalf("expected normalized contains matcher, got %#v", raw.contains)
	}

	longestWins, err := newCatalog(fileFormat{
		Fallback: "Unknown",
		Licenses: []Definition{
			{
				Key:              "MIT",
				Name:             "MIT License",
				Family:           "MIT",
				CopyleftStrength: "none",
				RiskLevel:        "low",
				SPDXIDs:          []string{"MIT"},
				Contains:         []string{"mit"},
			},
			{
				Key:              "MIT-URL",
				Name:             "MIT URL License",
				Family:           "MIT",
				CopyleftStrength: "none",
				RiskLevel:        "low",
				SPDXIDs:          []string{"MIT-URL"},
				Contains:         []string{"licenses.example.test/mit"},
			},
			{
				Key:                  "Unknown",
				Name:                 "Unknown",
				Family:               "Unknown",
				CopyleftStrength:     "unknown",
				RequiresManualReview: true,
				RiskLevel:            "unknown",
				SPDXIDs:              []string{"Unknown"},
			},
		},
	})
	if err != nil {
		t.Fatalf("newCatalog longest matcher fixture: %v", err)
	}
	if got, _ := longestWins.Normalize("https://licenses.example.test/MIT"); got != "MIT-URL" {
		t.Fatalf("expected longest contains matcher to win, got %q", got)
	}
}

func TestTextBundleHelpers(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "license-texts.ja.json")
	if err := os.WriteFile(path, []byte("{"), 0o644); err != nil {
		t.Fatalf("write invalid bundle: %v", err)
	}
	if _, err := LoadTextBundle(path); err == nil || !strings.Contains(err.Error(), "parse text bundle JSON") {
		t.Fatalf("expected bundle parse error, got %v", err)
	}

	if mapsClone(nil) != nil {
		t.Fatal("expected nil map clone")
	}

	source := map[string]string{"a": "1"}
	clone := mapsClone(source)
	clone["a"] = "2"
	if source["a"] != "1" {
		t.Fatalf("source map mutated: %#v", source)
	}

	if err := validateLocalizedText(LocalizedText{Description: "x", Obligations: []string{"a"}, Permissions: []string{"b"}, Limitations: []string{"c"}}); err == nil || !strings.Contains(err.Error(), "key is empty") {
		t.Fatalf("expected empty key error, got %v", err)
	}
}

func TestCatalogValidationAndConstructionHelpers(t *testing.T) {
	t.Parallel()

	if err := validateAbsoluteURL(" https://example.test/license "); err != nil {
		t.Fatalf("validateAbsoluteURL trimmed: %v", err)
	}
	if err := validateAbsoluteURL("ftp://mirror.example.test/license"); err != nil {
		t.Fatalf("validateAbsoluteURL ftp absolute: %v", err)
	}
	if err := validateAbsoluteURL("https:///missing-host"); err == nil || !strings.Contains(err.Error(), "invalid absolute url") {
		t.Fatalf("expected missing host error, got %v", err)
	}
	if err := validateAbsoluteURL("https://[::1"); err == nil || !strings.Contains(err.Error(), "invalid url") {
		t.Fatalf("expected parse failure, got %v", err)
	}

	if _, err := newCatalog(fileFormat{
		Fallback: "",
		Licenses: []Definition{{
			Key:              "MIT",
			Name:             "MIT License",
			Family:           "MIT",
			CopyleftStrength: "none",
			RiskLevel:        "low",
			SPDXIDs:          []string{"MIT"},
		}},
	}); err == nil || !strings.Contains(err.Error(), "fallback is empty") {
		t.Fatalf("expected empty fallback error, got %v", err)
	}

	if _, err := newCatalog(fileFormat{
		Fallback: "MIT",
		Licenses: []Definition{
			{
				Key:              "MIT",
				Name:             "MIT License",
				Family:           "MIT",
				CopyleftStrength: "none",
				RiskLevel:        "low",
				SPDXIDs:          []string{"MIT"},
			},
			{
				Key:              "MIT",
				Name:             "MIT License Duplicate",
				Family:           "MIT",
				CopyleftStrength: "none",
				RiskLevel:        "low",
				SPDXIDs:          []string{"MIT-DUP"},
			},
		},
	}); err == nil || !strings.Contains(err.Error(), "duplicate license definition key") {
		t.Fatalf("expected duplicate key error, got %v", err)
	}
}

type roundTripFunc = testutil.RoundTripFunc
