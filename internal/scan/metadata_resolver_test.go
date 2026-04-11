package scan

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"

	"depaudit-license/internal/externalaccess"
	"depaudit-license/internal/testutil"
)

type roundTripFunc = testutil.RoundTripFunc

func TestRequestJSONHandlesStatusAndTransportErrors(t *testing.T) {
	t.Parallel()

	if _, err := requestJSON(&http.Client{}, "://bad-url", externalaccess.Service{}); err == nil {
		t.Fatal("expected invalid URL error")
	}

	client := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		return nil, errors.New("boom")
	})}
	if _, err := requestJSON(client, "https://example.test", externalaccess.Service{}); err == nil {
		t.Fatal("expected transport error")
	}

	client = &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusBadGateway,
			Body:       io.NopCloser(strings.NewReader("bad gateway")),
			Header:     make(http.Header),
		}, nil
	})}
	if _, err := requestJSON(client, "https://example.test", externalaccess.Service{}); err == nil {
		t.Fatal("expected status error")
	}

	client = &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       testutil.ErrorBody(errors.New("read-failed")),
			Header:     make(http.Header),
		}, nil
	})}
	if _, err := requestJSON(client, "https://example.test", externalaccess.Service{}); err == nil {
		t.Fatal("expected body read error")
	}
}

func TestRequestJSONSetsAcceptAndUserAgentHeaders(t *testing.T) {
	t.Parallel()

	var gotUserAgent string
	var gotAccept string
	client := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		gotUserAgent = req.Header.Get("User-Agent")
		gotAccept = req.Header.Get("Accept")
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(strings.NewReader(`{"ok":true}`)),
			Header:     make(http.Header),
		}, nil
	})}

	body, err := requestJSON(client, "https://example.test/pkg/react", externalaccess.Service{})
	if err != nil {
		t.Fatalf("requestJSON: %v", err)
	}
	if string(body) != `{"ok":true}` {
		t.Fatalf("body = %q", string(body))
	}
	if gotUserAgent != "depaudit-license" {
		t.Fatalf("user agent = %q", gotUserAgent)
	}
	if gotAccept != "application/json" {
		t.Fatalf("accept = %q", gotAccept)
	}
}

func TestSanitizeVersionAndMakeNodePackageKey(t *testing.T) {
	t.Parallel()

	if got := sanitizeVersion("^1.2.3 "); got != "1.2.3" {
		t.Fatalf("sanitizeVersion = %q", got)
	}
	if got := sanitizeVersion(" >=1.2.3 "); got != "1.2.3" {
		t.Fatalf("sanitizeVersion comparator = %q", got)
	}
	if got := sanitizeVersion(" ~ 1.2.3 "); got != "1.2.3" {
		t.Fatalf("sanitizeVersion spaced comparator = %q", got)
	}
	if got := sanitizeVersion("  "); got != "" {
		t.Fatalf("sanitizeVersion blank = %q", got)
	}
	if got := makeNodePackageKey("react", "19.2.4"); got != "react@19.2.4" {
		t.Fatalf("makeNodePackageKey = %q", got)
	}
	if got := makeNodePackageKey("react", ""); got != "react" {
		t.Fatalf("makeNodePackageKey empty version = %q", got)
	}
	if !isExactNodeVersion("19.2.4") {
		t.Fatal("expected exact version")
	}
	if isExactNodeVersion("^19.0.0") {
		t.Fatal("expected range version to be non-exact")
	}
	if isExactNodeVersion("workspace:*") {
		t.Fatal("expected workspace version to be non-exact")
	}
	if isExactNodeVersion("file:../pkg") {
		t.Fatal("expected file version to be non-exact")
	}
	if isExactNodeVersion("  ") {
		t.Fatal("expected blank version to be non-exact")
	}
}

func TestNodeResolverResolveHelperBranches(t *testing.T) {
	t.Parallel()

	cached := metadata{RawLicense: "MIT", Source: "cache"}
	resolver := &nodeResolver{cache: map[string]metadata{"react@19.2.4": cached}}
	if got := resolver.resolve("react", "19.2.4", ""); got != cached {
		t.Fatalf("cached resolve = %#v", got)
	}

	resolver = &nodeResolver{cache: map[string]metadata{}, client: nil}
	got := resolver.resolve("react", "19.2.4", "")
	if got.Source != "fallback" || got.Holder != "react" || got.RawLicense != "Unknown" {
		t.Fatalf("nil client fallback = %#v", got)
	}

	resolver = &nodeResolver{cache: map[string]metadata{}, client: &http.Client{}}
	got = resolver.resolve("react", "^19.0.0", "")
	if got.Source != "fallback" || got.RawLicense != "Unknown" {
		t.Fatalf("range fallback = %#v", got)
	}
	if cached := resolver.cache["react@^19.0.0"]; cached.Source != "fallback" {
		t.Fatalf("cache after range fallback = %#v", cached)
	}

	client := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		payload, _ := json.Marshal(map[string]any{"license": map[string]string{"type": "MIT"}})
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(strings.NewReader(string(payload))),
			Header:     make(http.Header),
		}, nil
	})}
	resolver = &nodeResolver{cache: map[string]metadata{}, client: client, registryBaseURL: "https://registry.example.test"}
	got = resolver.resolve("react", "19.2.4", "")
	if got.Source != "npm-registry-version" || got.RawLicense != "MIT" {
		t.Fatalf("registry resolve = %#v", got)
	}
	if got.ArtifactResolution == nil || got.ArtifactResolution.Kind != "remote-metadata" || got.ArtifactResolution.Detail != "npm-registry-version" || !got.ArtifactResolution.ReviewRequired {
		t.Fatalf("artifact resolution = %#v", got.ArtifactResolution)
	}
	if cached := resolver.cache["react@19.2.4"]; cached.Source != "npm-registry-version" {
		t.Fatalf("cache after registry resolve = %#v", cached)
	}

	client = &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(strings.NewReader("{invalid")),
			Header:     make(http.Header),
		}, nil
	})}
	resolver = &nodeResolver{cache: map[string]metadata{}, client: client, registryBaseURL: "https://registry.example.test"}
	got = resolver.resolve("react", "19.2.4", "")
	if got.Source != "fallback" || got.RawLicense != "Unknown" {
		t.Fatalf("invalid json fallback = %#v", got)
	}
}

func TestNodeResolverResolveBuildsEscapedEndpointAndNormalizesPartialRegistryMetadata(t *testing.T) {
	t.Parallel()

	var gotPath string
	var gotUserAgent string
	resolver := &nodeResolver{
		cache:           map[string]metadata{},
		registryBaseURL: "https://registry.example.test/",
		client: &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			gotPath = req.URL.String()
			gotUserAgent = req.Header.Get("User-Agent")
			payload, _ := json.Marshal(map[string]any{
				"license":      "",
				"homepage":     "https://pkg.example.test/home",
				"contributors": []map[string]string{{"name": "Maintainer Name"}},
			})
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(strings.NewReader(string(payload))),
				Header:     make(http.Header),
			}, nil
		})},
	}

	got := resolver.resolve("@scope/pkg", "1.2.3", "")
	if gotPath != "https://registry.example.test/@scope%2Fpkg/1.2.3" {
		t.Fatalf("request path = %q", gotPath)
	}
	if gotUserAgent != "depaudit-license" {
		t.Fatalf("user agent = %q", gotUserAgent)
	}
	if got.Source != "npm-registry-version" {
		t.Fatalf("source = %q", got.Source)
	}
	if got.ArtifactResolution == nil || got.ArtifactResolution.Kind != "remote-metadata" || !got.ArtifactResolution.ReviewRequired {
		t.Fatalf("artifact resolution = %#v", got.ArtifactResolution)
	}
	if got.RawLicense != "Unknown" {
		t.Fatalf("raw license = %q", got.RawLicense)
	}
	if got.Homepage != "https://pkg.example.test/home" {
		t.Fatalf("homepage = %q", got.Homepage)
	}
	if got.Holder != "Maintainer Name" {
		t.Fatalf("holder = %q", got.Holder)
	}
}
