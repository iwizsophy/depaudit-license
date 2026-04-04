package scan

import (
	"errors"
	"path/filepath"
	"testing"
)

func TestNugetGlobalPackagesRootWithPrefersEnvironment(t *testing.T) {
	t.Parallel()

	root, ok := nugetGlobalPackagesRootWith(func(key string) string {
		if key == "NUGET_PACKAGES" {
			return filepath.Join("custom", "packages")
		}
		return ""
	}, func() (string, error) {
		return filepath.Join("home", "user"), nil
	})
	if !ok {
		t.Fatal("expected root")
	}
	if root != filepath.Clean(filepath.Join("custom", "packages")) {
		t.Fatalf("root = %q", root)
	}
}

func TestNugetGlobalPackagesRootWithFallsBackToHomeDir(t *testing.T) {
	t.Parallel()

	root, ok := nugetGlobalPackagesRootWith(func(string) string {
		return ""
	}, func() (string, error) {
		return filepath.Join("home", "user"), nil
	})
	if !ok {
		t.Fatal("expected root")
	}
	expected := filepath.Join("home", "user", ".nuget", "packages")
	if root != expected {
		t.Fatalf("root = %q, want %q", root, expected)
	}
}

func TestNugetGlobalPackagesRootWithReturnsFalseWhenUnavailable(t *testing.T) {
	t.Parallel()

	if _, ok := nugetGlobalPackagesRootWith(func(string) string {
		return ""
	}, func() (string, error) {
		return "", errors.New("no home")
	}); ok {
		t.Fatal("expected missing root")
	}
}

func TestNugetResolverResolveGlobalPackagesRootPrefersExplicitField(t *testing.T) {
	t.Parallel()

	resolver := nugetResolver{globalPackagesRoot: filepath.Join("custom", "packages")}
	root, ok := resolver.resolveGlobalPackagesRoot()
	if !ok {
		t.Fatal("expected explicit root")
	}
	if root != filepath.Join("custom", "packages") {
		t.Fatalf("root = %q", root)
	}
}

func TestNugetResolverPathAndURLHelpers(t *testing.T) {
	t.Parallel()

	resolver := nugetResolver{registrationBaseURL: "https://example.test/registration"}
	if got := resolver.resolveRegistrationBaseURL(); got != "https://example.test/registration" {
		t.Fatalf("explicit registration base url = %q", got)
	}

	resolver = nugetResolver{}
	if got := resolver.resolveRegistrationBaseURL(); got != "https://api.nuget.org/v3/registration5-gz-semver2" {
		t.Fatalf("default registration base url = %q", got)
	}

	if got := urlPathEscapeLower(" Newtonsoft.Json /Core "); got != "newtonsoft.json%20%2Fcore" {
		t.Fatalf("urlPathEscapeLower = %q", got)
	}

	resolver = nugetResolver{}
	root, ok := (&resolver).resolveGlobalPackagesRoot()
	if ok && root == "" {
		t.Fatalf("unexpected empty root with ok=true")
	}
}
