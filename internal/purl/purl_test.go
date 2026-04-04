package purl

import (
	"testing"

	"depaudit-license/internal/inventory"
)

func TestNormalizeCanonicalizesKnownEcosystems(t *testing.T) {
	t.Parallel()

	tests := []struct {
		raw  string
		want string
	}{
		{"pkg:npm/@Scope/React@18.2.0", "pkg:npm/scope/react@18.2.0"},
		{"pkg:nuget/Newtonsoft.Json@13.0.3", "pkg:nuget/newtonsoft.json@13.0.3"},
		{"pkg:generic/Custom-Lib@1.0.0?download_url=https%3A%2F%2Fexample.test%2Fpkg", "pkg:generic/Custom-Lib@1.0.0?download_url=https%3A%2F%2Fexample.test%2Fpkg"},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.raw, func(t *testing.T) {
			t.Parallel()
			got, ok := Normalize(tt.raw)
			if !ok {
				t.Fatal("expected normalized purl")
			}
			if got != tt.want {
				t.Fatalf("got %q, want %q", got, tt.want)
			}
		})
	}
}

func TestFromPackageBuildsCanonicalPURL(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		pkg  inventory.Package
		want string
	}{
		{
			name: "node scoped",
			pkg:  inventory.Package{Ecosystem: "node", Name: "@scope/react", Version: "18.2.0"},
			want: "pkg:npm/scope/react@18.2.0",
		},
		{
			name: "dotnet",
			pkg:  inventory.Package{Ecosystem: "dotnet", Name: "Newtonsoft.Json", Version: "13.0.3"},
			want: "pkg:nuget/newtonsoft.json@13.0.3",
		},
		{
			name: "generic fallback",
			pkg:  inventory.Package{Ecosystem: "generic", Name: "custom-lib", Version: "1.0.0"},
			want: "pkg:generic/custom-lib@1.0.0",
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, ok := FromPackage(tt.pkg)
			if !ok {
				t.Fatal("expected purl")
			}
			if got != tt.want {
				t.Fatalf("got %q, want %q", got, tt.want)
			}
		})
	}
}

func TestCanonicalKeyFallsBackWhenPURLMissing(t *testing.T) {
	t.Parallel()

	key := CanonicalKey(inventory.Package{Ecosystem: "node", Name: "react", Version: "18.2.0"})
	if key != "pkg:npm/react@18.2.0" {
		t.Fatalf("key = %q", key)
	}

	key = CanonicalKey(inventory.Package{Ecosystem: "", Name: "", Version: ""})
	if key != "\x00\x00" {
		t.Fatalf("fallback key = %q", key)
	}
}

func TestParseAndNormalizeRejectInvalidPURLs(t *testing.T) {
	t.Parallel()

	cases := []string{
		"",
		"npm/react",
		"pkg:npm",
		"pkg:npm/@scope",
		"pkg:npm/@1.0.0",
	}

	for _, raw := range cases {
		raw := raw
		t.Run(raw, func(t *testing.T) {
			t.Parallel()
			if _, ok := Parse(raw); ok {
				t.Fatalf("expected Parse(%q) to fail", raw)
			}
			if _, ok := Normalize(raw); ok {
				t.Fatalf("expected Normalize(%q) to fail", raw)
			}
		})
	}
}

func TestParseCanonicalizesQualifiersAndSubpath(t *testing.T) {
	t.Parallel()

	parsed, ok := Parse("pkg:generic/team/pkg%20name@1.0.0?arch=x86_64&empty=&repo_url=https%3A%2F%2Fexample.test%2Fa%2Fb#/%E6%96%87%E6%9B%B8/")
	if !ok {
		t.Fatal("expected Parse to succeed")
	}
	if parsed.Type != "generic" {
		t.Fatalf("type = %q", parsed.Type)
	}
	if parsed.Namespace != "team" {
		t.Fatalf("namespace = %q", parsed.Namespace)
	}
	if parsed.Name != "pkg name" {
		t.Fatalf("name = %q", parsed.Name)
	}
	if parsed.Subpath != "文書" {
		t.Fatalf("subpath = %q", parsed.Subpath)
	}
	if len(parsed.Qualifiers) != 2 {
		t.Fatalf("qualifiers = %#v", parsed.Qualifiers)
	}
	if parsed.Qualifiers["repo_url"] != "https://example.test/a/b" {
		t.Fatalf("repo_url = %q", parsed.Qualifiers["repo_url"])
	}
}

func TestFromPackageHandlesFallbackBranches(t *testing.T) {
	t.Parallel()

	if _, ok := FromPackage(inventory.Package{PURL: "pkg:npm/%40scope/react@18.2.0"}); !ok {
		t.Fatal("expected explicit PURL to win")
	}

	if _, ok := FromPackage(inventory.Package{Ecosystem: "node", Name: "", Version: "1.0.0"}); ok {
		t.Fatal("expected empty node package name to fail")
	}
	if got, ok := FromPackage(inventory.Package{Ecosystem: "node", Name: "@scopeonly", Version: "1.0.0"}); !ok || got != "pkg:npm/@scopeonly@1.0.0" {
		t.Fatalf("malformed scoped package = %q, %v", got, ok)
	}
	if _, ok := FromPackage(inventory.Package{Ecosystem: "dotnet", Name: "", Version: "1.0.0"}); ok {
		t.Fatal("expected empty dotnet package name to fail")
	}
	if _, ok := FromPackage(inventory.Package{Ecosystem: "generic", Name: "", Version: "1.0.0"}); ok {
		t.Fatal("expected empty generic package name to fail")
	}
	if got, ok := FromPackage(inventory.Package{Ecosystem: "", Name: "tool", Version: "1.0.0"}); !ok || got != "pkg:generic/tool@1.0.0" {
		t.Fatalf("generic fallback = %q, %v", got, ok)
	}
}

func TestPURLHelperUtilities(t *testing.T) {
	t.Parallel()

	if got := canonicalGenericType(""); got != "generic" {
		t.Fatalf("canonicalGenericType empty = %q", got)
	}
	if got := canonicalGenericType(" OCI "); got != "oci" {
		t.Fatalf("canonicalGenericType trim = %q", got)
	}

	qualifiers := parseQualifiers("arch=x86_64&empty=&novalue&REPO_URL=https%3A%2F%2Fexample.test%2Fa+b")
	if len(qualifiers) != 2 {
		t.Fatalf("parseQualifiers = %#v", qualifiers)
	}
	if qualifiers["repo_url"] != "https://example.test/a+b" {
		t.Fatalf("repo_url qualifier = %q", qualifiers["repo_url"])
	}

	rendered := renderQualifiers(map[string]string{"repo_url": "https://example.test/a b", "arch": "x86_64"})
	if rendered != "arch=x86_64&repo_url=https%3A%2F%2Fexample.test%2Fa+b" {
		t.Fatalf("renderQualifiers = %q", rendered)
	}

	if got := decode("%zz"); got != "%zz" {
		t.Fatalf("decode invalid = %q", got)
	}
	if got := encodePath("/team/pkg name/"); got != "team/pkg%20name" {
		t.Fatalf("encodePath = %q", got)
	}
	if got := cleanSubpath(" /docs/%E6%96%87%E6%9B%B8/ "); got != "docs/文書" {
		t.Fatalf("cleanSubpath = %q", got)
	}

	if got := (PackageURL{}).String(); got != "" {
		t.Fatalf("empty PackageURL string = %q", got)
	}
	if got := (PackageURL{
		Type:       "npm",
		Namespace:  "@Scope",
		Name:       "React",
		Version:    "18.2.0",
		Qualifiers: map[string]string{" Repo_URL ": " https://example.test/a b ", "": "ignored"},
		Subpath:    "/src/",
	}).String(); got != "pkg:npm/scope/react@18.2.0?repo_url=https%3A%2F%2Fexample.test%2Fa+b#src" {
		t.Fatalf("PackageURL.String = %q", got)
	}
}
