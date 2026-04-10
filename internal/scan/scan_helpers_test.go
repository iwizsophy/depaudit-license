package scan

import (
	"encoding/json"
	"testing"
)

func TestNodeMetadataParsingHelpers(t *testing.T) {
	t.Parallel()

	personJSON, _ := json.Marshal("Jane Doe <jane@example.test>")
	if got := parsePerson(personJSON); got != "Jane Doe" {
		t.Fatalf("parsePerson string = %q", got)
	}

	personObjectJSON, _ := json.Marshal(map[string]string{"name": "John Doe"})
	if got := parsePerson(personObjectJSON); got != "John Doe" {
		t.Fatalf("parsePerson object = %q", got)
	}

	if got := parsePerson(json.RawMessage(`{"email":"missing-name"}`)); got != "" {
		t.Fatalf("parsePerson invalid = %q", got)
	}

	people := parsePeople([]json.RawMessage{
		personJSON,
		personObjectJSON,
		json.RawMessage(`"Jane Doe <dupe@example.test>"`),
	})
	if len(people) != 2 || people[0] != "Jane Doe" || people[1] != "John Doe" {
		t.Fatalf("parsePeople = %#v", people)
	}

	repoJSON, _ := json.Marshal("git+https://github.com/example/repo.git")
	if got := parseRepository(repoJSON); got != "https://github.com/example/repo.git" {
		t.Fatalf("parseRepository string = %q", got)
	}
	repoObjectJSON, _ := json.Marshal(map[string]string{"url": "git+https://github.com/example/object.git"})
	if got := parseRepository(repoObjectJSON); got != "https://github.com/example/object.git" {
		t.Fatalf("parseRepository object = %q", got)
	}

	licenseJSON, _ := json.Marshal("MIT")
	if got := parseLicense(licenseJSON); got != "MIT" {
		t.Fatalf("parseLicense string = %q", got)
	}
	licenseObjectJSON, _ := json.Marshal(map[string]string{"type": "Apache-2.0"})
	if got := parseLicense(licenseObjectJSON); got != "Apache-2.0" {
		t.Fatalf("parseLicense object = %q", got)
	}

	if got := parseRepository(json.RawMessage(`{"name":"missing-url"}`)); got != "" {
		t.Fatalf("parseRepository invalid = %q", got)
	}
	if got := parseLicense(json.RawMessage(`{"name":"missing-type"}`)); got != "" {
		t.Fatalf("parseLicense invalid = %q", got)
	}
	if got := parsePerson(json.RawMessage(`{"name":`)); got != "" {
		t.Fatalf("parsePerson malformed = %q", got)
	}
	if got := parseRepository(json.RawMessage(`{"url":`)); got != "" {
		t.Fatalf("parseRepository malformed = %q", got)
	}
	if got := parseLicense(json.RawMessage(`{"type":`)); got != "" {
		t.Fatalf("parseLicense malformed = %q", got)
	}
	if got := firstCSVValue("Alice; Bob"); got != "Alice" {
		t.Fatalf("firstCSVValue semicolon = %q", got)
	}
	if got := firstCSVValue("   "); got != "" {
		t.Fatalf("firstCSVValue blank = %q", got)
	}
	if got := uniqueStrings([]string{"a", "", "a", "b"}); len(got) != 2 || got[0] != "a" || got[1] != "b" {
		t.Fatalf("uniqueStrings blanks = %#v", got)
	}
	if got := parsePeople(nil); len(got) != 0 {
		t.Fatalf("parsePeople nil = %#v", got)
	}
	if got := cleanPerson("No Email"); got != "No Email" {
		t.Fatalf("cleanPerson plain = %q", got)
	}
	if got := firstCSVValue(" Alice, Bob "); got != "Alice" {
		t.Fatalf("firstCSVValue comma = %q", got)
	}
	if got := firstNonEmpty("   ", " second ", "third"); got != "second" {
		t.Fatalf("firstNonEmpty = %q", got)
	}
	if got := mustPURL(Package{Ecosystem: "node", Name: "react", Version: "19.2.4"}); got != "pkg:npm/react@19.2.4" {
		t.Fatalf("mustPURL generated = %q", got)
	}
	if got := mustPURL(Package{PURL: "pkg:generic/custom@1.0.0"}); got != "pkg:generic/custom@1.0.0" {
		t.Fatalf("mustPURL explicit = %q", got)
	}
	if got := mustPURL(Package{}); got != "" {
		t.Fatalf("mustPURL empty = %q", got)
	}
	if got := embeddedLicenseFileCandidate("SEE LICENSE IN LICENSE.md"); got != "LICENSE.md" {
		t.Fatalf("embeddedLicenseFileCandidate SEE LICENSE = %q", got)
	}
	if got := embeddedLicenseFileCandidate("MIT"); got != "" {
		t.Fatalf("embeddedLicenseFileCandidate SPDX = %q", got)
	}
}
