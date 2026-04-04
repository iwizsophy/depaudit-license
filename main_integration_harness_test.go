package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type cliOutputPaths struct {
	HTML      string
	JSON      string
	LegalHTML string
	VulnHTML  string
	VulnJSON  string
}

func newCLIOutputPaths(dir string) cliOutputPaths {
	return cliOutputPaths{
		HTML:      filepath.Join(dir, "report.html"),
		JSON:      filepath.Join(dir, "report.json"),
		LegalHTML: filepath.Join(dir, "legal.html"),
		VulnHTML:  filepath.Join(dir, "vuln.html"),
		VulnJSON:  filepath.Join(dir, "vuln.json"),
	}
}

func (paths cliOutputPaths) baseArgs() []string {
	return []string{
		"-output-html", paths.HTML,
		"-output-json", paths.JSON,
		"-output-legal-html", paths.LegalHTML,
	}
}

func setMainHarness(t *testing.T, args []string) (*bytes.Buffer, *int) {
	t.Helper()

	oldArgs := os.Args
	oldExit := exitFunc
	oldStderr := stderrOut
	t.Cleanup(func() {
		os.Args = oldArgs
		exitFunc = oldExit
		stderrOut = oldStderr
	})

	var stderr bytes.Buffer
	exitCode := -1
	exitFunc = func(code int) { exitCode = code }
	stderrOut = &stderr
	os.Args = args
	return &stderr, &exitCode
}

func assertContainsAll(t *testing.T, label string, content string, wants ...string) {
	t.Helper()
	for _, want := range wants {
		if !strings.Contains(content, want) {
			t.Fatalf("%s missing %q\n%s", label, want, content)
		}
	}
}

func expectedOutputAnnouncements(includeVulnHTML bool, includeVulnJSON bool) []string {
	wants := []string{
		"generated HTML",
		"generated legal notice HTML",
		"generated JSON",
	}
	if includeVulnHTML {
		wants = append(wants, "generated vulnerability HTML")
	}
	if includeVulnJSON {
		wants = append(wants, "generated vulnerability JSON")
	}
	return wants
}

func rootDisplay(parts ...string) string {
	cleaned := make([]string, 0, len(parts))
	for _, part := range parts {
		cleaned = append(cleaned, filepath.Clean(part))
	}
	return strings.Join(cleaned, " + ")
}

func escapedRootDisplay(parts ...string) string {
	return strings.ReplaceAll(rootDisplay(parts...), "+", "&#43;")
}
