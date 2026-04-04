package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

type failingWriter struct {
	err error
}

func (w failingWriter) Write([]byte) (int, error) {
	return 0, w.err
}

func TestRunWritesTextAndJSONOutputs(t *testing.T) {
	coverOutput := []byte("internal/report/report.go:95:\tBuildDocument\t92.3%\nmain.go:42:\trun\t88.1%\ntotal:\t(statements)\t93.7%\n")
	original := coverFuncOutput
	defer func() { coverFuncOutput = original }()
	coverFuncOutput = func(string) ([]byte, error) {
		return coverOutput, nil
	}

	t.Run("text", func(t *testing.T) {
		var stdout bytes.Buffer
		var stderr bytes.Buffer
		exitCode := run([]string{"-threshold", "90", "-top", "1"}, &stdout, &stderr)
		if exitCode != 0 {
			t.Fatalf("exit code = %d stderr=%q", exitCode, stderr.String())
		}
		text := stdout.String()
		for _, want := range []string{"TOTAL", "THRESHOLD", "PACKAGE", "run", "88.1%"} {
			if !strings.Contains(text, want) {
				t.Fatalf("stdout missing %q\n%s", want, text)
			}
		}
		if stderr.Len() != 0 {
			t.Fatalf("stderr = %q", stderr.String())
		}
	})

	t.Run("json", func(t *testing.T) {
		var stdout bytes.Buffer
		var stderr bytes.Buffer
		exitCode := run([]string{"-format", "json", "-threshold", "95"}, &stdout, &stderr)
		if exitCode != 0 {
			t.Fatalf("exit code = %d stderr=%q", exitCode, stderr.String())
		}
		var payload struct {
			Threshold float64 `json:"threshold"`
			Total     float64 `json:"total"`
			Hotspots  []struct {
				Function string  `json:"function"`
				Percent  float64 `json:"percent"`
			} `json:"hotspots"`
		}
		if err := json.Unmarshal(stdout.Bytes(), &payload); err != nil {
			t.Fatalf("unmarshal json: %v\n%s", err, stdout.String())
		}
		if payload.Threshold != 95 || payload.Total != 93.7 || len(payload.Hotspots) != 2 {
			t.Fatalf("payload = %#v", payload)
		}
	})
}

func TestRunReportsCommandParseAndFormatFailures(t *testing.T) {
	t.Run("flag-parse", func(t *testing.T) {
		var stdout bytes.Buffer
		var stderr bytes.Buffer
		exitCode := run([]string{"-threshold", "oops"}, &stdout, &stderr)
		if exitCode != 2 || !strings.Contains(stderr.String(), "invalid value") || !strings.Contains(stderr.String(), "-threshold") {
			t.Fatalf("exit=%d stderr=%q", exitCode, stderr.String())
		}
	})

	t.Run("command", func(t *testing.T) {
		original := coverFuncOutput
		defer func() { coverFuncOutput = original }()
		coverFuncOutput = func(string) ([]byte, error) {
			return []byte("tool failed"), errors.New("exit status 1")
		}

		var stdout bytes.Buffer
		var stderr bytes.Buffer
		exitCode := run([]string{"-coverprofile", "coverage.out"}, &stdout, &stderr)
		if exitCode != 1 || !strings.Contains(stderr.String(), "go tool cover -func coverage.out") || !strings.Contains(stderr.String(), "tool failed") {
			t.Fatalf("exit=%d stderr=%q", exitCode, stderr.String())
		}
	})

	t.Run("parse", func(t *testing.T) {
		original := coverFuncOutput
		defer func() { coverFuncOutput = original }()
		coverFuncOutput = func(string) ([]byte, error) {
			return []byte("broken"), nil
		}

		var stdout bytes.Buffer
		var stderr bytes.Buffer
		exitCode := run(nil, &stdout, &stderr)
		if exitCode != 1 || !strings.Contains(stderr.String(), "parse coverage output") {
			t.Fatalf("exit=%d stderr=%q", exitCode, stderr.String())
		}
	})

	t.Run("format", func(t *testing.T) {
		original := coverFuncOutput
		defer func() { coverFuncOutput = original }()
		coverFuncOutput = func(string) ([]byte, error) {
			return []byte("main.go:42:\trun\t88.1%\ntotal:\t(statements)\t93.7%\n"), nil
		}

		var stdout bytes.Buffer
		var stderr bytes.Buffer
		exitCode := run([]string{"-format", "xml"}, &stdout, &stderr)
		if exitCode != 1 || !strings.Contains(stderr.String(), `unsupported format "xml"`) {
			t.Fatalf("exit=%d stderr=%q", exitCode, stderr.String())
		}
	})

	t.Run("json-write", func(t *testing.T) {
		original := coverFuncOutput
		defer func() { coverFuncOutput = original }()
		coverFuncOutput = func(string) ([]byte, error) {
			return []byte("main.go:42:\trun\t88.1%\ntotal:\t(statements)\t93.7%\n"), nil
		}

		var stderr bytes.Buffer
		exitCode := run([]string{"-format", "json"}, failingWriter{err: errors.New("boom")}, &stderr)
		if exitCode != 1 || !strings.Contains(stderr.String(), "write json: boom") {
			t.Fatalf("exit=%d stderr=%q", exitCode, stderr.String())
		}
	})

	t.Run("text-write", func(t *testing.T) {
		original := coverFuncOutput
		defer func() { coverFuncOutput = original }()
		coverFuncOutput = func(string) ([]byte, error) {
			return []byte("main.go:42:\trun\t88.1%\ntotal:\t(statements)\t93.7%\n"), nil
		}

		var stderr bytes.Buffer
		exitCode := run([]string{"-format", "text"}, failingWriter{err: errors.New("boom")}, &stderr)
		if exitCode != 1 || !strings.Contains(stderr.String(), "write text: boom") {
			t.Fatalf("exit=%d stderr=%q", exitCode, stderr.String())
		}
	})
}
