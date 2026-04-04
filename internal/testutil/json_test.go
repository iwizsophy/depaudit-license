package testutil

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestWriteIndentedJSONFixtureWritesIndentedJSON(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "fixture.json")
	WriteIndentedJSONFixture(t, path, map[string]any{
		"name": "widget",
		"tags": []string{"a", "b"},
	})

	payload, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	text := string(payload)
	if !strings.Contains(text, "\n  \"name\": \"widget\"") {
		t.Fatalf("payload = %q", text)
	}

	var decoded map[string]any
	if err := json.Unmarshal(payload, &decoded); err != nil {
		t.Fatalf("unmarshal fixture: %v", err)
	}
	if decoded["name"] != "widget" {
		t.Fatalf("decoded = %#v", decoded)
	}
}

func TestWriteIndentedJSONFixtureFailsOnMarshalAndWriteErrors(t *testing.T) {
	t.Parallel()

	t.Run("marshal", func(t *testing.T) {
		t.Parallel()

		path := filepath.Join(t.TempDir(), "fixture.json")
		marshal := func(any, string, string) ([]byte, error) {
			return nil, errors.New("marshal failed")
		}

		err := writeIndentedJSONFixtureWith(path, map[string]any{"name": "widget"}, marshal, os.WriteFile)
		if err == nil || !strings.Contains(err.Error(), "marshal json fixture") || !strings.Contains(err.Error(), "marshal failed") {
			t.Fatalf("error = %v", err)
		}
	})

	t.Run("write", func(t *testing.T) {
		t.Parallel()

		path := filepath.Join(t.TempDir(), "fixture.json")
		write := func(string, []byte, os.FileMode) error {
			return errors.New("write failed")
		}

		err := writeIndentedJSONFixtureWith(path, map[string]any{"name": "widget"}, json.MarshalIndent, write)
		if err == nil || !strings.Contains(err.Error(), "write json fixture") || !strings.Contains(err.Error(), "write failed") {
			t.Fatalf("error = %v", err)
		}
	})
}
