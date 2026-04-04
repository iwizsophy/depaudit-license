package testutil

import (
	"encoding/json"
	"os"
	"testing"
)

func WriteIndentedJSONFixture[T any](t *testing.T, path string, value T) {
	t.Helper()

	if err := writeIndentedJSONFixture(path, value); err != nil {
		t.Fatal(err)
	}
}

func writeIndentedJSONFixture[T any](path string, value T) error {
	return writeIndentedJSONFixtureWith(path, value, json.MarshalIndent, os.WriteFile)
}

func writeIndentedJSONFixtureWith[T any](
	path string,
	value T,
	marshal func(any, string, string) ([]byte, error),
	write func(string, []byte, os.FileMode) error,
) error {
	payload, err := marshal(value, "", "  ")
	if err != nil {
		return &jsonFixtureError{op: "marshal", path: path, err: err}
	}
	if err := write(path, payload, 0o644); err != nil {
		return &jsonFixtureError{op: "write", path: path, err: err}
	}
	return nil
}

type jsonFixtureError struct {
	op   string
	path string
	err  error
}

func (e *jsonFixtureError) Error() string {
	return e.op + " json fixture " + e.path + ": " + e.err.Error()
}
