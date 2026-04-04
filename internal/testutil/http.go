package testutil

import (
	"errors"
	"io"
	"net/http"
)

type RoundTripFunc func(*http.Request) (*http.Response, error)

func (fn RoundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return fn(req)
}

type errReadCloser struct {
	err error
}

func (r errReadCloser) Read([]byte) (int, error) {
	return 0, r.err
}

func (r errReadCloser) Close() error {
	return nil
}

func ErrorBody(err error) io.ReadCloser {
	if err == nil {
		err = errors.New("boom")
	}
	return errReadCloser{err: err}
}
