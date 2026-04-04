package testutil

import (
	"errors"
	"io"
	"net/http"
	"testing"
)

func TestRoundTripFuncForwardsRequestAndResponse(t *testing.T) {
	t.Parallel()

	req, err := http.NewRequest(http.MethodGet, "https://example.test/pkg", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}

	wantResp := &http.Response{StatusCode: http.StatusAccepted}
	gotReq := (*http.Request)(nil)
	resp, gotErr := RoundTripFunc(func(inner *http.Request) (*http.Response, error) {
		gotReq = inner
		return wantResp, nil
	}).RoundTrip(req)
	if gotErr != nil {
		t.Fatalf("RoundTrip error: %v", gotErr)
	}
	if gotReq != req {
		t.Fatalf("request pointer changed: got %p want %p", gotReq, req)
	}
	if resp != wantResp {
		t.Fatalf("response pointer changed: got %p want %p", resp, wantResp)
	}
}

func TestRoundTripFuncForwardsErrors(t *testing.T) {
	t.Parallel()

	req, err := http.NewRequest(http.MethodGet, "https://example.test/pkg", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}

	wantErr := errors.New("transport failed")
	resp, gotErr := RoundTripFunc(func(*http.Request) (*http.Response, error) {
		return nil, wantErr
	}).RoundTrip(req)
	if !errors.Is(gotErr, wantErr) {
		t.Fatalf("error = %v", gotErr)
	}
	if resp != nil {
		t.Fatalf("response = %#v", resp)
	}
}

func TestErrorBodyUsesProvidedErrorAndDefaultFallback(t *testing.T) {
	t.Parallel()

	t.Run("provided", func(t *testing.T) {
		t.Parallel()

		wantErr := errors.New("read failed")
		body := ErrorBody(wantErr)
		defer body.Close()

		_, gotErr := io.ReadAll(body)
		if !errors.Is(gotErr, wantErr) {
			t.Fatalf("error = %v", gotErr)
		}
	})

	t.Run("default", func(t *testing.T) {
		t.Parallel()

		body := ErrorBody(nil)
		defer body.Close()

		_, gotErr := io.ReadAll(body)
		if gotErr == nil || gotErr.Error() != "boom" {
			t.Fatalf("error = %v", gotErr)
		}
	})
}
