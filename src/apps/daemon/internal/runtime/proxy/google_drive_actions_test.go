package proxy

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
)

func TestGoogleDriveUploadUsesPreGeneratedIDAndConfirmsRetryConflict(t *testing.T) {
	var posts atomic.Int32
	var calls atomic.Int32
	client := &http.Client{Transport: driveRoundTripperFunc(func(req *http.Request) (*http.Response, error) {
		switch calls.Add(1) {
		case 1:
			if req.Method != http.MethodGet || !strings.Contains(req.URL.Path, "/files/generateIds") {
				t.Fatalf("first request=%s %s, want generateIds", req.Method, req.URL)
			}
			return driveResponse(http.StatusOK, `{"ids":["generated-1"]}`), nil
		case 2:
			if req.Method != http.MethodPost || !strings.Contains(req.URL.Path, "/upload/drive/v3/files") {
				t.Fatalf("second request=%s %s, want upload", req.Method, req.URL)
			}
			posts.Add(1)
			body, err := io.ReadAll(req.Body)
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(string(body), `"id":"generated-1"`) {
				t.Fatalf("multipart metadata missing generated ID: %s", body)
			}
			return nil, errors.New("connection reset after write")
		case 3:
			posts.Add(1)
			return driveResponse(http.StatusConflict, `{"error":{"code":409}}`), nil
		case 4:
			if req.Method != http.MethodGet || !strings.Contains(req.URL.Path, "/files/generated-1") || req.URL.Query().Get("alt") != "media" {
				t.Fatalf("fourth request=%s %s, want exact-ID readback", req.Method, req.URL)
			}
			return driveResponse(http.StatusOK, "cGF5bG9hZA=="), nil
		default:
			t.Fatalf("unexpected request %d: %s %s", calls.Load(), req.Method, req.URL)
			return nil, nil
		}
	})}

	err := uploadGoogleDriveFile(
		context.Background(), client, "test.drive.upload", "token", "folder", "chunk.txt",
		"application/octet-stream", []byte("cGF5bG9hZA=="),
	)
	if err != nil {
		t.Fatalf("uploadGoogleDriveFile() error = %v", err)
	}
	if posts.Load() != 2 {
		t.Fatalf("POST calls=%d, want 2 attempts with one stable file ID", posts.Load())
	}
}

func TestGoogleDriveUploadFailsClosedOnConflictWithDifferentPayload(t *testing.T) {
	var calls atomic.Int32
	client := &http.Client{Transport: driveRoundTripperFunc(func(req *http.Request) (*http.Response, error) {
		switch calls.Add(1) {
		case 1:
			return driveResponse(http.StatusOK, `{"ids":["generated-1"]}`), nil
		case 2:
			return driveResponse(http.StatusConflict, `{"error":{"code":409}}`), nil
		case 3:
			return driveResponse(http.StatusOK, "different"), nil
		default:
			t.Fatalf("unexpected request after conflicting readback")
			return nil, nil
		}
	})}

	err := uploadGoogleDriveFile(
		context.Background(), client, "test.drive.upload", "token", "folder", "chunk.txt",
		"text/plain", []byte("expected"),
	)
	if err == nil || !strings.Contains(err.Error(), "payload differs") {
		t.Fatalf("error=%v, want fail-closed payload conflict", err)
	}
	if calls.Load() != 3 {
		t.Fatalf("calls=%d, want 3", calls.Load())
	}
}

func TestGoogleDriveUploadFailsClosedWhenGeneratedIDResponseIsInvalid(t *testing.T) {
	client := &http.Client{Transport: driveRoundTripperFunc(func(req *http.Request) (*http.Response, error) {
		return driveResponse(http.StatusOK, `{"ids":[]}`), nil
	})}

	err := uploadGoogleDriveFile(
		context.Background(), client, "test.drive.upload", "token", "folder", "chunk.txt",
		"text/plain", []byte("expected"),
	)
	if err == nil || !strings.Contains(err.Error(), "no usable file ID") {
		t.Fatalf("error=%v, want generated-ID failure", err)
	}
}

func TestDriveQueryLiteralEscapesQuotesAndBackslashes(t *testing.T) {
	got := escapeDriveQueryLiteral(`a'b\\c`)
	if got != `a\'b\\\\c` {
		t.Fatalf("escaped=%q", got)
	}
}

type driveRoundTripperFunc func(*http.Request) (*http.Response, error)

func (f driveRoundTripperFunc) RoundTrip(req *http.Request) (*http.Response, error) { return f(req) }

func driveResponse(status int, body string) *http.Response {
	return &http.Response{StatusCode: status, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body))}
}
