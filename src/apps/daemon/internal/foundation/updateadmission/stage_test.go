package updateadmission

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestStageDownloadsVerifiesAndReusesArtifact(t *testing.T) {
	body := []byte("signed update bytes\n")
	digest := sha256.Sum256(body)
	requests := 0
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		_, _ = w.Write(body)
	}))
	defer server.Close()

	plan := Plan{ReleaseID: "release/42", Version: "4.0.0", ArtifactURL: server.URL + "/artifact", ArtifactSHA256: hex.EncodeToString(digest[:]), ArtifactSize: int64(len(body))}
	dir := t.TempDir()
	first, err := Stage(context.Background(), server.Client(), dir, plan)
	if err != nil {
		t.Fatal(err)
	}
	if first.ApplyAuthorized || first.Reused || first.Bytes != int64(len(body)) {
		t.Fatalf("first=%+v", first)
	}
	got, err := os.ReadFile(first.Path)
	if err != nil || string(got) != string(body) {
		t.Fatalf("staged bytes=%q err=%v", got, err)
	}
	if _, err := os.Stat(first.ReceiptPath); err != nil {
		t.Fatalf("receipt missing: %v", err)
	}

	second, err := Stage(context.Background(), server.Client(), dir, plan)
	if err != nil {
		t.Fatal(err)
	}
	if !second.Reused || requests != 1 {
		t.Fatalf("second=%+v requests=%d", second, requests)
	}
}

func TestStageRejectsWrongSizeDigestAndStatus(t *testing.T) {
	body := []byte("artifact")
	digest := sha256.Sum256(body)
	base := Plan{ReleaseID: "r", Version: "v", ArtifactSHA256: hex.EncodeToString(digest[:]), ArtifactSize: int64(len(body))}

	for _, tc := range []struct {
		name   string
		status int
		body   []byte
		mutate func(*Plan)
	}{
		{name: "status", status: http.StatusBadGateway, body: body},
		{name: "size", status: http.StatusOK, body: append(body, '!')},
		{name: "digest", status: http.StatusOK, body: body, mutate: func(p *Plan) { p.ArtifactSHA256 = strings.Repeat("00", 32) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tc.status)
				_, _ = w.Write(tc.body)
			}))
			defer server.Close()
			plan := base
			plan.ArtifactURL = server.URL
			if tc.mutate != nil {
				tc.mutate(&plan)
			}
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			if _, err := Stage(ctx, server.Client(), t.TempDir(), plan); err == nil {
				t.Fatal("invalid stage accepted")
			}
		})
	}
}

func TestStageRejectsInsecureInitialURLAndRedirect(t *testing.T) {
	body := []byte("artifact")
	digest := sha256.Sum256(body)
	plan := Plan{ReleaseID: "r", Version: "v", ArtifactURL: "http://example.test/artifact", ArtifactSHA256: hex.EncodeToString(digest[:]), ArtifactSize: int64(len(body))}
	if _, err := Stage(context.Background(), nil, t.TempDir(), plan); err == nil || !strings.Contains(err.Error(), "absolute HTTPS") {
		t.Fatalf("insecure initial URL accepted: %v", err)
	}

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://example.test/artifact", http.StatusFound)
	}))
	defer server.Close()
	plan.ArtifactURL = server.URL + "/start"
	if _, err := Stage(context.Background(), server.Client(), t.TempDir(), plan); err == nil || !strings.Contains(err.Error(), "absolute HTTPS") {
		t.Fatalf("insecure redirect accepted: %v", err)
	}
}

func TestStageCapsRedirectChain(t *testing.T) {
	body := []byte("artifact")
	digest := sha256.Sum256(body)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var hop int
		_, _ = fmt.Sscanf(r.URL.Query().Get("hop"), "%d", &hop)
		if hop < 6 {
			http.Redirect(w, r, fmt.Sprintf("/artifact?hop=%d", hop+1), http.StatusFound)
			return
		}
		_, _ = w.Write(body)
	}))
	defer server.Close()
	plan := Plan{ReleaseID: "r", Version: "v", ArtifactURL: server.URL + "/artifact?hop=0", ArtifactSHA256: hex.EncodeToString(digest[:]), ArtifactSize: int64(len(body))}
	if _, err := Stage(context.Background(), server.Client(), t.TempDir(), plan); err == nil || !strings.Contains(err.Error(), "redirect limit") {
		t.Fatalf("redirect chain was not capped: %v", err)
	}
}

func TestReplaceStagedFileOverwritesRegularTarget(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "release.artifact")
	source := filepath.Join(dir, ".release.partial")
	if err := os.WriteFile(target, []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(source, []byte("new"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := replaceStagedFile(source, target); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "new" {
		t.Fatalf("target=%q, want new", got)
	}
	if _, err := os.Stat(source); !os.IsNotExist(err) {
		t.Fatalf("source still exists after publication: %v", err)
	}
}

func TestReplaceStagedFileRejectsSymlinkTarget(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation is privilege-dependent on Windows")
	}
	dir := t.TempDir()
	realTarget := filepath.Join(dir, "real.artifact")
	target := filepath.Join(dir, "release.artifact")
	source := filepath.Join(dir, ".release.partial")
	if err := os.WriteFile(realTarget, []byte("safe"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(realTarget, target); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(source, []byte("new"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := replaceStagedFile(source, target); err == nil || !strings.Contains(err.Error(), "non-regular") {
		t.Fatalf("replaceStagedFile error=%v, want non-regular rejection", err)
	}
	got, err := os.ReadFile(realTarget)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "safe" {
		t.Fatalf("symlink target was modified: %q", got)
	}
}
