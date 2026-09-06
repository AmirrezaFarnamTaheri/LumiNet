package updateadmission

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

const maxStagingResponseOverhead int64 = 1

var safeStageComponent = regexp.MustCompile(`[^A-Za-z0-9._-]+`)

// StageResult describes an artifact that has been fully downloaded and verified.
// Staging alone never authorizes installation or execution.
type StageResult struct {
	Plan            Plan      `json:"plan"`
	Path            string    `json:"path"`
	ReceiptPath     string    `json:"receipt_path"`
	SHA256          string    `json:"sha256"`
	Bytes           int64     `json:"bytes"`
	StagedAt        time.Time `json:"staged_at"`
	ApplyAuthorized bool      `json:"apply_authorized"`
	Reused          bool      `json:"reused"`
}

// Stage downloads a verified update plan into dir, checks the exact byte count
// and SHA-256, fsyncs file contents and durable directory publication where the platform supports it, then publishes both artifact and receipt.
// Repeated staging reuses an already verified identical artifact.
func Stage(ctx context.Context, client *http.Client, dir string, plan Plan) (StageResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	stagingClient, err := boundedUpdateHTTPClient(client)
	if err != nil {
		return StageResult{}, err
	}
	if plan.ArtifactSize <= 0 || plan.ArtifactSize > maxArtifactBytes {
		return StageResult{}, fmt.Errorf("invalid staged artifact size %d", plan.ArtifactSize)
	}
	if _, err := hex.DecodeString(plan.ArtifactSHA256); err != nil || len(plan.ArtifactSHA256) != 64 {
		return StageResult{}, fmt.Errorf("invalid staged artifact sha256")
	}
	artifactURL, err := url.Parse(strings.TrimSpace(plan.ArtifactURL))
	if err != nil {
		return StageResult{}, fmt.Errorf("parse update artifact URL: %w", err)
	}
	if err := validateUpdateURL(artifactURL); err != nil {
		return StageResult{}, err
	}
	if strings.TrimSpace(dir) == "" {
		cache, err := os.UserCacheDir()
		if err != nil {
			return StageResult{}, fmt.Errorf("resolve update cache directory: %w", err)
		}
		dir = filepath.Join(cache, "luminet", "updates")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return StageResult{}, fmt.Errorf("create update staging directory: %w", err)
	}

	name := safeStageName(plan.ReleaseID, plan.Version)
	artifactPath := filepath.Join(dir, name+".artifact")
	receiptPath := filepath.Join(dir, name+".json")
	if ok, err := verifyExistingArtifact(artifactPath, plan.ArtifactSize, plan.ArtifactSHA256); err == nil && ok {
		result := StageResult{Plan: plan, Path: artifactPath, ReceiptPath: receiptPath, SHA256: strings.ToLower(plan.ArtifactSHA256), Bytes: plan.ArtifactSize, StagedAt: time.Now().UTC(), ApplyAuthorized: false, Reused: true}
		if err := writeStageReceipt(receiptPath, result); err != nil {
			return StageResult{}, err
		}
		return result, nil
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, plan.ArtifactURL, nil)
	if err != nil {
		return StageResult{}, fmt.Errorf("build update artifact request: %w", err)
	}
	resp, err := stagingClient.Do(req)
	if err != nil {
		return StageResult{}, fmt.Errorf("download update artifact: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return StageResult{}, fmt.Errorf("download update artifact: HTTP %d", resp.StatusCode)
	}
	if resp.ContentLength >= 0 && resp.ContentLength != plan.ArtifactSize {
		return StageResult{}, fmt.Errorf("update artifact content length %d does not match signed size %d", resp.ContentLength, plan.ArtifactSize)
	}

	tmp, err := os.CreateTemp(dir, "."+name+"-*.partial")
	if err != nil {
		return StageResult{}, fmt.Errorf("create staged update artifact: %w", err)
	}
	tmpPath := tmp.Name()
	published := false
	defer func() {
		_ = tmp.Close()
		if !published {
			_ = os.Remove(tmpPath)
		}
	}()

	hash := sha256.New()
	reader := io.LimitReader(resp.Body, plan.ArtifactSize+maxStagingResponseOverhead)
	written, copyErr := io.Copy(io.MultiWriter(tmp, hash), reader)
	if copyErr != nil {
		return StageResult{}, fmt.Errorf("write staged update artifact: %w", copyErr)
	}
	if written != plan.ArtifactSize {
		return StageResult{}, fmt.Errorf("update artifact size %d does not match signed size %d", written, plan.ArtifactSize)
	}
	actualDigest := hex.EncodeToString(hash.Sum(nil))
	if !strings.EqualFold(actualDigest, plan.ArtifactSHA256) {
		return StageResult{}, fmt.Errorf("update artifact sha256 mismatch")
	}
	if err := tmp.Sync(); err != nil {
		return StageResult{}, fmt.Errorf("sync staged update artifact: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return StageResult{}, fmt.Errorf("close staged update artifact: %w", err)
	}
	if err := os.Chmod(tmpPath, 0o600); err != nil {
		return StageResult{}, fmt.Errorf("set staged artifact permissions: %w", err)
	}
	if err := replaceStagedFile(tmpPath, artifactPath); err != nil {
		return StageResult{}, fmt.Errorf("publish staged update artifact: %w", err)
	}
	published = true

	result := StageResult{Plan: plan, Path: artifactPath, ReceiptPath: receiptPath, SHA256: actualDigest, Bytes: written, StagedAt: time.Now().UTC(), ApplyAuthorized: false, Reused: false}
	if err := writeStageReceipt(receiptPath, result); err != nil {
		return StageResult{}, err
	}
	return result, nil
}

func boundedUpdateHTTPClient(client *http.Client) (*http.Client, error) {
	base := client
	if base == nil {
		base = &http.Client{Timeout: 20 * time.Minute}
	}
	clone := *base
	if clone.Timeout <= 0 {
		clone.Timeout = 20 * time.Minute
	}
	priorRedirect := clone.CheckRedirect
	clone.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if len(via) >= 5 {
			return fmt.Errorf("update artifact redirect limit exceeded")
		}
		if err := validateUpdateURL(req.URL); err != nil {
			return err
		}
		if priorRedirect != nil {
			return priorRedirect(req, via)
		}
		return nil
	}
	return &clone, nil
}

func validateUpdateURL(candidate *url.URL) error {
	if candidate == nil || candidate.Scheme != "https" || candidate.Host == "" || candidate.User != nil || candidate.Fragment != "" {
		return errors.New("update artifact URL must remain absolute HTTPS without userinfo or fragment")
	}
	return nil
}

func replaceStagedFile(source, target string) error {
	if info, err := os.Lstat(target); err == nil {
		if !info.Mode().IsRegular() {
			return fmt.Errorf("refusing to replace non-regular staged path %s", target)
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	if err := replacePublishedStagedFile(source, target); err != nil {
		return err
	}
	if err := syncStageDirectory(filepath.Dir(target)); err != nil {
		return fmt.Errorf("sync staging directory: %w", err)
	}
	return nil
}

func safeStageName(releaseID, version string) string {
	releaseID = strings.Trim(safeStageComponent.ReplaceAllString(strings.TrimSpace(releaseID), "_"), "._-")
	version = strings.Trim(safeStageComponent.ReplaceAllString(strings.TrimSpace(version), "_"), "._-")
	if releaseID == "" {
		releaseID = "release"
	}
	if version == "" {
		version = "unknown"
	}
	if len(releaseID) > 80 {
		releaseID = releaseID[:80]
	}
	if len(version) > 48 {
		version = version[:48]
	}
	return releaseID + "-" + version
}

func verifyExistingArtifact(path string, size int64, digest string) (bool, error) {
	file, err := os.Open(path)
	if err != nil {
		return false, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() != size {
		return false, err
	}
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return false, err
	}
	return strings.EqualFold(hex.EncodeToString(hash.Sum(nil)), digest), nil
}

func writeStageReceipt(path string, result StageResult) error {
	data, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return fmt.Errorf("encode update stage receipt: %w", err)
	}
	data = append(data, '\n')
	tmp, err := os.CreateTemp(filepath.Dir(path), ".receipt-*.tmp")
	if err != nil {
		return fmt.Errorf("create update stage receipt: %w", err)
	}
	tmpPath := tmp.Name()
	ok := false
	defer func() {
		_ = tmp.Close()
		if !ok {
			_ = os.Remove(tmpPath)
		}
	}()
	if err := tmp.Chmod(0o600); err != nil {
		return fmt.Errorf("set update receipt permissions: %w", err)
	}
	if _, err := tmp.Write(data); err != nil {
		return fmt.Errorf("write update stage receipt: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		return fmt.Errorf("sync update stage receipt: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close update stage receipt: %w", err)
	}
	if err := replaceStagedFile(tmpPath, path); err != nil {
		return fmt.Errorf("publish update stage receipt: %w", err)
	}
	ok = true
	return nil
}
