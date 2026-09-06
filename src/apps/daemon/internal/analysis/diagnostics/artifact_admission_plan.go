package diagnostics

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
	"path/filepath"
	"strings"
	"unicode/utf8"
)

const maxArtifactAdmissionSampleBytes = 1 << 20

type ArtifactAdmissionRequest struct {
	ID             string `json:"id"`
	Kind           string `json:"kind,omitempty"`
	Filename       string `json:"filename,omitempty"`
	ClaimedFormat  string `json:"claimed_format,omitempty"`
	SourceURL      string `json:"source_url,omitempty"`
	ExpectedSHA256 string `json:"expected_sha256,omitempty"`
	ActualSHA256   string `json:"actual_sha256,omitempty"`
	SizeBytes      int64  `json:"size_bytes,omitempty"`
	ContentBase64  string `json:"content_base64,omitempty"`
}

type ArtifactAdmissionPlan struct {
	ID                  string   `json:"id"`
	Kind                string   `json:"kind,omitempty"`
	Filename            string   `json:"filename,omitempty"`
	ClaimedFormat       string   `json:"claimed_format,omitempty"`
	DetectedFormat      string   `json:"detected_format,omitempty"`
	FormatChecked       bool     `json:"format_checked"`
	FormatMatchesClaim  bool     `json:"format_matches_claim"`
	ObservedSHA256      string   `json:"observed_sha256,omitempty"`
	ObservedBytes       int64    `json:"observed_bytes,omitempty"`
	DetectedSecretKinds []string `json:"detected_secret_kinds"`
	Quarantined         bool     `json:"quarantined"`
	Reasons             []string `json:"reasons"`
	ReadOnly            bool     `json:"read_only"`
	ContentReturned     bool     `json:"content_returned"`
}

func normalizeArtifactFormat(raw string) (string, bool) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "":
		return "", true
	case "zip", "application/zip":
		return "zip", true
	case "deb", "debian", "debian-ar", "application/vnd.debian.binary-package":
		return "debian-ar", true
	case "html", "text/html":
		return "html", true
	case "json", "application/json":
		return "json", true
	case "pem", "application/x-pem-file":
		return "pem", true
	case "gzip", "gz", "application/gzip":
		return "gzip", true
	case "tar", "application/x-tar":
		return "tar", true
	case "text", "text/plain":
		return "text", true
	case "binary", "application/octet-stream":
		return "binary", true
	default:
		return "", false
	}
}

func artifactFormatFromFilename(name string) string {
	lower := strings.ToLower(strings.TrimSpace(name))
	switch {
	case strings.HasSuffix(lower, ".tar.gz"), strings.HasSuffix(lower, ".tgz"):
		return "gzip"
	}
	switch filepath.Ext(lower) {
	case ".zip":
		return "zip"
	case ".deb":
		return "debian-ar"
	case ".html", ".htm":
		return "html"
	case ".json":
		return "json"
	case ".pem", ".crt", ".cer", ".key":
		return "pem"
	case ".gz":
		return "gzip"
	case ".tar":
		return "tar"
	case ".txt", ".md", ".csv", ".yaml", ".yml", ".toml":
		return "text"
	default:
		return ""
	}
}

func detectArtifactFormat(data []byte) string {
	if len(data) == 0 {
		return "empty"
	}
	if len(data) >= 4 && bytes.Equal(data[:2], []byte("PK")) &&
		(bytes.Equal(data[2:4], []byte{0x03, 0x04}) || bytes.Equal(data[2:4], []byte{0x05, 0x06}) || bytes.Equal(data[2:4], []byte{0x07, 0x08})) {
		return "zip"
	}
	if len(data) >= 8 && bytes.Equal(data[:8], []byte("!<arch>\n")) {
		return "debian-ar"
	}
	if len(data) >= 2 && data[0] == 0x1f && data[1] == 0x8b {
		return "gzip"
	}
	if len(data) >= 262 && bytes.Equal(data[257:262], []byte("ustar")) {
		return "tar"
	}
	trimmed := bytes.TrimSpace(bytes.TrimPrefix(data, []byte{0xef, 0xbb, 0xbf}))
	lower := bytes.ToLower(trimmed)
	if bytes.HasPrefix(lower, []byte("<!doctype html")) || bytes.HasPrefix(lower, []byte("<html")) {
		return "html"
	}
	upper := bytes.ToUpper(trimmed)
	if bytes.HasPrefix(upper, []byte("-----BEGIN ")) && bytes.Contains(upper, []byte("-----")) {
		return "pem"
	}
	if json.Valid(trimmed) {
		return "json"
	}
	if utf8.Valid(data) {
		printable := 0
		for _, r := range string(data) {
			if r == '\n' || r == '\r' || r == '\t' || (r >= 0x20 && r != 0x7f) {
				printable++
			}
		}
		if printable*100 >= len([]rune(string(data)))*95 {
			return "text"
		}
	}
	return "binary"
}

func validSHA256(raw string) bool {
	if len(raw) != 64 {
		return false
	}
	b, err := hex.DecodeString(raw)
	return err == nil && len(b) == 32
}

func BuildArtifactAdmissionPlan(req ArtifactAdmissionRequest) (ArtifactAdmissionPlan, error) {
	id := strings.TrimSpace(req.ID)
	if id == "" || len(id) > 128 {
		return ArtifactAdmissionPlan{}, fmt.Errorf("artifact id is required and must be <=128 bytes")
	}
	filename := strings.TrimSpace(req.Filename)
	if len(filename) > 512 || strings.ContainsAny(filename, "\x00\r\n") {
		return ArtifactAdmissionPlan{}, fmt.Errorf("artifact filename must be <=512 bytes and contain no control separators")
	}
	claimed, ok := normalizeArtifactFormat(req.ClaimedFormat)
	if !ok {
		return ArtifactAdmissionPlan{}, fmt.Errorf("unsupported claimed artifact format %q", req.ClaimedFormat)
	}
	filenameClaim := artifactFormatFromFilename(filename)
	if claimed == "" {
		claimed = filenameClaim
	} else if filenameClaim != "" && claimed != filenameClaim {
		return ArtifactAdmissionPlan{}, fmt.Errorf("claimed artifact format %q conflicts with filename %q", claimed, filename)
	}
	plan := ArtifactAdmissionPlan{ID: id, Kind: strings.TrimSpace(req.Kind), Filename: filename, ClaimedFormat: claimed, ReadOnly: true, ContentReturned: false, DetectedSecretKinds: []string{}, Reasons: []string{}}
	if req.SizeBytes < 0 {
		return ArtifactAdmissionPlan{}, fmt.Errorf("artifact size cannot be negative")
	}
	if req.SourceURL != "" {
		u, err := url.Parse(strings.TrimSpace(req.SourceURL))
		if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Fragment != "" {
			plan.Reasons = append(plan.Reasons, "remote artifact URL must be absolute HTTPS without userinfo or fragment")
		}
	}
	expected := strings.ToLower(strings.TrimSpace(req.ExpectedSHA256))
	actual := strings.ToLower(strings.TrimSpace(req.ActualSHA256))
	if expected != "" && !validSHA256(expected) {
		return ArtifactAdmissionPlan{}, fmt.Errorf("expected sha256 is invalid")
	}
	if actual != "" && !validSHA256(actual) {
		return ArtifactAdmissionPlan{}, fmt.Errorf("actual sha256 is invalid")
	}
	if expected != "" && actual != "" && expected != actual {
		plan.Reasons = append(plan.Reasons, "artifact digest mismatch")
	}
	if req.ContentBase64 != "" {
		decoded, err := base64.StdEncoding.DecodeString(req.ContentBase64)
		if err != nil {
			return ArtifactAdmissionPlan{}, fmt.Errorf("content_base64 is invalid")
		}
		if len(decoded) > maxArtifactAdmissionSampleBytes {
			return ArtifactAdmissionPlan{}, fmt.Errorf("artifact sample exceeds %d bytes", maxArtifactAdmissionSampleBytes)
		}
		d := sha256.Sum256(decoded)
		observed := hex.EncodeToString(d[:])
		plan.ObservedSHA256 = observed
		plan.ObservedBytes = int64(len(decoded))
		plan.DetectedFormat = detectArtifactFormat(decoded)
		if claimed != "" {
			plan.FormatChecked = true
			plan.FormatMatchesClaim = plan.DetectedFormat == claimed
			if !plan.FormatMatchesClaim {
				plan.Reasons = append(plan.Reasons, fmt.Sprintf("artifact format mismatch: claimed %s but supplied bytes are %s", claimed, plan.DetectedFormat))
			}
		}
		if req.SizeBytes != 0 && req.SizeBytes != int64(len(decoded)) {
			plan.Reasons = append(plan.Reasons, "declared size does not match supplied bytes")
		}
		if expected != "" && expected != observed {
			plan.Reasons = append(plan.Reasons, "supplied bytes do not match expected digest")
		}
		if actual != "" && actual != observed {
			plan.Reasons = append(plan.Reasons, "supplied bytes do not match actual digest")
		}
		upper := strings.ToUpper(string(decoded))
		markers := []struct{ marker, kind string }{
			{"-----BEGIN PRIVATE KEY-----", "private-key-pem"}, {"-----BEGIN RSA PRIVATE KEY-----", "rsa-private-key-pem"}, {"-----BEGIN EC PRIVATE KEY-----", "ec-private-key-pem"}, {"-----BEGIN OPENSSH PRIVATE KEY-----", "openssh-private-key"}, {"-----BEGIN ENCRYPTED PRIVATE KEY-----", "encrypted-private-key-pem"}, {"-----BEGIN PGP PRIVATE KEY BLOCK-----", "pgp-private-key"},
		}
		for _, m := range markers {
			if strings.Contains(upper, m.marker) {
				plan.DetectedSecretKinds = append(plan.DetectedSecretKinds, m.kind)
			}
		}
		if len(plan.DetectedSecretKinds) > 0 {
			plan.Reasons = append(plan.Reasons, "secret-bearing artifact material detected")
		}
	} else {
		plan.ObservedBytes = req.SizeBytes
		plan.ObservedSHA256 = actual
		if claimed != "" {
			plan.Reasons = append(plan.Reasons, "artifact format claim cannot be verified without supplied bytes")
		}
	}
	plan.Quarantined = len(plan.Reasons) > 0
	return plan, nil
}
