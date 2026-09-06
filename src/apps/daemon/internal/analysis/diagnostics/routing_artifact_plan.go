package diagnostics

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/url"
	"sort"
	"strings"
)

const (
	maxRoutingArtifacts           = 64
	maxRoutingArtifactBytes int64 = 128 << 20
)

type RoutingArtifactCandidate struct {
	ID             string `json:"id"`
	Kind           string `json:"kind"`
	Format         string `json:"format"`
	SourceURL      string `json:"source_url,omitempty"`
	ExpectedSHA256 string `json:"expected_sha256,omitempty"`
	ActualSHA256   string `json:"actual_sha256,omitempty"`
	Bytes          int64  `json:"bytes"`
	SourceVersion  string `json:"source_version,omitempty"`
	Category       string `json:"category,omitempty"`
	DownloadDetour string `json:"download_detour,omitempty"`
}

type RoutingArtifactRank struct {
	ID            string `json:"id"`
	Admitted      bool   `json:"admitted"`
	Reason        string `json:"reason,omitempty"`
	ProvenanceSHA string `json:"provenance_sha256"`
}

type RoutingArtifactPlan struct {
	Artifacts []RoutingArtifactRank `json:"artifacts"`
	Admitted  []string              `json:"admitted"`
	Rejected  []string              `json:"rejected"`
	ReadOnly  bool                  `json:"read_only"`
	Fetches   bool                  `json:"fetches"`
	Installs  bool                  `json:"installs"`
}

func BuildRoutingArtifactPlan(candidates []RoutingArtifactCandidate) (RoutingArtifactPlan, error) {
	if len(candidates) == 0 || len(candidates) > maxRoutingArtifacts {
		return RoutingArtifactPlan{}, fmt.Errorf("routing artifact count must be between 1 and %d", maxRoutingArtifacts)
	}
	seen := map[string]struct{}{}
	plan := RoutingArtifactPlan{ReadOnly: true, Fetches: false, Installs: false}
	allowedFormat := map[string]bool{"srs": true, "json": true, "mmdb": true, "dat": true, "txt": true, "text": true, "binary": true}
	allowedKind := map[string]bool{"geoip": true, "geosite": true, "ruleset": true, "routing-list": true, "database": true}
	for _, c := range candidates {
		id := strings.TrimSpace(c.ID)
		kind := strings.ToLower(strings.TrimSpace(c.Kind))
		format := strings.ToLower(strings.TrimSpace(c.Format))
		if id == "" || len(id) > 128 || !allowedKind[kind] || !allowedFormat[format] {
			return RoutingArtifactPlan{}, fmt.Errorf("invalid routing artifact identity %q", id)
		}
		if _, ok := seen[id]; ok {
			return RoutingArtifactPlan{}, fmt.Errorf("duplicate routing artifact %q", id)
		}
		seen[id] = struct{}{}
		if c.Bytes <= 0 || c.Bytes > maxRoutingArtifactBytes {
			return RoutingArtifactPlan{}, fmt.Errorf("routing artifact %q size outside 1..%d", id, maxRoutingArtifactBytes)
		}
		expected := strings.ToLower(strings.TrimSpace(c.ExpectedSHA256))
		actual := strings.ToLower(strings.TrimSpace(c.ActualSHA256))
		remote := strings.TrimSpace(c.SourceURL) != ""
		reason := ""
		admitted := true
		if remote {
			u, err := url.Parse(strings.TrimSpace(c.SourceURL))
			if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Fragment != "" {
				admitted = false
				reason = "remote source must be credential-free HTTPS"
			}
			if expected == "" {
				admitted = false
				reason = "remote routing artifact requires expected SHA-256"
			}
		}
		if expected != "" && !validSHA256(expected) {
			return RoutingArtifactPlan{}, fmt.Errorf("routing artifact %q expected sha256 invalid", id)
		}
		if actual != "" && !validSHA256(actual) {
			return RoutingArtifactPlan{}, fmt.Errorf("routing artifact %q actual sha256 invalid", id)
		}
		if expected != "" && actual != "" && expected != actual {
			admitted = false
			reason = "digest mismatch"
		}
		canonical := strings.Join([]string{id, kind, format, strings.TrimSpace(c.SourceURL), expected, actual, fmt.Sprint(c.Bytes), strings.TrimSpace(c.SourceVersion), strings.TrimSpace(c.Category), strings.TrimSpace(c.DownloadDetour)}, "\x00")
		d := sha256.Sum256([]byte(canonical))
		rank := RoutingArtifactRank{ID: id, Admitted: admitted, Reason: reason, ProvenanceSHA: hex.EncodeToString(d[:])}
		plan.Artifacts = append(plan.Artifacts, rank)
		if admitted {
			plan.Admitted = append(plan.Admitted, id)
		} else {
			plan.Rejected = append(plan.Rejected, id)
		}
	}
	sort.Slice(plan.Artifacts, func(i, j int) bool { return plan.Artifacts[i].ID < plan.Artifacts[j].ID })
	sort.Strings(plan.Admitted)
	sort.Strings(plan.Rejected)
	return plan, nil
}
