package diagnostics

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"math"
	"strings"
)

type UpdateRolloutPlanRequest struct {
	Version             string  `json:"version"`
	Rollout             float64 `json:"rollout"`
	CohortSeed          uint32  `json:"cohort_seed"`
	MetadataSequence    uint64  `json:"metadata_sequence"`
	HighestSeenSequence uint64  `json:"highest_seen_sequence,omitempty"`
}

type UpdateRolloutPlan struct {
	Version                        string   `json:"version"`
	Rollout                        float64  `json:"rollout"`
	CohortThreshold                float64  `json:"cohort_threshold"`
	Eligible                       bool     `json:"eligible"`
	Withdrawn                      bool     `json:"withdrawn"`
	SequenceFresh                  bool     `json:"sequence_fresh"`
	MetadataReplayRejected         bool     `json:"metadata_replay_rejected"`
	RequiresPersistedHighWaterMark bool     `json:"requires_persisted_high_water_mark"`
	PersistsHighWaterMark          bool     `json:"persists_high_water_mark"`
	DownloadsArtifact              bool     `json:"downloads_artifact"`
	InstallsUpdate                 bool     `json:"installs_update"`
	Reasons                        []string `json:"reasons"`
	Invariants                     []string `json:"invariants"`
	ReadOnly                       bool     `json:"read_only"`
}

func BuildUpdateRolloutPlan(req UpdateRolloutPlanRequest) (UpdateRolloutPlan, error) {
	version := strings.TrimSpace(req.Version)
	if version == "" || len(version) > 128 {
		return UpdateRolloutPlan{}, fmt.Errorf("version must be 1..128 bytes")
	}
	if math.IsNaN(req.Rollout) || math.IsInf(req.Rollout, 0) || req.Rollout < 0 || req.Rollout > 1 {
		return UpdateRolloutPlan{}, fmt.Errorf("rollout must be a finite value in 0..1")
	}
	if req.MetadataSequence == 0 {
		return UpdateRolloutPlan{}, fmt.Errorf("metadata_sequence must be non-zero")
	}
	material := fmt.Sprintf("%d\x00%s", req.CohortSeed, version)
	digest := sha256.Sum256([]byte(material))
	raw := binary.BigEndian.Uint64(digest[:8])
	maxUint := ^uint64(0)
	threshold := (float64(raw) + 1.0) / (float64(maxUint) + 1.0)
	if threshold <= 0 {
		threshold = math.SmallestNonzeroFloat64
	}
	if threshold > 1 {
		threshold = 1
	}
	fresh := req.HighestSeenSequence == 0 || req.MetadataSequence >= req.HighestSeenSequence
	withdrawn := req.Rollout == 0
	eligible := !withdrawn && fresh && (req.Rollout >= threshold || req.Rollout == 1)
	plan := UpdateRolloutPlan{
		Version: version, Rollout: req.Rollout, CohortThreshold: threshold, Eligible: eligible, Withdrawn: withdrawn,
		SequenceFresh: fresh, MetadataReplayRejected: !fresh, RequiresPersistedHighWaterMark: true, PersistsHighWaterMark: false,
		DownloadsArtifact: false, InstallsUpdate: false, ReadOnly: true,
		Invariants: []string{
			"rollout must be finite and remain in the closed interval 0..1",
			"a zero rollout withdraws the release from notification eligibility",
			"cohort membership is deterministic for a stable seed and release version",
			"signed metadata with a sequence lower than the highest previously accepted sequence is rejected as replay/stale evidence",
			"the monotonic metadata high-water mark must be persisted by the signed-update authority before replay protection can be claimed end to end",
			"rollout eligibility never bypasses signature, expiry, version-transition, artifact-size, or artifact-hash verification",
			"this planner downloads no metadata or artifact and installs no update",
		},
	}
	if withdrawn {
		plan.Reasons = append(plan.Reasons, "rollout is zero; release is withdrawn for notification eligibility")
	}
	if !fresh {
		plan.Reasons = append(plan.Reasons, "metadata sequence is below the caller-supplied high-water mark")
	}
	if fresh && !withdrawn && !eligible {
		plan.Reasons = append(plan.Reasons, "client cohort threshold is above the current rollout fraction")
	}
	if eligible {
		plan.Reasons = append(plan.Reasons, "client cohort is eligible, subject to the existing signed-update admission authority")
	}
	return plan, nil
}
