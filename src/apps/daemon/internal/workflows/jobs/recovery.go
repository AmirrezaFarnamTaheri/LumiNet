package jobs

import (
	"encoding/json"
	"fmt"
	"strings"
)

const interruptedByRestartError = "server restarted"

const (
	recoveryPolicyNone                  = "not-replayable"
	recoveryPolicyExplicitNewExecution  = "operator-confirmed-new-job"
	recoveryReasonNotInterrupted        = "job was not interrupted by daemon restart"
	recoveryReasonCredentialRedacted    = "persisted execution input intentionally omits credentials required for a faithful replay"
	recoveryReasonConsequentialMutation = "job performs consequential remote mutation and is not eligible for generic replay"
)

// RecoveryInfo describes whether an interrupted historical job can be
// reconstructed from its credential-free durable representation. Reconstructible
// does not mean auto-replayable: all recovered execution requires an explicit
// operator confirmation and is created as a new job with immutable lineage.
type RecoveryInfo struct {
	JobID                string  `json:"job_id"`
	JobType              JobType `json:"job_type"`
	Interrupted          bool    `json:"interrupted"`
	Reconstructible      bool    `json:"reconstructible"`
	RequiresConfirmation bool    `json:"requires_confirmation"`
	RequeueAvailable     bool    `json:"requeue_available"`
	ActiveDescendant     string  `json:"active_descendant,omitempty"`
	Policy               string  `json:"policy"`
	Reason               string  `json:"reason,omitempty"`
}

func recoveryInfoFor(job *Job) RecoveryInfo {
	info := RecoveryInfo{
		JobID:   job.ID,
		JobType: job.Type,
		Policy:  recoveryPolicyNone,
	}
	if job.Status != JobStatusFailed || strings.TrimSpace(job.Error) != interruptedByRestartError {
		info.Reason = recoveryReasonNotInterrupted
		return info
	}
	info.Interrupted = true

	switch job.Type {
	case JobTypeProxyTest:
		info.Reason = recoveryReasonCredentialRedacted
		return info
	case JobTypeVpsProvision, JobTypeEdgeDeploy:
		info.Reason = recoveryReasonConsequentialMutation
		return info
	case JobTypeIcmpScan, JobTypePortScan, JobTypeDnsScan, JobTypeTlsScan,
		JobTypeSniScan, JobTypeDiagnostic, JobTypeSpeedTest, JobTypeWgScan,
		JobTypeCdnScan, JobTypeIpDiscovery:
		info.Reconstructible = true
		info.RequiresConfirmation = true
		info.Policy = recoveryPolicyExplicitNewExecution
		info.Reason = "persisted probe intent is credential-free and reconstructible; replay creates a new execution record"
		return info
	default:
		info.Reason = "job type has no audited recovery contract"
		return info
	}
}

func restorePersistedIntent(jobType JobType, raw string) (JobIntent, error) {
	if strings.TrimSpace(raw) == "" {
		return nil, fmt.Errorf("persisted job config is empty")
	}
	decode := func(dst any) error {
		if err := json.Unmarshal([]byte(raw), dst); err != nil {
			return fmt.Errorf("decode persisted %s intent: %w", jobType, err)
		}
		return nil
	}

	var intent JobIntent
	switch jobType {
	case JobTypeIcmpScan:
		var v IcmpScanIntent
		if err := decode(&v); err != nil {
			return nil, err
		}
		intent = v
	case JobTypePortScan:
		var v PortScanIntent
		if err := decode(&v); err != nil {
			return nil, err
		}
		intent = v
	case JobTypeDnsScan:
		var v DnsScanIntent
		if err := decode(&v); err != nil {
			return nil, err
		}
		intent = v
	case JobTypeTlsScan:
		var v TlsScanIntent
		if err := decode(&v); err != nil {
			return nil, err
		}
		intent = v
	case JobTypeSniScan:
		var v SniScanIntent
		if err := decode(&v); err != nil {
			return nil, err
		}
		intent = v
	case JobTypeDiagnostic:
		var v DiagnosticIntent
		if err := decode(&v); err != nil {
			return nil, err
		}
		intent = v
	case JobTypeSpeedTest:
		var v SpeedTestIntent
		if err := decode(&v); err != nil {
			return nil, err
		}
		intent = v
	case JobTypeWgScan:
		var v WgScanIntent
		if err := decode(&v); err != nil {
			return nil, err
		}
		intent = v
	case JobTypeCdnScan:
		var v CdnScanIntent
		if err := decode(&v); err != nil {
			return nil, err
		}
		intent = v
	case JobTypeIpDiscovery:
		var v IpDiscoveryIntent
		if err := decode(&v); err != nil {
			return nil, err
		}
		intent = v
	case JobTypeProxyTest:
		return nil, fmt.Errorf("proxy_test persisted config is intentionally credential-redacted")
	case JobTypeVpsProvision, JobTypeEdgeDeploy:
		return nil, fmt.Errorf("%s is a consequential mutation and has no generic replay contract", jobType)
	default:
		return nil, fmt.Errorf("job type %s has no audited recovery contract", jobType)
	}

	normalized, err := normalizeIntent(intent)
	if err != nil {
		return nil, fmt.Errorf("normalize persisted %s intent: %w", jobType, err)
	}
	if normalized.jobType() != jobType {
		return nil, fmt.Errorf("persisted intent type mismatch: got %s, want %s", normalized.jobType(), jobType)
	}
	return normalized, nil
}

// GetRecoveryInfo reports restart-recovery eligibility without changing state.
func (m *JobManager) GetRecoveryInfo(id string) (RecoveryInfo, error) {
	job, err := m.GetJob(id)
	if err != nil {
		return RecoveryInfo{}, err
	}
	info := recoveryInfoFor(job)
	if info.Reconstructible {
		if _, err := restorePersistedIntent(job.Type, job.Config); err != nil {
			info.Reconstructible = false
			info.RequiresConfirmation = false
			info.Policy = recoveryPolicyNone
			info.Reason = "persisted intent failed audited reconstruction: " + err.Error()
			return info, nil
		}
		descendant, active, err := m.activeRecoveryDescendant(id)
		if err != nil {
			return RecoveryInfo{}, fmt.Errorf("check active recovery for %s: %w", id, err)
		}
		if active {
			info.ActiveDescendant = descendant
			info.RequeueAvailable = false
			info.Reason = "an operator-confirmed recovery descendant is already queued or running"
		} else {
			info.RequeueAvailable = true
		}
	}
	return info, nil
}

// RequeueInterrupted creates a new queued job from an interrupted historical
// probe intent. It never mutates or restarts the original job and never starts
// execution by itself; the API layer must obtain explicit confirmation and call
// StartJob on the returned ID.
func (m *JobManager) RequeueInterrupted(id string) (string, error) {
	m.recoveryMu.Lock()
	defer m.recoveryMu.Unlock()

	job, err := m.GetJob(id)
	if err != nil {
		return "", err
	}
	info := recoveryInfoFor(job)
	if !info.Reconstructible {
		if info.Reason == "" {
			info.Reason = "job is not reconstructible"
		}
		return "", fmt.Errorf("job %s cannot be recovered: %s", id, info.Reason)
	}
	if descendant, ok, err := m.activeRecoveryDescendant(id); err != nil {
		return "", fmt.Errorf("check active recovery for %s: %w", id, err)
	} else if ok {
		return "", fmt.Errorf("job %s already has active recovery %s", id, descendant)
	}
	intent, err := restorePersistedIntent(job.Type, job.Config)
	if err != nil {
		return "", fmt.Errorf("job %s cannot be recovered: %w", id, err)
	}
	return m.createJob(intent, id)
}

func (m *JobManager) activeRecoveryDescendant(sourceID string) (string, bool, error) {
	if m.db != nil {
		return m.db.FindActiveRecoveredJob(m.ctx, sourceID)
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	for id, job := range m.jobs {
		job.mu.RLock()
		match := job.RecoveredFrom == sourceID && (job.Status == JobStatusQueued || job.Status == JobStatusRunning)
		job.mu.RUnlock()
		if match {
			return id, true, nil
		}
	}
	return "", false, nil
}
