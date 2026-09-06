package jobs

import (
	"context"
	"time"

	"github.com/maybeknott/luminet/internal/foundation/evidence"
	"github.com/maybeknott/luminet/internal/native/bridge"
)

func mapAliveState(alive bool) evidence.ProbeState {
	if alive {
		return evidence.StateAlive
	}
	return evidence.StateDead
}

func (m *JobManager) completeProbeBatch(ctx context.Context, job *Job, results []bridge.ProbeResult) error {
	for _, result := range results {
		meta := make(map[string]interface{})
		if result.Metadata != nil {
			for k, v := range result.Metadata {
				meta[k] = v
			}
		}
		item := &evidence.ProbeEvidence{
			ID:          generateUUID(),
			JobID:       job.ID,
			Kind:        evidence.ProbeICMP,
			Target:      result.Target,
			IP:          result.IP,
			Port:        int(result.Port),
			State:       mapAliveState(result.Alive),
			Reason:      result.ErrorCode,
			LatencyMs:   result.LatencyMs,
			StartedAt:   time.Unix(int64(result.Timestamp), 0),
			CompletedAt: time.Now(),
			Error:       result.Error,
			Metadata:    meta,
		}
		if err := m.persistEvidence(ctx, item); err != nil {
			return err
		}
		m.publishEvent(JobEvent{
			JobID:     job.ID,
			Type:      "probe_result",
			Data:      item,
			Timestamp: time.Now(),
		})
	}
	return nil
}

func (m *JobManager) completePortBatch(ctx context.Context, job *Job, results []bridge.PortResult) error {
	for _, result := range results {
		state := evidence.StateDead
		if result.Open {
			state = evidence.StateAlive
		}
		meta := map[string]interface{}{
			"protocol": result.Protocol,
			"service":  result.Service,
			"banner":   result.Banner,
		}
		item := &evidence.ProbeEvidence{
			ID:          generateUUID(),
			JobID:       job.ID,
			Kind:        evidence.ProbeTCP,
			Target:      result.IP,
			IP:          result.IP,
			Port:        int(result.Port),
			State:       state,
			LatencyMs:   result.LatencyMs,
			StartedAt:   time.Now().Add(-time.Duration(result.LatencyMs) * time.Millisecond),
			CompletedAt: time.Now(),
			Metadata:    meta,
		}
		if err := m.persistEvidence(ctx, item); err != nil {
			return err
		}
		m.publishEvent(JobEvent{
			JobID:     job.ID,
			Type:      "probe_result",
			Data:      item,
			Timestamp: time.Now(),
		})
	}
	return nil
}

func (m *JobManager) completeDnsResult(ctx context.Context, job *Job, result *bridge.DnsServerResult) error {
	if result == nil {
		return nil
	}
	state := evidence.StateDead
	if result.Success {
		state = evidence.StateAlive
	}
	meta := map[string]interface{}{
		"server":   result.Server,
		"protocol": result.Protocol,
		"records":  result.Records,
	}
	item := &evidence.ProbeEvidence{
		ID:          generateUUID(),
		JobID:       job.ID,
		Kind:        evidence.ProbeDNS,
		Target:      result.Server,
		State:       state,
		LatencyMs:   result.LatencyMs,
		StartedAt:   time.Now().Add(-time.Duration(result.LatencyMs) * time.Millisecond),
		CompletedAt: time.Now(),
		Error:       result.Error,
		Metadata:    meta,
	}
	if err := m.persistEvidence(ctx, item); err != nil {
		return err
	}
	m.publishEvent(JobEvent{
		JobID:     job.ID,
		Type:      "probe_result",
		Data:      item,
		Timestamp: time.Now(),
	})
	return nil
}

func (m *JobManager) completeTlsResult(ctx context.Context, job *Job, target string, port int, result *bridge.TlsInfo, err error) error {
	state := evidence.StateDead
	errStr := ""
	if err == nil {
		state = evidence.StateAlive
	} else {
		errStr = err.Error()
	}
	var meta map[string]interface{}
	if result != nil {
		meta = map[string]interface{}{
			"version":            result.Version,
			"cipher_suite":       result.CipherSuite,
			"issuer":             result.CertIssuer,
			"subject":            result.CertSubject,
			"not_before":         result.NotBefore,
			"not_after":          result.NotAfter,
			"serial_number":      result.SerialNumber,
			"alpn":               result.ALPN,
			"san_domains":        result.SanDomains,
			"fingerprint_sha256": result.FingerprintSha256,
			"chain_length":       result.ChainLength,
			"ocsp_stapled":       result.OcspStapled,
		}
	}
	item := &evidence.ProbeEvidence{
		ID:          generateUUID(),
		JobID:       job.ID,
		Kind:        evidence.ProbeTLS,
		Target:      target,
		Port:        port,
		State:       state,
		StartedAt:   time.Now().Add(-100 * time.Millisecond),
		CompletedAt: time.Now(),
		Error:       errStr,
		Metadata:    meta,
	}
	if err := m.persistEvidence(ctx, item); err != nil {
		return err
	}
	m.publishEvent(JobEvent{
		JobID:     job.ID,
		Type:      "probe_result",
		Data:      item,
		Timestamp: time.Now(),
	})
	return nil
}

func (m *JobManager) completeSniResult(ctx context.Context, job *Job, result *bridge.SniResult, err error) error {
	state := evidence.StateDead
	errStr := ""
	if err == nil && result != nil {
		if result.Blocked {
			state = evidence.StateFiltered
		} else {
			state = evidence.StateAlive
		}
	} else if err != nil {
		errStr = err.Error()
	}
	var meta map[string]interface{}
	if result != nil {
		meta = map[string]interface{}{
			"domain":      result.Domain,
			"blocked":     result.Blocked,
			"tls_success": result.TlsSuccess,
			"evidence":    result.Evidence,
			"confidence":  result.Confidence,
		}
		if result.TlsInfo != nil {
			meta["tls_info"] = result.TlsInfo
		}
	}
	item := &evidence.ProbeEvidence{
		ID:    generateUUID(),
		JobID: job.ID,
		Kind:  evidence.ProbeSNI,
		Target: func() string {
			if intent, intentErr := intentAs[SniScanIntent](job); intentErr == nil {
				return intent.Domain
			}
			if result != nil {
				return result.Domain
			}
			return ""
		}(),
		State:       state,
		StartedAt:   time.Now().Add(-100 * time.Millisecond),
		CompletedAt: time.Now(),
		Error:       errStr,
		Metadata:    meta,
	}
	if err := m.persistEvidence(ctx, item); err != nil {
		return err
	}
	m.publishEvent(JobEvent{
		JobID:     job.ID,
		Type:      "probe_result",
		Data:      item,
		Timestamp: time.Now(),
	})
	return nil
}
