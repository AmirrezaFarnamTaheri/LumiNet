package jobs

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/maybeknott/luminet/internal/native/bridge"
)

// runJob handles async background FFI calls to Rust core based on JobType
func (m *JobManager) runJob(ctx context.Context, job *Job) {
	m.UpdateProgress(job.ID, 5)

	select {
	case <-ctx.Done():
		m.CancelJob(job.ID)
		return
	default:
	}

	var results interface{}
	var err error

	switch job.Type {
	case JobTypeIcmpScan:
		var scanRes []bridge.ProbeResult
		var rawRes interface{}
		rawRes, err = m.runIcmpScan(ctx, job)
		if err == nil {
			if castRes, ok := rawRes.([]bridge.ProbeResult); ok {
				scanRes = castRes
			}
		}
		results = rawRes
		if err == nil && len(scanRes) > 0 {
			_ = m.completeProbeBatch(ctx, job, scanRes)
		}
	case JobTypePortScan:
		var portRes []bridge.PortResult
		var rawRes interface{}
		rawRes, err = m.runPortScan(ctx, job)
		if err == nil {
			if castRes, ok := rawRes.([]bridge.PortResult); ok {
				portRes = castRes
			}
		}
		results = rawRes
		if err == nil && len(portRes) > 0 {
			_ = m.completePortBatch(ctx, job, portRes)
		}
	case JobTypeDnsScan:
		var dnsRes *bridge.DnsServerResult
		var rawRes interface{}
		rawRes, err = m.runDnsScan(ctx, job)
		if err == nil {
			if castRes, ok := rawRes.(*bridge.DnsServerResult); ok {
				dnsRes = castRes
			}
		}
		results = rawRes
		if err == nil && dnsRes != nil {
			_ = m.completeDnsResult(ctx, job, dnsRes)
		}
	case JobTypeTlsScan:
		var tlsRes *bridge.TlsInfo
		var rawRes interface{}
		rawRes, err = m.runTlsScan(ctx, job)
		if err == nil {
			if castRes, ok := rawRes.(*bridge.TlsInfo); ok {
				tlsRes = castRes
			}
		}
		results = rawRes
		payload, intentErr := intentAs[TlsScanIntent](job)
		if intentErr != nil && err == nil {
			err = intentErr
		}
		_ = m.completeTlsResult(ctx, job, payload.Target, int(payload.Port), tlsRes, err)
	case JobTypeSniScan:
		var sniRes *bridge.SniResult
		var rawRes interface{}
		rawRes, err = m.runSniScan(ctx, job)
		if err == nil {
			if castRes, ok := rawRes.(*bridge.SniResult); ok {
				sniRes = castRes
			}
		}
		results = rawRes
		_ = m.completeSniResult(ctx, job, sniRes, err)
	case JobTypeProxyTest:
		results, err = m.runProxyTest(ctx, job)
	case JobTypeSpeedTest:
		results, err = m.runSpeedTest(ctx, job)
	case JobTypeDiagnostic:
		results, err = m.runDiagnostic(ctx, job)
	case JobTypeWgScan:
		results, err = m.runWgScan(ctx, job)
	case JobTypeCdnScan:
		results, err = m.runCdnScan(ctx, job)
	case JobTypeIpDiscovery:
		results, err = m.runIpDiscovery(ctx, job)
	case JobTypeVpsProvision:
		results, err = m.runVpsProvision(ctx, job)
	case JobTypeEdgeDeploy:
		results, err = m.runEdgeDeploy(ctx, job)
	case JobTypeStreamScan:
		results, err = m.runStreamScan(ctx, job)
	default:
		err = fmt.Errorf("unsupported job type: %s", job.Type)
	}

	if err != nil {
		m.FailJob(job.ID, err.Error())
		return
	}

	resJSON, marshalErr := json.Marshal(results)
	if marshalErr != nil {
		_ = m.FailJob(job.ID, fmt.Sprintf("serialize job result: %v", marshalErr))
		return
	}
	_ = m.UpdateProgress(job.ID, 100)
	_ = m.CompleteJob(job.ID, string(resJSON))
}
