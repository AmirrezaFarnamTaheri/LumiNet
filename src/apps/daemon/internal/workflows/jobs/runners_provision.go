package jobs

import (
	"context"

	"github.com/maybeknott/luminet/internal/integrations/provision"
)

// runVpsProvision executes a VPS setup job.
func (m *JobManager) runVpsProvision(ctx context.Context, job *Job) (interface{}, error) {
	cfg, err := vpsProvisionConfig(job)
	if err != nil {
		return nil, err
	}

	logger := provision.NewProvisionLogger()

	done := make(chan error, 1)
	go func() {
		done <- provision.ProvisionVPS(ctx, cfg, logger)
	}()

	m.UpdateProgress(job.ID, 10)

	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case err := <-done:
			if err != nil {
				return nil, err
			}
			m.UpdateProgress(job.ID, 100)
			return map[string]string{
				"status":  "completed",
				"vps_ip":  cfg.IP,
				"logs":    logger.GetLogs(),
				"message": "VPS successfully provisioned with 3x-ui and Tor routing",
			}, nil
		}
	}
}

// runEdgeDeploy executes a Cloudflare Worker edge deployment job.
func (m *JobManager) runEdgeDeploy(ctx context.Context, job *Job) (interface{}, error) {
	cfg, err := edgeDeployConfig(job)
	if err != nil {
		return nil, err
	}

	logger := provision.NewProvisionLogger()

	done := make(chan error, 1)
	go func() {
		done <- provision.DeployWorker(ctx, cfg, logger)
	}()

	m.UpdateProgress(job.ID, 15)

	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case err := <-done:
			if err != nil {
				return nil, err
			}
			m.UpdateProgress(job.ID, 100)
			subdomain := cfg.ScriptName
			if subdomain == "" {
				subdomain = "luminet-edge-relay"
			}
			return map[string]string{
				"status":    "completed",
				"subdomain": subdomain,
				"logs":      logger.GetLogs(),
				"message":   "Cloudflare Worker Edge Relay successfully deployed",
			}, nil
		}
	}
}
