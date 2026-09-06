package jobs

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/maybeknott/luminet/internal/foundation/store"
	"github.com/maybeknott/luminet/internal/integrations/provision"
)

func TestCreateJobKeepsProvisionSecretsOutOfPublicConfig(t *testing.T) {
	m := NewJobManager(context.Background(), nil)
	defer m.Stop()
	id, err := m.CreateJob(VpsProvisionIntent{Config: provision.VpsConfig{IP: "203.0.113.10", SSHPassword: "test-password-secret", SSHKey: "test-key-secret", CFToken: "test-token-secret"}})
	if err != nil {
		t.Fatalf("CreateJob: %v", err)
	}
	job, err := m.GetJob(id)
	if err != nil {
		t.Fatalf("GetJob: %v", err)
	}
	for _, secret := range []string{"test-password-secret", "test-key-secret", "test-token-secret"} {
		if strings.Contains(job.Config, secret) {
			t.Fatalf("public config leaked %q: %s", secret, job.Config)
		}
	}
	if !strings.Contains(job.Config, redactedSecret) {
		t.Fatalf("public config missing redaction marker: %s", job.Config)
	}
	m.mu.RLock()
	live := m.jobs[id]
	m.mu.RUnlock()
	cfg, err := vpsProvisionConfig(live)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.SSHPassword != "test-password-secret" || cfg.SSHKey != "test-key-secret" || cfg.CFToken != "test-token-secret" {
		t.Fatal("execution intent lost provisioning secrets")
	}
}

func TestNewJobManagerScrubsLegacyProvisionSecretsFromDatabase(t *testing.T) {
	db, err := store.OpenDB(t.TempDir() + "/jobs.db")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.Migrate(); err != nil {
		t.Fatal(err)
	}
	legacy, _ := json.Marshal(provision.VpsConfig{IP: "203.0.113.10", SSHPassword: "legacy-password", SSHKey: "legacy-key", CFToken: "legacy-token"})
	if err := db.SaveJobRecord(context.Background(), &store.JobRecord{ID: "legacy", Type: string(JobTypeVpsProvision), Status: string(JobStatusCompleted), Config: string(legacy)}); err != nil {
		t.Fatal(err)
	}
	m := NewJobManager(context.Background(), db)
	defer m.Stop()
	record, err := db.GetJobRecord(context.Background(), "legacy")
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"legacy-password", "legacy-key", "legacy-token"} {
		if strings.Contains(record.Config, secret) {
			t.Fatalf("legacy config leaked %q: %s", secret, record.Config)
		}
	}
}

func TestScrubLegacyProvisionConfigFailsClosedWhenUnreadable(t *testing.T) {
	raw := `{"ssh_password":"test-secret"`
	got, changed := scrubLegacyConfig(JobTypeVpsProvision, raw)
	if !changed {
		t.Fatal("expected unreadable provisioning config to be replaced")
	}
	if got != redactedUnreadableConfig {
		t.Fatalf("scrubbed config = %q, want %q", got, redactedUnreadableConfig)
	}
	if strings.Contains(got, "test-secret") {
		t.Fatalf("scrubbed config leaked secret: %s", got)
	}
}

func TestDnsScanIntentOwnsDefaults(t *testing.T) {
	v, err := normalizeIntent(DnsScanIntent{Domain: "example.test"})
	if err != nil {
		t.Fatal(err)
	}
	dns := v.(DnsScanIntent)
	if dns.Server != "8.8.8.8" || dns.RecordType != "A" || dns.TimeoutMs != 3000 {
		t.Fatalf("defaults = %#v", dns)
	}
}

func TestCreateProxyTestJobPersistsOnlyCredentialFreePreviews(t *testing.T) {
	m := NewJobManager(context.Background(), nil)
	defer m.Stop()
	secret := "super-secret-password"
	raw := "socks5://user:" + secret + "@example.com:1080#office"
	id, err := m.CreateJob(ProxyTestIntent{ProxyURI: raw, Proxies: []string{raw}, Target: "https://example.com/"})
	if err != nil {
		t.Fatal(err)
	}
	job, err := m.GetJob(id)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(job.Config, secret) || strings.Contains(job.Config, "user:") {
		t.Fatalf("proxy credentials leaked into persisted config: %s", job.Config)
	}
	if !strings.Contains(job.Config, "example.com:1080") {
		t.Fatalf("credential-free endpoint preview missing: %s", job.Config)
	}
	m.mu.RLock()
	live := m.jobs[id]
	m.mu.RUnlock()
	intent := live.intent.(ProxyTestIntent)
	if intent.ProxyURI != raw || len(intent.Proxies) != 1 || intent.Proxies[0] != raw {
		t.Fatal("in-memory execution intent lost proxy credentials needed for the live job")
	}
}

func TestScrubLegacyProxyTestConfigRemovesCredentials(t *testing.T) {
	raw := `{"proxy_uri":"socks5://user:legacy-secret@example.com:1080#office","target":"https://example.com/"}`
	got, changed := scrubLegacyConfig(JobTypeProxyTest, raw)
	if !changed {
		t.Fatal("expected legacy proxy test history to be sanitized")
	}
	if strings.Contains(got, "legacy-secret") || strings.Contains(got, "user:") {
		t.Fatalf("legacy proxy credentials survived scrub: %s", got)
	}
	if !strings.Contains(got, "example.com:1080") {
		t.Fatalf("legacy scrub removed useful endpoint preview: %s", got)
	}
}
