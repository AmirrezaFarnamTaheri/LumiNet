package jobs

import (
	"context"
	"strings"
	"testing"
	"time"
)

func interruptedJob(jobType JobType, config string) *Job {
	now := time.Now()
	return &Job{
		ID:          "source-job",
		Type:        jobType,
		Status:      JobStatusFailed,
		CreatedAt:   now.Add(-time.Minute),
		CompletedAt: &now,
		Config:      config,
		Error:       interruptedByRestartError,
	}
}

func TestRecoveryInfoRequiresInterruptedReconstructibleProbe(t *testing.T) {
	probe := interruptedJob(JobTypeDnsScan, `{"server":"1.1.1.1","domain":"example.com","record_type":"A","timeout_ms":1000}`)
	info := recoveryInfoFor(probe)
	if !info.Interrupted || !info.Reconstructible || !info.RequiresConfirmation || info.Policy != recoveryPolicyExplicitNewExecution {
		t.Fatalf("unexpected recovery info: %+v", info)
	}

	for _, tt := range []struct {
		name string
		job  *Job
	}{
		{"proxy credentials redacted", interruptedJob(JobTypeProxyTest, `{"proxy_uri":"socks5://example.com:1080"}`)},
		{"vps mutation", interruptedJob(JobTypeVpsProvision, `{}`)},
		{"edge mutation", interruptedJob(JobTypeEdgeDeploy, `{}`)},
		{"ordinary failure", &Job{ID: "failed", Type: JobTypeDnsScan, Status: JobStatusFailed, Error: "timeout", Config: `{}`}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			got := recoveryInfoFor(tt.job)
			if got.Reconstructible || got.RequiresConfirmation {
				t.Fatalf("unsafe recovery classification: %+v", got)
			}
		})
	}
}

func TestRestorePersistedIntentRejectsRedactedAndMutationJobs(t *testing.T) {
	for _, jobType := range []JobType{JobTypeProxyTest, JobTypeVpsProvision, JobTypeEdgeDeploy} {
		if _, err := restorePersistedIntent(jobType, `{}`); err == nil {
			t.Fatalf("%s unexpectedly reconstructible", jobType)
		}
	}
	if _, err := restorePersistedIntent(JobTypeDnsScan, `{bad-json`); err == nil {
		t.Fatal("malformed persisted intent was accepted")
	}
}

func TestRequeueInterruptedPreservesSourceAndBlocksActiveDuplicate(t *testing.T) {
	m := &JobManager{jobs: map[string]*Job{}, ctx: context.Background()}
	source := interruptedJob(JobTypeDnsScan, `{"server":"1.1.1.1","domain":"example.com","record_type":"A","timeout_ms":1000}`)
	m.jobs[source.ID] = source

	newID, err := m.RequeueInterrupted(source.ID)
	if err != nil {
		t.Fatal(err)
	}
	if newID == source.ID || strings.TrimSpace(newID) == "" {
		t.Fatalf("invalid recovery id %q", newID)
	}
	recovered, err := m.GetJob(newID)
	if err != nil {
		t.Fatal(err)
	}
	if recovered.Status != JobStatusQueued || recovered.RecoveredFrom != source.ID {
		t.Fatalf("bad recovery descendant: %+v", recovered)
	}
	original, err := m.GetJob(source.ID)
	if err != nil {
		t.Fatal(err)
	}
	if original.Status != JobStatusFailed || original.Error != interruptedByRestartError {
		t.Fatalf("source job mutated: %+v", original)
	}
	if _, err := m.RequeueInterrupted(source.ID); err == nil || !strings.Contains(err.Error(), "active recovery") {
		t.Fatalf("duplicate active recovery not rejected: %v", err)
	}
}

func TestGetRecoveryInfoReportsActiveDescendantWithoutChangingReconstructibility(t *testing.T) {
	m := &JobManager{jobs: map[string]*Job{}, ctx: context.Background()}
	source := interruptedJob(JobTypeDnsScan, `{"server":"1.1.1.1","domain":"example.com","record_type":"A","timeout_ms":1000}`)
	m.jobs[source.ID] = source

	info, err := m.GetRecoveryInfo(source.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !info.Reconstructible || !info.RequeueAvailable || info.ActiveDescendant != "" {
		t.Fatalf("unexpected initial recovery info: %+v", info)
	}

	newID, err := m.RequeueInterrupted(source.ID)
	if err != nil {
		t.Fatal(err)
	}
	info, err = m.GetRecoveryInfo(source.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !info.Reconstructible || info.RequeueAvailable || info.ActiveDescendant != newID {
		t.Fatalf("active descendant truth missing: %+v", info)
	}
}
