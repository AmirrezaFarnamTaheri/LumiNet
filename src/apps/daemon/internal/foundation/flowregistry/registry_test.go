package flowregistry

import (
	"context"
	"errors"
	"fmt"
	"sync/atomic"
	"testing"
	"time"
)

func TestRegistryLifecycleCountersAndCopyIsolation(t *testing.T) {
	r := New(4)
	if err := r.DeclareOwner(OwnerCoverage{Owner: "evasion", Visible: true, Closeable: true, ByteCounters: true, DestinationMetadata: true, Notes: []string{"tcp only"}}); err != nil {
		t.Fatal(err)
	}
	d := Descriptor{Owner: "evasion", Network: "TCP", Destination: "example.com:443", Chain: []string{"direct"}, Labels: map[string]string{"route": "proxy"}, StartedAt: time.Unix(100, 0)}
	h, err := r.Register(d, func(context.Context) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	h.AddUpload(10)
	h.AddDownload(20)
	got := r.Snapshot()
	if len(got) != 1 {
		t.Fatalf("len=%d", len(got))
	}
	if got[0].Network != "tcp" || got[0].UploadBytes != 10 || got[0].DownloadBytes != 20 || !got[0].Closeable {
		t.Fatalf("snapshot=%+v", got[0])
	}
	got[0].Chain[0] = "mutated"
	got[0].Labels["route"] = "mutated"
	again, _ := r.Get(h.ID())
	if again.Chain[0] != "direct" || again.Labels["route"] != "proxy" {
		t.Fatalf("registry state leaked through snapshot: %+v", again)
	}
	h.End()
	if len(r.Snapshot()) != 0 {
		t.Fatal("End did not remove flow")
	}
}

func TestCloseRunsOutsideLockAndRemovesOnSuccess(t *testing.T) {
	r := New(4)
	if err := r.DeclareOwner(OwnerCoverage{Owner: "relay", Visible: true, Closeable: true}); err != nil {
		t.Fatal(err)
	}
	var called atomic.Int32
	var id string
	h, err := r.Register(Descriptor{Owner: "relay"}, func(context.Context) error {
		called.Add(1)
		if _, ok := r.Get(id); !ok {
			t.Error("flow disappeared before owner close callback")
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	id = h.ID()
	if err := r.Close(context.Background(), id); err != nil {
		t.Fatal(err)
	}
	if called.Load() != 1 {
		t.Fatalf("called=%d", called.Load())
	}
	if _, ok := r.Get(id); ok {
		t.Fatal("flow remains after successful close")
	}
}

func TestCloseFailureRestoresActive(t *testing.T) {
	r := New(2)
	if err := r.DeclareOwner(OwnerCoverage{Owner: "runtime", Visible: true, Closeable: true}); err != nil {
		t.Fatal(err)
	}
	want := errors.New("busy")
	h, err := r.Register(Descriptor{Owner: "runtime"}, func(context.Context) error { return want })
	if err != nil {
		t.Fatal(err)
	}
	if err := r.Close(context.Background(), h.ID()); !errors.Is(err, want) {
		t.Fatalf("err=%v", err)
	}
	s, ok := r.Get(h.ID())
	if !ok || s.State != StateActive {
		t.Fatalf("snapshot=%+v ok=%v", s, ok)
	}
}

func TestCapacityValidationAndExplicitBulkBound(t *testing.T) {
	r := New(1)
	if _, err := r.Register(Descriptor{Owner: ""}, nil); err == nil {
		t.Fatal("accepted empty owner")
	}
	if err := r.DeclareOwner(OwnerCoverage{Owner: "one", Visible: true}); err != nil {
		t.Fatal(err)
	}
	if err := r.DeclareOwner(OwnerCoverage{Owner: "two", Visible: true}); err != nil {
		t.Fatal(err)
	}
	h, err := r.Register(Descriptor{Owner: "one"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.Register(Descriptor{Owner: "two"}, nil); !errors.Is(err, ErrCapacity) {
		t.Fatalf("err=%v", err)
	}
	if err := r.Close(context.Background(), h.ID()); !errors.Is(err, ErrNotCloseable) {
		t.Fatalf("err=%v", err)
	}
}

func TestDeclareOwnerIsTruthfulAndSorted(t *testing.T) {
	r := New(1)
	if err := r.DeclareOwner(OwnerCoverage{Owner: "z", Visible: true}); err != nil {
		t.Fatal(err)
	}
	if err := r.DeclareOwner(OwnerCoverage{Owner: "a", Visible: true, ProcessAttribution: false}); err != nil {
		t.Fatal(err)
	}
	got := r.Coverage()
	if len(got) != 2 || got[0].Owner != "a" || got[1].Owner != "z" {
		t.Fatalf("coverage=%+v", got)
	}
}

func TestStatsReflectRegisteredAndClosingFlows(t *testing.T) {
	r := New(3)
	if err := r.DeclareOwner(OwnerCoverage{Owner: "a", Visible: true, Closeable: true, ByteCounters: true}); err != nil {
		t.Fatal(err)
	}
	if err := r.DeclareOwner(OwnerCoverage{Owner: "b", Visible: true, ByteCounters: true}); err != nil {
		t.Fatal(err)
	}
	block := make(chan struct{})
	h1, err := r.Register(Descriptor{Owner: "a"}, func(context.Context) error { <-block; return nil })
	if err != nil {
		t.Fatal(err)
	}
	h2, err := r.Register(Descriptor{Owner: "b"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	h1.AddUpload(7)
	h2.AddDownload(11)

	closeDone := make(chan error, 1)
	go func() { closeDone <- r.Close(context.Background(), h1.ID()) }()
	deadline := time.Now().Add(time.Second)
	for {
		st := r.Stats()
		if st.Closing == 1 {
			if st.Active != 1 || st.Capacity != 3 || st.UploadBytes != 7 || st.DownloadBytes != 11 {
				t.Fatalf("stats=%+v", st)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("flow never entered closing state")
		}
		time.Sleep(time.Millisecond)
	}
	close(block)
	if err := <-closeDone; err != nil {
		t.Fatal(err)
	}
	st := r.Stats()
	if st.Active != 1 || st.Closing != 0 || st.UploadBytes != 0 || st.DownloadBytes != 11 {
		t.Fatalf("post-close stats=%+v", st)
	}
}

func TestRegisterRequiresTruthfulOwnerCoverage(t *testing.T) {
	r := New(4)
	if _, err := r.Register(Descriptor{Owner: "missing"}, nil); !errors.Is(err, ErrOwnerUndeclared) {
		t.Fatalf("undeclared owner err=%v", err)
	}
	if err := r.DeclareOwner(OwnerCoverage{Owner: "limited", Visible: true}); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Register(Descriptor{Owner: "limited", Destination: "example.test:443"}, nil); !errors.Is(err, ErrCoverageMismatch) {
		t.Fatalf("destination mismatch err=%v", err)
	}
	if _, err := r.Register(Descriptor{Owner: "limited"}, func(context.Context) error { return nil }); !errors.Is(err, ErrCoverageMismatch) {
		t.Fatalf("close mismatch err=%v", err)
	}
	if err := r.DeclareOwner(OwnerCoverage{Owner: "hidden", Visible: false}); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Register(Descriptor{Owner: "hidden"}, nil); !errors.Is(err, ErrCoverageMismatch) {
		t.Fatalf("hidden owner err=%v", err)
	}
}

func TestCoverageCannotContradictLiveFlow(t *testing.T) {
	r := New(2)
	if err := r.DeclareOwner(OwnerCoverage{Owner: "owner", Visible: true, Closeable: true, ByteCounters: true, DestinationMetadata: true}); err != nil {
		t.Fatal(err)
	}
	h, err := r.Register(Descriptor{Owner: "owner", Destination: "198.51.100.1:443"}, func(context.Context) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	h.AddUpload(1)
	for _, bad := range []OwnerCoverage{
		{Owner: "owner", Visible: false, Closeable: true, ByteCounters: true, DestinationMetadata: true},
		{Owner: "owner", Visible: true, Closeable: false, ByteCounters: true, DestinationMetadata: true},
		{Owner: "owner", Visible: true, Closeable: true, ByteCounters: false, DestinationMetadata: true},
		{Owner: "owner", Visible: true, Closeable: true, ByteCounters: true, DestinationMetadata: false},
	} {
		if err := r.DeclareOwner(bad); !errors.Is(err, ErrCoverageMismatch) {
			t.Fatalf("contradictory coverage %+v err=%v", bad, err)
		}
	}
}

func TestCloseIDsRejectsOversizedBatchWithoutPartialClose(t *testing.T) {
	r := New(16)
	if err := r.DeclareOwner(OwnerCoverage{Owner: "bulk", Visible: true, Closeable: true}); err != nil {
		t.Fatal(err)
	}
	closed := 0
	id, err := r.Register(Descriptor{Owner: "bulk", Network: "tcp", Protocol: "test"}, func(context.Context) error {
		closed++
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	ids := make([]string, MaxBulkCloseFlows+1)
	ids[0] = id.ID()
	for i := 1; i < len(ids); i++ {
		ids[i] = fmt.Sprintf("missing-%d", i)
	}
	if got, err := r.CloseIDs(context.Background(), ids); err == nil || got != nil {
		t.Fatalf("expected oversized batch rejection, got result=%v err=%v", got, err)
	}
	if closed != 0 {
		t.Fatalf("oversized batch performed partial close: closed=%d", closed)
	}
	if _, ok := r.Get(id.ID()); !ok {
		t.Fatal("flow disappeared after rejected oversized batch")
	}
}
