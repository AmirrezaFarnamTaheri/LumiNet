package sub

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"
)

func TestProfileServiceReturnsIndependentSnapshots(t *testing.T) {
	service := NewProfileService()
	expire := time.Unix(1_700_000_000, 0).UTC()
	original := ManagedProfile{
		ID:          "profile-1",
		Name:        "Primary",
		URL:         "https://example.test/sub",
		LastUpdated: time.Unix(1_600_000_000, 0).UTC(),
		Info: &ProfileInfo{
			Total:  1024,
			Expire: expire,
		},
		Active: true,
	}

	created := service.Create(original)
	original.Info.Total = 1
	created.Name = "mutated"
	created.Info.Total = 2

	stored, ok := service.Get(original.ID)
	if !ok {
		t.Fatal("created profile was not found")
	}
	if stored.Name != "Primary" {
		t.Fatalf("stored name = %q, want Primary", stored.Name)
	}
	if stored.Info == nil || stored.Info.Total != 1024 {
		t.Fatalf("stored metadata was mutated through an external pointer: %+v", stored.Info)
	}

	stored.Info.Total = 3
	again, _ := service.Get(original.ID)
	if again.Info == nil || again.Info.Total != 1024 {
		t.Fatalf("Get returned shared metadata: %+v", again.Info)
	}
}

func TestProfileServicePatchPreservesMetadata(t *testing.T) {
	service := NewProfileService()
	service.Create(ManagedProfile{
		ID:     "profile-1",
		Name:   "Before",
		URL:    "https://example.test/sub",
		Info:   &ProfileInfo{Announcement: "maintenance"},
		Active: true,
	})

	name := "After"
	active := false
	updated, ok := service.Update("profile-1", ProfilePatch{
		Name:   &name,
		Active: &active,
	})
	if !ok {
		t.Fatal("profile was not updated")
	}
	if updated.Name != name || updated.Active {
		t.Fatalf("patch not applied: %+v", updated)
	}
	if updated.Info == nil || updated.Info.Announcement != "maintenance" {
		t.Fatalf("metadata was not preserved: %+v", updated.Info)
	}
}

func TestProfileServiceRejectsStaleRefresh(t *testing.T) {
	service := NewProfileService()
	service.Create(ManagedProfile{
		ID:     "profile-1",
		Name:   "Before",
		URL:    "https://old.example.test/sub",
		Active: true,
	})

	newURL := "https://new.example.test/sub"
	if _, ok := service.Update("profile-1", ProfilePatch{URL: &newURL}); !ok {
		t.Fatal("profile was not updated")
	}

	applied, ok := service.ApplyRefresh(
		"profile-1",
		"https://old.example.test/sub",
		ProfileRefresh{
			Name:        "Stale title",
			NodeCount:   9,
			Info:        &ProfileInfo{Total: 2048},
			LastUpdated: time.Now().UTC(),
		},
	)
	if ok {
		t.Fatalf("stale refresh unexpectedly applied: %+v", applied)
	}

	current, _ := service.Get("profile-1")
	if current.URL != newURL || current.Name != "Before" || current.NodeCount != 0 || current.Info != nil {
		t.Fatalf("stale refresh changed the profile: %+v", current)
	}
}

func TestProfileServiceConcurrentAccess(t *testing.T) {
	service := NewProfileService()
	service.Create(ManagedProfile{
		ID:     "profile-1",
		Name:   "Initial",
		URL:    "https://example.test/sub",
		Active: true,
	})

	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		i := i
		wg.Add(1)
		go func() {
			defer wg.Done()
			name := fmt.Sprintf("profile-%d", i)
			service.Update("profile-1", ProfilePatch{Name: &name})
			service.ApplyRefresh(
				"profile-1",
				"https://example.test/sub",
				ProfileRefresh{
					NodeCount:   i,
					Info:        &ProfileInfo{Download: int64(i)},
					LastUpdated: time.Now().UTC(),
				},
			)
			service.Get("profile-1")
			service.List()
		}()
	}
	wg.Wait()

	if _, ok := service.Get("profile-1"); !ok {
		t.Fatal("profile disappeared during concurrent access")
	}
}

type blockingProfileFetcher struct {
	started chan context.Context
	done    chan error
}

func newBlockingProfileFetcher() *blockingProfileFetcher {
	return &blockingProfileFetcher{
		started: make(chan context.Context, 4),
		done:    make(chan error, 4),
	}
}

func (f *blockingProfileFetcher) Fetch(ctx context.Context, _ string) (EgressResponse, error) {
	f.started <- ctx
	<-ctx.Done()
	f.done <- ctx.Err()
	return EgressResponse{}, ctx.Err()
}

func TestProfileServiceQueuedRefreshFollowsOwnerLifetime(t *testing.T) {
	ownerCtx, ownerCancel := context.WithCancel(context.Background())
	fetcher := newBlockingProfileFetcher()
	service := newProfileService(ownerCtx, fetcher)
	service.Create(ManagedProfile{ID: "profile-1", URL: "https://example.test/sub", RemoteFetchEnabled: true})

	if !service.QueueRefresh("profile-1") {
		t.Fatal("refresh was not queued")
	}
	<-fetcher.started
	ownerCancel()

	select {
	case err := <-fetcher.done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("refresh cancellation error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("refresh did not observe owner cancellation")
	}

	closeCtx, closeCancel := context.WithTimeout(context.Background(), time.Second)
	defer closeCancel()
	if err := service.Close(closeCtx); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
}

func TestProfileServiceRepeatedRefreshCancelsPreviousTask(t *testing.T) {
	fetcher := newBlockingProfileFetcher()
	service := newProfileService(context.Background(), fetcher)
	service.Create(ManagedProfile{ID: "profile-1", URL: "https://example.test/sub", RemoteFetchEnabled: true})

	if !service.QueueRefresh("profile-1") {
		t.Fatal("first refresh was not queued")
	}
	<-fetcher.started
	if !service.QueueRefresh("profile-1") {
		t.Fatal("replacement refresh was not queued")
	}
	<-fetcher.started

	select {
	case err := <-fetcher.done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("replaced refresh error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("replacement did not cancel prior refresh")
	}

	closeCtx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := service.Close(closeCtx); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
}

func TestProfileServiceDeleteCancelsRefresh(t *testing.T) {
	fetcher := newBlockingProfileFetcher()
	service := newProfileService(context.Background(), fetcher)
	service.Create(ManagedProfile{ID: "profile-1", URL: "https://example.test/sub", RemoteFetchEnabled: true})
	service.QueueRefresh("profile-1")
	<-fetcher.started

	if !service.Delete("profile-1") {
		t.Fatal("profile was not deleted")
	}
	select {
	case err := <-fetcher.done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("delete cancellation error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("delete did not cancel refresh")
	}

	closeCtx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := service.Close(closeCtx); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
}

func TestProfileServiceURLChangeCancelsRefresh(t *testing.T) {
	fetcher := newBlockingProfileFetcher()
	service := newProfileService(context.Background(), fetcher)
	service.Create(ManagedProfile{ID: "profile-1", URL: "https://old.example.test/sub", RemoteFetchEnabled: true})
	service.QueueRefresh("profile-1")
	<-fetcher.started

	newURL := "https://new.example.test/sub"
	if _, ok := service.Update("profile-1", ProfilePatch{URL: &newURL}); !ok {
		t.Fatal("profile update failed")
	}
	select {
	case err := <-fetcher.done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("URL-change cancellation error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("URL change did not cancel refresh")
	}

	closeCtx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := service.Close(closeCtx); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
}
