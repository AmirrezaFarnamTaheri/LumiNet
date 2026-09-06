//go:build darwin && cgo

package secrets

import (
	"bytes"
	"context"
	"fmt"
	"testing"
	"time"
)

func TestKeychainStoreIdentity(t *testing.T) {
	store, err := OpenNativeStore()
	if err != nil {
		t.Fatalf("OpenNativeStore: %v", err)
	}
	if store.ProviderName() != "keychain" || !store.Native() {
		t.Fatalf("wrong store identity: %#v", store)
	}
}

func TestKeychainStoreLifecycle(t *testing.T) {
	store, err := OpenNativeStore()
	if err != nil {
		t.Fatalf("OpenNativeStore: %v", err)
	}
	ref := fmt.Sprintf("luminet-test/%d", time.Now().UnixNano())
	ctx := context.Background()
	defer func() { _ = store.Delete(ctx, ref) }()
	want := []byte{0, 1, 2, 0xFF}
	if err := store.Put(ctx, ref, want); err != nil {
		t.Fatalf("Put: %v", err)
	}
	got, err := store.Get(ctx, ref)
	if err != nil || !bytes.Equal(got, want) {
		t.Fatalf("Get = %x, %v; want %x", got, err, want)
	}
	if err := store.Delete(ctx, ref); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := store.Get(ctx, ref); err == nil {
		t.Fatal("Get after Delete succeeded")
	}
}
