//go:build windows

package secrets

import (
	"bytes"
	"context"
	"testing"
)

func TestNativePlatformStoreSelectsDPAPI(t *testing.T) {
	store, err := OpenNativeStore()
	if err != nil {
		t.Fatal(err)
	}
	if store.ProviderName() != "dpapi" || !store.Native() {
		t.Fatalf("unexpected Windows native store: %T provider=%q native=%v", store, store.ProviderName(), store.Native())
	}
}

func TestDPAPIStoreRoundTrip(t *testing.T) {
	store := &DPAPIStore{dir: t.TempDir()}
	ctx := context.Background()
	value := []byte("tpm-provider-smoke")
	if err := store.Put(ctx, "tpm/smoke", value); err != nil {
		t.Fatal(err)
	}
	got, err := store.Get(ctx, "tpm/smoke")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, value) {
		t.Fatal("DPAPI round-trip mismatch")
	}
	if err := store.Delete(ctx, "tpm/smoke"); err != nil {
		t.Fatal(err)
	}
}
