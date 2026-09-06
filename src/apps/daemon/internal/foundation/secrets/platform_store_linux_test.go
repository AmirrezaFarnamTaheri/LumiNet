//go:build linux

package secrets

import "testing"

func TestSecretServiceStoreIdentity(t *testing.T) {
	store := &SecretServiceStore{}
	if got := store.ProviderName(); got != "secretservice" {
		t.Fatalf("ProviderName() = %q", got)
	}
	if !store.Native() {
		t.Fatal("Native() = false")
	}
}

func TestSecretServiceRefValidation(t *testing.T) {
	if err := validNativeRef(""); err == nil {
		t.Fatal("empty ref was accepted")
	}
	if err := validNativeRef("ddns/token"); err != nil {
		t.Fatalf("valid ref rejected: %v", err)
	}
}
