package cmd

import (
	"bytes"
	"path/filepath"
	"strings"
	"testing"
	"time"

	lcrypto "github.com/maybeknott/luminet/internal/foundation/crypto"
	"github.com/maybeknott/luminet/internal/foundation/secrets"
	"github.com/spf13/cobra"
)

func TestTPMInventoryDoesNotExposeSecretReferenceOrBlobs(t *testing.T) {
	path := filepath.Join(t.TempDir(), "record.json")
	cutoff := time.Now().UTC().Add(time.Hour)
	envelope := lcrypto.TPMEnvelope{
		Version:  lcrypto.TPMEnvelopeVersion,
		RecordID: "record-safe",
		Authorization: secrets.SecretRef{
			Provider: "dpapi",
			Ref:      "secret-reference",
		},
		Profile: lcrypto.DefaultTPMProfile,
		Policy:  lcrypto.DefaultTPMPolicy(),
		Public:  []byte("public-sensitive"),
		Private: []byte("private-sensitive"),
	}
	repository := lcrypto.NewTPMEnvelopeRepository(path)
	if err := repository.Activate(envelope, &lcrypto.LegacyTPMBlobs{Public: []byte("legacy-public"), Private: []byte("legacy-private")}, &cutoff); err != nil {
		t.Fatal(err)
	}

	var output bytes.Buffer
	command := &cobra.Command{}
	command.SetOut(&output)
	command.Flags().String("record", path, "")
	if err := runTPMInventory(command, nil); err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"secret-reference", "public-sensitive", "private-sensitive", "legacy-public", "legacy-private"} {
		if strings.Contains(output.String(), secret) {
			t.Fatalf("inventory exposed %q: %s", secret, output.String())
		}
	}
}
