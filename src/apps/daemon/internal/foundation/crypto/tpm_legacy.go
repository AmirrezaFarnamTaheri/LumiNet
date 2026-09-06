package crypto

import (
	"context"
	"errors"
	"time"

	"github.com/maybeknott/luminet/internal/foundation/secrets"
)

const legacyTPMPassword = "LumiNetMasterKeyPassword"

var ErrLegacyTPMSealingDisabled = errors.New("creating compiled-password legacy TPM blobs is disabled")

// SealKeyToTPM is retained for source compatibility with the pre-envelope
// configuration-key path, but it never creates new compiled-password blobs.
// Existing blobs remain readable through UnsealKeyFromTPM.
func SealKeyToTPM(key []byte) (pub []byte, priv []byte, err error) {
	return nil, nil, ErrLegacyTPMSealingDisabled
}

// UnsealKeyFromTPM is the isolated reader for historical compiled-password
// blobs. New envelopes resolve authorization through secrets.Store.
func UnsealKeyFromTPM(pubBlob, privBlob []byte) ([]byte, error) {
	return UnsealKeyFromTPMWithAuthorization(pubBlob, privBlob, []byte(legacyTPMPassword))
}

// MigrateCompiledLegacyTPMToRepository is the sole operator migration adapter
// for blobs created with the historical compiled authorization. New envelopes
// are always sealed through the referenced native-store authorization.
func MigrateCompiledLegacyTPMToRepository(
	ctx context.Context,
	legacyPublic, legacyPrivate []byte,
	store secrets.Store,
	ref secrets.SecretRef,
	repository *TPMEnvelopeRepository,
	cutoff time.Time,
) (TPMEnvelope, error) {
	return MigrateLegacyTPMToRepository(
		ctx,
		legacyPublic,
		legacyPrivate,
		[]byte(legacyTPMPassword),
		store,
		ref,
		SystemTPMSealer{},
		repository,
		&cutoff,
	)
}
