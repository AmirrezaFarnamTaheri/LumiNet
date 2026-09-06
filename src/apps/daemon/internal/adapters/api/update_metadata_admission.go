package api

import (
	"context"
	"fmt"
	"time"

	"github.com/maybeknott/luminet/internal/foundation/updateadmission"
)

const updateMetadataProduct = "luminet"

// verifySignedUpdateAgainstHighWater performs a read-only comparison against
// the persisted schema-v2 metadata high-water mark when the store is present.
// It never advances the mark.
func (s *Server) verifySignedUpdateAgainstHighWater(ctx context.Context, verifier *updateadmission.Verifier, currentVersion string, envelope updateadmission.Envelope) (updateadmission.Plan, error) {
	var highest uint64
	if s != nil && s.store != nil {
		value, err := s.store.HighestUpdateMetadataSequence(ctx, updateMetadataProduct)
		if err != nil {
			return updateadmission.Plan{}, err
		}
		highest = value
	}
	return verifier.VerifyWithMinimumSequence(time.Now().UTC(), currentVersion, highest, envelope)
}

// acceptSignedUpdateSequence atomically advances schema-v2 metadata replay
// state. Schema-v1 remains predecessor-compatible but cannot claim monotonic
// replay protection.
func (s *Server) acceptSignedUpdateSequence(ctx context.Context, plan *updateadmission.Plan) error {
	if plan == nil || plan.SchemaVersion < updateadmission.ManifestSchemaVersion {
		return nil
	}
	if s == nil || s.store == nil {
		return fmt.Errorf("schema-v2 signed update requires persistent metadata replay state")
	}
	highest, accepted, err := s.store.AcceptUpdateMetadataSequence(ctx, updateMetadataProduct, plan.MetadataSequence)
	if err != nil {
		return err
	}
	if !accepted {
		return fmt.Errorf("update metadata sequence %d is below persisted high-water mark %d", plan.MetadataSequence, highest)
	}
	plan.ReplayProtected = true
	return nil
}
