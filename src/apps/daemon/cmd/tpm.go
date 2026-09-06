package cmd

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/maybeknott/luminet/internal/foundation/config"
	lcrypto "github.com/maybeknott/luminet/internal/foundation/crypto"
	"github.com/maybeknott/luminet/internal/foundation/secrets"
	"github.com/spf13/cobra"
)

var tpmCmd = &cobra.Command{
	Use:   "tpm",
	Short: "Explicit TPM envelope migration and recovery operations",
}

var tpmMigrateCmd = &cobra.Command{
	Use:   "migrate",
	Short: "Migrate legacy TPM blobs to a native-provider envelope",
	RunE:  runTPMMigrate,
}

var tpmVerifyCmd = &cobra.Command{
	Use:   "verify",
	Short: "Verify that the active envelope reopens through its native provider",
	RunE:  runTPMVerify,
}

var tpmInventoryCmd = &cobra.Command{
	Use:   "inventory",
	Short: "Print an audit-safe TPM envelope inventory",
	RunE:  runTPMInventory,
}

var tpmRollbackCmd = &cobra.Command{
	Use:   "rollback",
	Short: "Export retained legacy blobs before their compatibility cutoff",
	RunE:  runTPMRollback,
}

var tpmCutoffCmd = &cobra.Command{
	Use:   "cutoff",
	Short: "Shorten the legacy compatibility cutoff",
	RunE:  runTPMCutoff,
}

func init() {
	rootCmd.AddCommand(tpmCmd)
	tpmCmd.AddCommand(tpmMigrateCmd, tpmVerifyCmd, tpmInventoryCmd, tpmRollbackCmd, tpmCutoffCmd)

	for _, command := range []*cobra.Command{tpmMigrateCmd, tpmVerifyCmd, tpmInventoryCmd, tpmRollbackCmd, tpmCutoffCmd} {
		command.Flags().String("record", "", "TPM envelope repository path (default: <data-dir>/tpm-envelope.json)")
	}
	tpmMigrateCmd.Flags().String("legacy-public", "", "legacy TPM public blob path")
	tpmMigrateCmd.Flags().String("legacy-private", "", "legacy TPM private blob path")
	tpmMigrateCmd.Flags().String("authorization-ref", "", "new native-store authorization reference")
	tpmMigrateCmd.Flags().String("legacy-cutoff", "", "future RFC3339 legacy compatibility cutoff")
	tpmRollbackCmd.Flags().String("output-dir", "", "new directory for the atomic legacy rollback bundle")
	tpmCutoffCmd.Flags().String("at", "", "new RFC3339 cutoff (must not extend the current cutoff)")
}

func runTPMMigrate(cmd *cobra.Command, _ []string) error {
	recordPath, _ := cmd.Flags().GetString("record")
	recordPath = resolveTPMRecordPath(recordPath)
	publicPath, _ := cmd.Flags().GetString("legacy-public")
	privatePath, _ := cmd.Flags().GetString("legacy-private")
	authorizationRef, _ := cmd.Flags().GetString("authorization-ref")
	cutoffRaw, _ := cmd.Flags().GetString("legacy-cutoff")
	if publicPath == "" || privatePath == "" || authorizationRef == "" || cutoffRaw == "" {
		return errors.New("legacy-public, legacy-private, authorization-ref, and legacy-cutoff are required")
	}
	cutoff, err := time.Parse(time.RFC3339, cutoffRaw)
	if err != nil {
		return fmt.Errorf("parse legacy cutoff: %w", err)
	}
	store, err := secrets.OpenNativeStore()
	if err != nil {
		return err
	}
	policy, err := config.ResolveTPMLifecyclePolicy(config.TPMLifecycleInput{
		Source:              config.TPMConfigSourceOperator,
		ProductionAssertion: true,
		RecordPath:          recordPath,
		Provider:            store.ProviderName(),
		AuthorizationRef:    authorizationRef,
		Profile:             lcrypto.DefaultTPMProfile,
		LegacyCutoff:        &cutoff,
	})
	if err != nil {
		return err
	}
	publicBlob, err := os.ReadFile(publicPath)
	if err != nil {
		return fmt.Errorf("read legacy public blob: %w", err)
	}
	privateBlob, err := os.ReadFile(privatePath)
	if err != nil {
		return fmt.Errorf("read legacy private blob: %w", err)
	}
	envelope, err := executeTPMMigration(
		cmd.Context(),
		store,
		policy,
		publicBlob,
		privateBlob,
	)
	if err != nil {
		return err
	}
	return writeTPMJSON(cmd.OutOrStdout(), map[string]any{
		"status":    "migrated",
		"record_id": envelope.RecordID,
		"provider":  envelope.Authorization.Provider,
		"profile":   envelope.Profile,
	})
}

func executeTPMMigration(ctx context.Context, store secrets.NativeStore, policy config.TPMLifecyclePolicy, publicBlob, privateBlob []byte) (lcrypto.TPMEnvelope, error) {
	return lcrypto.MigrateCompiledLegacyTPMToRepository(
		ctx,
		publicBlob,
		privateBlob,
		store,
		secrets.SecretRef{Provider: policy.Provider, Ref: policy.AuthorizationRef},
		lcrypto.NewTPMEnvelopeRepository(policy.RecordPath),
		policy.LegacyCutoff,
	)
}

func runTPMVerify(cmd *cobra.Command, _ []string) error {
	recordPath, _ := cmd.Flags().GetString("record")
	recordPath = resolveTPMRecordPath(recordPath)
	store, err := secrets.OpenNativeStore()
	if err != nil {
		return err
	}
	repository := lcrypto.NewTPMEnvelopeRepository(recordPath)
	key, err := lcrypto.UnsealActiveTPMEnvelope(cmd.Context(), repository, store, lcrypto.SystemTPMSealer{})
	if err != nil {
		return err
	}
	for i := range key {
		key[i] = 0
	}
	record, err := repository.Load()
	if err != nil {
		return err
	}
	return writeTPMJSON(cmd.OutOrStdout(), safeTPMInventory(record, "verified"))
}

func runTPMInventory(cmd *cobra.Command, _ []string) error {
	recordPath, _ := cmd.Flags().GetString("record")
	recordPath = resolveTPMRecordPath(recordPath)
	record, err := lcrypto.NewTPMEnvelopeRepository(recordPath).Load()
	if err != nil {
		return err
	}
	return writeTPMJSON(cmd.OutOrStdout(), safeTPMInventory(record, "inventory"))
}

func runTPMRollback(cmd *cobra.Command, _ []string) error {
	recordPath, _ := cmd.Flags().GetString("record")
	recordPath = resolveTPMRecordPath(recordPath)
	outputDir, _ := cmd.Flags().GetString("output-dir")
	if err := lcrypto.NewTPMEnvelopeRepository(recordPath).ExportLegacyRollback(time.Now().UTC(), outputDir); err != nil {
		return err
	}
	return writeTPMJSON(cmd.OutOrStdout(), map[string]any{"status": "legacy-exported"})
}

func runTPMCutoff(cmd *cobra.Command, _ []string) error {
	recordPath, _ := cmd.Flags().GetString("record")
	recordPath = resolveTPMRecordPath(recordPath)
	raw, _ := cmd.Flags().GetString("at")
	cutoff, err := time.Parse(time.RFC3339, raw)
	if err != nil {
		return fmt.Errorf("parse cutoff: %w", err)
	}
	if err := lcrypto.NewTPMEnvelopeRepository(recordPath).SetLegacyCutoff(cutoff); err != nil {
		return err
	}
	return writeTPMJSON(cmd.OutOrStdout(), map[string]any{"status": "cutoff-updated", "legacy_cutoff": cutoff.UTC()})
}

func resolveTPMRecordPath(path string) string {
	if path != "" {
		return path
	}
	return filepath.Join(resolveDataDir(), "tpm-envelope.json")
}

func safeTPMInventory(record lcrypto.TPMEnvelopeRecord, status string) map[string]any {
	return map[string]any{
		"status":        status,
		"record_id":     record.RecordID,
		"provider":      record.Active.Authorization.Provider,
		"profile":       record.Profile,
		"policy":        record.Policy,
		"activated_at":  record.ActivatedAt,
		"has_legacy":    record.Legacy != nil,
		"legacy_cutoff": record.LegacyCutoff,
	}
}

func writeTPMJSON(writer io.Writer, value any) error {
	encoder := json.NewEncoder(writer)
	encoder.SetIndent("", "  ")
	return encoder.Encode(value)
}
