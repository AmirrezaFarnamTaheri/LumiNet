package crypto

import (
	"errors"
	"fmt"
	"io"

	"github.com/google/go-tpm/legacy/tpm2"
	"github.com/google/go-tpm/tpmutil"
)

const (
	pcrNum = 7
)

// IsTPMAvailable checks if a TPM 2.0 device can be opened.
func IsTPMAvailable() bool {
	rwc, err := tpm2.OpenTPM()
	if err != nil {
		return false
	}
	rwc.Close()
	return true
}

// getSRKTemplate returns the default Storage Root Key (SRK) template.
func getSRKTemplate() tpm2.Public {
	return tpm2.Public{
		Type:       tpm2.AlgRSA,
		NameAlg:    tpm2.AlgSHA256,
		Attributes: tpm2.FlagFixedTPM | tpm2.FlagFixedParent | tpm2.FlagSensitiveDataOrigin | tpm2.FlagUserWithAuth | tpm2.FlagRestricted | tpm2.FlagDecrypt,
		AuthPolicy: nil,
		RSAParameters: &tpm2.RSAParams{
			Symmetric: &tpm2.SymScheme{
				Alg:     tpm2.AlgAES,
				KeyBits: 128,
				Mode:    tpm2.AlgCFB,
			},
			KeyBits: 2048,
		},
	}
}

// getPCR7PasswordPolicyDigest constructs the policy digest for PCR 7 + Password.
func getPCR7PasswordPolicyDigest(rwc io.ReadWriteCloser, pcr int, isTrial bool) (tpmutil.Handle, []byte, error) {
	sessionType := tpm2.SessionPolicy
	if isTrial {
		sessionType = tpm2.SessionTrial
	}

	sessHandle, _, err := tpm2.StartAuthSession(
		rwc,
		tpm2.HandleNull,
		tpm2.HandleNull,
		make([]byte, 16),
		nil,
		sessionType,
		tpm2.AlgNull,
		tpm2.AlgSHA256,
	)
	if err != nil {
		return tpm2.HandleNull, nil, err
	}

	pcrSelection := tpm2.PCRSelection{
		Hash: tpm2.AlgSHA256,
		PCRs: []int{pcr},
	}

	// PolicyPCR with nil digest reads the current PCR value from the TPM
	if err := tpm2.PolicyPCR(rwc, sessHandle, nil, pcrSelection); err != nil {
		tpm2.FlushContext(rwc, sessHandle)
		return tpm2.HandleNull, nil, err
	}

	if err := tpm2.PolicyPassword(rwc, sessHandle); err != nil {
		tpm2.FlushContext(rwc, sessHandle)
		return tpm2.HandleNull, nil, err
	}

	policy, err := tpm2.PolicyGetDigest(rwc, sessHandle)
	if err != nil {
		tpm2.FlushContext(rwc, sessHandle)
		return tpm2.HandleNull, nil, err
	}

	return sessHandle, policy, nil
}

// SealKeyToTPMWithAuthorization seals a key with caller-owned authorization.
// The authorization must come from an external secret provider for new blobs.
func SealKeyToTPMWithAuthorization(key, authorization []byte) (pub []byte, priv []byte, err error) {
	if len(key) != 32 {
		return nil, nil, errors.New("key must be exactly 32 bytes")
	}
	if len(authorization) == 0 {
		return nil, nil, errors.New("TPM authorization must not be empty")
	}

	rwc, err := tpm2.OpenTPM()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to open TPM: %w", err)
	}
	defer rwc.Close()

	// 1. Create Primary Key (SRK)
	srkHandle, _, err := tpm2.CreatePrimary(rwc, tpm2.HandleOwner, tpm2.PCRSelection{}, "", "", getSRKTemplate())
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create primary SRK: %w", err)
	}
	defer tpm2.FlushContext(rwc, srkHandle)

	// 2. Compute the policy digest for PCR 7 + Password using a trial session
	trialSess, policyDigest, err := getPCR7PasswordPolicyDigest(rwc, pcrNum, true)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate policy digest: %w", err)
	}
	tpm2.FlushContext(rwc, trialSess)

	// 3. Define the template for the sealed object containing the AuthPolicy
	sealedTemplate := tpm2.Public{
		Type:       tpm2.AlgKeyedHash,
		NameAlg:    tpm2.AlgSHA256,
		Attributes: tpm2.FlagFixedTPM | tpm2.FlagFixedParent | tpm2.FlagUserWithAuth,
		AuthPolicy: policyDigest,
	}

	// 4. Create the sealed object
	privBlob, pubBlob, _, _, _, err := tpm2.CreateKeyWithSensitive(rwc, srkHandle, tpm2.PCRSelection{}, "", string(authorization), sealedTemplate, key)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create sealed key: %w", err)
	}

	return pubBlob, privBlob, nil
}

// UnsealKeyFromTPMWithAuthorization unseals a blob with caller-owned authorization.
func UnsealKeyFromTPMWithAuthorization(pubBlob, privBlob, authorization []byte) ([]byte, error) {
	if len(authorization) == 0 {
		return nil, errors.New("TPM authorization must not be empty")
	}
	rwc, err := tpm2.OpenTPM()
	if err != nil {
		return nil, fmt.Errorf("failed to open TPM: %w", err)
	}
	defer rwc.Close()

	// 1. Create/Load Primary Key (SRK)
	srkHandle, _, err := tpm2.CreatePrimary(rwc, tpm2.HandleOwner, tpm2.PCRSelection{}, "", "", getSRKTemplate())
	if err != nil {
		return nil, fmt.Errorf("failed to create primary SRK: %w", err)
	}
	defer tpm2.FlushContext(rwc, srkHandle)

	// 2. Load the sealed object
	sealHandle, _, err := tpm2.Load(rwc, srkHandle, "", pubBlob, privBlob)
	if err != nil {
		return nil, fmt.Errorf("failed to load sealed key: %w", err)
	}
	defer tpm2.FlushContext(rwc, sealHandle)

	// 3. Start a policy session to authorize unsealing
	policySess, _, err := getPCR7PasswordPolicyDigest(rwc, pcrNum, false)
	if err != nil {
		return nil, fmt.Errorf("failed to start policy session for unsealing: %w", err)
	}
	defer tpm2.FlushContext(rwc, policySess)

	// 4. Unseal the key
	unsealed, err := tpm2.UnsealWithSession(rwc, policySess, sealHandle, string(authorization))
	if err != nil {
		return nil, fmt.Errorf("failed to unseal key: %w", err)
	}

	return unsealed, nil
}
