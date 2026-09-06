package proxy

import "testing"

func TestPostRefactor224ResolveKCPPolicyPreservesExplicitZeroFalse(t *testing.T) {
	cfg := &proxyConfig{
		KCPProfile:              "loss-recovery",
		KCPObservedLossPercent:  35,
		KCPObservedLossSet:      true,
		KCPDataShards:           0,
		KCPDataShardsSet:        true,
		KCPParityShards:         0,
		KCPParityShardsSet:      true,
		KCPNoDelay:              0,
		KCPNoDelaySet:           true,
		KCPACKNoDelay:           false,
		KCPACKNoDelaySet:        true,
		KCPWriteDelay:           false,
		KCPWriteDelaySet:        true,
		KCPPacketDuplication:    0,
		KCPPacketDuplicationSet: true,
	}
	policy, err := resolveKCPPolicy(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if policy.DataShards != 0 || policy.ParityShards != 0 || policy.NoDelay != 0 || policy.ACKNoDelay || policy.WriteDelay || policy.PacketDuplication != 0 {
		t.Fatalf("explicit config lost to advice: %+v", policy)
	}
}

func TestPostRefactor224KCPSessionIdentityIncludesCredentialsAndPolicy(t *testing.T) {
	base := &proxyConfig{Address: "example.com", Port: 29900, Method: "aes-128", Password: "one"}
	policy, err := resolveKCPPolicy(base)
	if err != nil {
		t.Fatal(err)
	}
	one := kcpSessionKey(base, policy)

	rotated := *base
	rotated.Password = "two"
	two := kcpSessionKey(&rotated, policy)
	if one == two {
		t.Fatal("credential rotation must not reuse an existing KCP/SMUX session")
	}

	changed := *base
	changed.KCPProfile = "latency"
	latencyPolicy, err := resolveKCPPolicy(&changed)
	if err != nil {
		t.Fatal(err)
	}
	if one == kcpSessionKey(&changed, latencyPolicy) {
		t.Fatal("policy change must not reuse an incompatible KCP/SMUX session")
	}
}

func TestPostRefactor224KCPAESGCMIsOptIn(t *testing.T) {
	for _, method := range []string{"aes-gcm", "aes-gcm-128", "aes-gcm-192", "aes-gcm-256"} {
		block, err := createKCPBlockCrypt(method, "credential-free-test-secret")
		if err != nil {
			t.Fatalf("%s: %v", method, err)
		}
		if block == nil {
			t.Fatalf("%s returned nil block crypt", method)
		}
	}
	legacy, err := createKCPBlockCrypt("aes-256", "credential-free-test-secret")
	if err != nil || legacy == nil {
		t.Fatalf("legacy AES path changed: block=%T err=%v", legacy, err)
	}
}
