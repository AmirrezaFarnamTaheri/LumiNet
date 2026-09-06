package diagnostics

import "testing"

func TestCloudflareCleanPoolContract(t *testing.T) {
	if len(cloudflareCleanPool) != 8 {
		t.Fatalf("pool=%d", len(cloudflareCleanPool))
	}
}
