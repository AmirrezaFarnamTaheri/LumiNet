package workers

import (
	"encoding/json"
	"testing"
)

func TestUsageTelemetryClient_Limits(t *testing.T) {
	client := NewUsageTelemetryClient("test_account", "test_secret_token_value")

	// Verify masking
	masked := client.MaskToken()
	expectedMasked := "test****alue"
	if masked != expectedMasked {
		t.Errorf("expected masked token to be %q, got %q", expectedMasked, masked)
	}

	// Verify limits manipulation
	client.SetLimit("workers_requests", 5000000)
	limit := client.GetLimit("workers_requests")
	if limit != 5000000 {
		t.Errorf("expected limit to be 5000000, got %f", limit)
	}

	// Verify RenderQuotaBar
	barJSON, err := client.RenderQuotaBar()
	if err != nil {
		t.Fatalf("RenderQuotaBar failed: %v", err)
	}

	var data map[string]map[string]interface{}
	if err := json.Unmarshal([]byte(barJSON), &data); err != nil {
		t.Fatalf("failed to parse RenderQuotaBar json: %v", err)
	}

	if _, ok := data["workers_requests"]; !ok {
		t.Errorf("expected workers_requests bar to be rendered")
	}
}
