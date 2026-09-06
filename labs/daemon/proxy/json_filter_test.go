package proxy

import (
	"encoding/json"
	"reflect"
	"testing"
)

func TestTransformSubscriptionJSON(t *testing.T) {
	inputJSON := []byte(`{
		"outbounds": [
			{"type": "shadowsocks", "server": "1.1.1.1", "port": 8388},
			{"type": "vmess", "server": "2.2.2.2", "port": 443}
		]
	}`)

	// Query to get only shadowsocks outbound servers
	query := `.outbounds[] | select(.type == "shadowsocks") | .server`

	res, err := ExecuteJSONFilter(inputJSON, query)
	if err != nil {
		t.Fatalf("expected no query error, got %v", err)
	}

	if !reflect.DeepEqual(res, "1.1.1.1") {
		t.Errorf("expected 1.1.1.1, got %v", res)
	}

	// Query to transform to a simplified list
	transformQuery := `[.outbounds[] | {type: .type, addr: .server}]`
	transformedBytes, err := TransformSubscriptionJSON(inputJSON, transformQuery)
	if err != nil {
		t.Fatalf("expected no transform error, got %v", err)
	}

	var parsed []map[string]string
	if err := json.Unmarshal(transformedBytes, &parsed); err != nil {
		t.Fatalf("expected valid JSON output, got error: %v", err)
	}

	if len(parsed) != 2 || parsed[0]["type"] != "shadowsocks" || parsed[0]["addr"] != "1.1.1.1" {
		t.Errorf("unexpected transformed JSON output: %s", string(transformedBytes))
	}
}
