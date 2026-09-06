package tarpit

import (
	"bytes"
	"context"
	"strings"
	"testing"
)

func TestLoggerRedaction(t *testing.T) {
	var buf bytes.Buffer
	logger := newLogger("info")
	logger.SetOutput(&buf)

	ctx := context.Background()
	logger.Info(ctx, "access granted with api_key=super-secret-key-999", "user", "admin", "token", "Bearer secret-token-xyz")

	output := buf.String()

	// Verify message redaction
	if strings.Contains(output, "super-secret-key-999") {
		t.Errorf("unredacted message secret found in logs: %s", output)
	}
	if !strings.Contains(output, "api_key=") {
		t.Errorf("expected key parameter label to be preserved: %s", output)
	}

	// Verify structured fields string values redaction
	if strings.Contains(output, "secret-token-xyz") {
		t.Errorf("unredacted field value secret found in logs: %s", output)
	}
	if !strings.Contains(output, "Bearer") {
		t.Errorf("expected bearer token prefix to be preserved in fields: %s", output)
	}
}
