package relayclient

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

func TestReadBoundedRelayControlResponseRejectsOversize(t *testing.T) {
	_, err := readBoundedRelayControlResponse(bytes.NewReader(make([]byte, maxRelayControlResponseBytes+1)))
	if err == nil {
		t.Fatal("expected oversized relay response to be rejected")
	}
}

func TestPostRefactor229RelayControlDecodeClassifiesHTMLWithoutOverclaimingCause(t *testing.T) {
	err := relayControlDecodeError("text/html; charset=utf-8", []byte("<!DOCTYPE html><title>quota</title>"), errors.New("invalid character '<'"))
	if !strings.Contains(err.Error(), "HTML instead of JSON") || !strings.Contains(err.Error(), "cause is ambiguous") || !strings.Contains(err.Error(), "quota") {
		t.Fatalf("error=%v", err)
	}
	jsonErr := relayControlDecodeError("application/json", []byte("not-json"), errors.New("decode"))
	if !strings.Contains(jsonErr.Error(), "invalid JSON control data") || strings.Contains(jsonErr.Error(), "HTML") {
		t.Fatalf("json error=%v", jsonErr)
	}
}
