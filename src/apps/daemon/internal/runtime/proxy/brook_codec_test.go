package proxy

import (
	"bytes"
	"testing"
)

func TestBrookCodecDomainRoundTrip(t *testing.T) {
	codec := NewBrookCodec()
	req := &BrookRequest{
		TargetType: BrookTargetDomain,
		Host:       "secure.api.luminet.internal",
		Port:       443,
	}

	var buf bytes.Buffer
	if err := codec.EncodeRequest(&buf, req); err != nil {
		t.Fatalf("Encode failed: %v", err)
	}

	decoded, err := codec.DecodeRequest(&buf)
	if err != nil {
		t.Fatalf("Decode failed: %v", err)
	}

	if decoded.Host != req.Host || decoded.Port != req.Port || decoded.TargetType != req.TargetType {
		t.Fatalf("mismatch decoded req: %+v vs %+v", decoded, req)
	}
}
