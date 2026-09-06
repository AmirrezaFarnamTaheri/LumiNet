package dns

import (
	"reflect"
	"testing"
)

func TestAutoTunePresets(t *testing.T) {
	if len(AutoTunePresets) != 10 {
		t.Fatalf("expected 10 presets, got %d", len(AutoTunePresets))
	}

	p := GetPresetByID("iran-average")
	if p == nil {
		t.Fatalf("preset iran-average not found")
	}
	if p.Label != "Iran Default" {
		t.Fatalf("unexpected label: %s", p.Label)
	}
	if p.MinUploadMtu != 40 || p.MaxUploadMtu != 140 {
		t.Fatalf("unexpected upload MTU: %d..%d", p.MinUploadMtu, p.MaxUploadMtu)
	}
	if p.Stability != StabilityStable {
		t.Fatalf("expected stable preset")
	}

	agg := GetPresetByID("iran-wide-range-aggressive")
	if agg == nil || agg.Stability != StabilityAggressive {
		t.Fatalf("expected aggressive preset, got %+v", agg)
	}

	if GetPresetByID("non-existent") != nil {
		t.Fatalf("expected nil for non-existent preset")
	}
}

func TestChunkResolversRoundRobin(t *testing.T) {
	resolvers := []string{
		"1.1.1.1:53",
		"8.8.8.8:53",
		"9.9.9.9:53",
		"8.8.4.4:53",
		"1.0.0.1:53",
	}

	chunks := ChunkResolversRoundRobin(resolvers, 2)
	if len(chunks) != 2 {
		t.Fatalf("expected 2 chunks, got %d", len(chunks))
	}
	expected0 := []string{"1.1.1.1:53", "9.9.9.9:53", "1.0.0.1:53"}
	expected1 := []string{"8.8.8.8:53", "8.8.4.4:53"}

	if !reflect.DeepEqual(chunks[0], expected0) {
		t.Fatalf("chunk 0 mismatch: got %v, expected %v", chunks[0], expected0)
	}
	if !reflect.DeepEqual(chunks[1], expected1) {
		t.Fatalf("chunk 1 mismatch: got %v, expected %v", chunks[1], expected1)
	}

	if len(ChunkResolversRoundRobin(nil, 3)) != 0 {
		t.Fatalf("expected empty chunks for nil input")
	}
}

func TestDnsProfileLinkEncodeDecode(t *testing.T) {
	rec := DnsProfileRecord{
		Name:             "Primary AntiCensorship DNS",
		Domain:           "dns.antidpi.net",
		EncryptionKey:    "k3y-secret-777",
		EncryptionMethod: 1,
		Engine:           "stormdns",
	}

	link, err := EncodeDnsProfileLink(rec)
	if err != nil {
		t.Fatalf("failed to encode: %v", err)
	}

	decoded, err := DecodeDnsProfileLink(link)
	if err != nil {
		t.Fatalf("failed to decode: %v", err)
	}

	if decoded.Name != rec.Name {
		t.Fatalf("expected name %s, got %s", rec.Name, decoded.Name)
	}
	if decoded.Domain != rec.Domain {
		t.Fatalf("expected domain %s, got %s", rec.Domain, decoded.Domain)
	}
	if decoded.EncryptionKey != rec.EncryptionKey {
		t.Fatalf("expected key %s, got %s", rec.EncryptionKey, decoded.EncryptionKey)
	}
	if decoded.EncryptionMethod != rec.EncryptionMethod {
		t.Fatalf("expected method %d, got %d", rec.EncryptionMethod, decoded.EncryptionMethod)
	}
	if decoded.Engine != rec.Engine {
		t.Fatalf("expected engine %s, got %s", rec.Engine, decoded.Engine)
	}
}
