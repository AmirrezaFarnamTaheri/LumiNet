package proxy

import (
	"bytes"
	"testing"
)

func TestCompileGeositeDat(t *testing.T) {
	sites := []V2RayGeoSite{
		{
			CountryCode: "IR",
			Domains: []V2RayDomain{
				{Type: V2RayDomainDomain, Value: "snapp.ir"},
				{Type: V2RayDomainFull, Value: "digikala.com"},
			},
		},
		{
			CountryCode: "US",
			Domains: []V2RayDomain{
				{Type: V2RayDomainRegex, Value: "google.*"},
			},
		},
	}

	var buf bytes.Buffer
	err := CompileGeositeDat(sites, &buf)
	if err != nil {
		t.Fatalf("failed to compile geosite.dat: %v", err)
	}

	data := buf.Bytes()
	if len(data) == 0 {
		t.Error("compiled geosite.dat is empty")
	}

	// Verify magic patterns in serialized protobuf
	// Protobuf tag check:
	// IR geosite country code: 1(tag)<<3 | 2(wire) = 10 (0x0A)
	// IR country code payload length is 2 bytes: 0x02
	// Payload: 'I' (0x49), 'R' (0x52)
	// So data should contain [0x0A, 0x02, 0x49, 0x52] at some point
	expectedSub := []byte{0x0A, 0x02, 0x49, 0x52}
	if !bytes.Contains(data, expectedSub) {
		t.Errorf("compiled protobuf does not contain country code 'IR' structure: %x", data)
	}
}
