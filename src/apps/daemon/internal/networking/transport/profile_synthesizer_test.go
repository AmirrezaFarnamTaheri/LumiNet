package transport

import (
	"testing"
)

func TestCensorshipProfileSynthesizer(t *testing.T) {
	synth := NewCensorshipProfileSynthesizer()

	iran := synth.GetProfile(RegionIran)
	if !iran.DnsFragmentationEnabled || iran.DnsFragmentSize != 32 || iran.TcpMssClamp != 1100 {
		t.Fatalf("unexpected profile for Iran: %+v", iran)
	}

	china := synth.GetProfile(RegionChina)
	if china.TcpMssClamp != 1200 {
		t.Fatalf("unexpected MSS for China: %d", china.TcpMssClamp)
	}

	global := synth.GetProfile(RegionGlobal)
	if global.DnsFragmentationEnabled || global.TcpMssClamp != 1460 {
		t.Fatalf("unexpected global profile: %+v", global)
	}
}
