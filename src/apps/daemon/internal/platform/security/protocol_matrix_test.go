package security

import "testing"

func TestProtocolMatrix(t *testing.T) {
	matrix := NewProtocolMatrix()
	rec := matrix.Recommend([]EvasionTrait{TraitMultipathUdp})
	if rec == nil || rec.Name != "Hysteria2" {
		t.Errorf("expected Hysteria2 recommendation for multipath UDP")
	}

	recSni := matrix.Recommend([]EvasionTrait{TraitSniFrag})
	if recSni == nil || recSni.Name != "Trojan-SNI-Fragment" {
		t.Errorf("expected Trojan-SNI-Fragment for SNI frag")
	}
}
