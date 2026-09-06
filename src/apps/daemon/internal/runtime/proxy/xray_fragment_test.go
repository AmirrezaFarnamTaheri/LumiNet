package proxy

import "testing"

func TestParseXrayFragmentSettingsValid(t *testing.T) {
	for _, csv := range []string{"tlshello,10-20,10-20", "tlshello,100-200,10-20", "1-3,10-20,10-20"} {
		settings, err := ParseXrayFragmentSettings(csv)
		if err != nil {
			t.Fatalf("%q rejected: %v", csv, err)
		}
		outbound := map[string]any{}
		settings.Apply(outbound)
		frag, ok := outbound["fragment"].(map[string]any)
		if !ok || frag["packets"] != settings.Packets {
			t.Fatalf("fragment block wrong for %q: %+v", csv, outbound["fragment"])
		}
	}
}

func TestParseXrayFragmentSettingsInvalid(t *testing.T) {
	for _, csv := range []string{"", ",,", "nosuffix,10-20,1-2", "tlshello,abc,10", "tlshello,200-100,5"} {
		if _, err := ParseXrayFragmentSettings(csv); err == nil {
			t.Errorf("%q accepted", csv)
		}
	}
}

func TestApplyNoOpOnInvalid(t *testing.T) {
	bad := XrayFragmentSettings{Packets: ""}
	outbound := map[string]any{}
	bad.Apply(outbound)
	if _, exists := outbound["fragment"]; exists {
		t.Fatal("invalid settings must not mutate the outbound")
	}
}
