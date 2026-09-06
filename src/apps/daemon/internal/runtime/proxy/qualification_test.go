package proxy

import "testing"

func TestNormalizeQualificationRequestOwnsDefaults(t *testing.T) {
	t.Parallel()

	got, err := normalizeQualificationRequest(QualificationRequest{})
	if err == nil {
		t.Fatal("normalizeQualificationRequest() accepted an empty proxy set")
	}
	if got.Timeout != 10 || got.Concurrency != 8 || len(got.TestURLs) != 1 || got.TestURLs[0] != "http://cp.cloudflare.com/" {
		t.Fatalf("defaults = %#v", got)
	}
}

func TestQualificationCoreTypeNormalizesAliases(t *testing.T) {
	t.Parallel()

	for input, want := range map[string]CoreType{
		"":         CoreTypeAuto,
		"auto":     CoreTypeAuto,
		"xray":     CoreTypeXray,
		"singbox":  CoreTypeSingBox,
		"sing-box": CoreTypeSingBox,
	} {
		got, err := qualificationCoreType(input)
		if err != nil {
			t.Fatalf("qualificationCoreType(%q) error = %v", input, err)
		}
		if got != want {
			t.Fatalf("qualificationCoreType(%q) = %q, want %q", input, got, want)
		}
	}

	if _, err := qualificationCoreType("unknown"); err == nil {
		t.Fatal("qualificationCoreType accepted unknown core")
	}
}
