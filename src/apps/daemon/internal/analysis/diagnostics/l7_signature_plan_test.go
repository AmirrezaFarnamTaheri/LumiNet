package diagnostics

import "testing"

func TestPostRefactor224L7AdmissionIsBoundedOfflineAndIndividual(t *testing.T) {
	plan, err := BuildL7SignaturePlan([]L7SignatureCandidate{{Name: "tls", Expression: `^\\x16\\x03`}, {Name: "bad", Expression: "("}, {Name: "empty", Expression: ".*"}, {Name: "tls", Expression: "abc"}})
	if err != nil {
		t.Fatal(err)
	}
	if !plan.OfflineOnly || plan.InstallsClassifier {
		t.Fatalf("unexpected authority: %+v", plan)
	}
	if plan.Admitted != 1 || plan.Rejected != 3 || plan.Results[0].ExpressionSHA256 == "" {
		t.Fatalf("plan=%+v", plan)
	}
}

func TestPostRefactor224L7AdmissionRejectsAggregateExplosion(t *testing.T) {
	c := make([]L7SignatureCandidate, 256)
	for i := range c {
		c[i] = L7SignatureCandidate{Name: string(rune('a'+i%26)) + string(rune(i+1000)), Expression: string(make([]byte, 1024))}
	}
	if _, err := BuildL7SignaturePlan(c); err == nil {
		t.Fatal("expected aggregate bound")
	}
}
