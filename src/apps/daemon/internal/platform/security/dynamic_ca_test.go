package security

import (
	"testing"
	"time"
)

func TestDynamicCaManager(t *testing.T) {
	ca := NewDynamicCaManager("LumiNet Root CA")
	cert1 := ca.IssueOrGetCert("api.example.com", 1*time.Hour)

	if cert1.CommonName != "api.example.com" {
		t.Errorf("expected api.example.com, got %s", cert1.CommonName)
	}

	// Cache hit
	cert2 := ca.IssueOrGetCert("api.example.com", 1*time.Hour)
	if cert1.SerialNumber != cert2.SerialNumber {
		t.Fatal("cached cert should have same serial number")
	}

	// Different domain
	cert3 := ca.IssueOrGetCert("login.example.com", 1*time.Hour)
	if cert1.SerialNumber == cert3.SerialNumber {
		t.Fatal("different domain should have incremented serial number")
	}
}
