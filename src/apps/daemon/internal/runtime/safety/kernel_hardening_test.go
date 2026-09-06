package safety

import (
	"testing"
)

func TestKernelHardeningAuditor(t *testing.T) {
	auditor := NewKernelHardeningAuditor()
	current := map[string]string{
		"net.ipv4.ip_forward":                   "1",
		"net.ipv4.conf.all.rp_filter":           "1",
		"net.ipv4.conf.default.rp_filter":       "1",
		"net.ipv4.conf.all.accept_source_route": "0",
		"net.ipv4.conf.all.send_redirects":      "0",
		"net.ipv4.tcp_syncookies":               "1",
		"net.ipv4.tcp_rfc1337":                 "1",
		"net.ipv6.conf.all.disable_ipv6":        "0",
	}

	score := auditor.AuditValues(current)
	if score != 100.0 {
		t.Errorf("expected 100.0 compliance, got %f", score)
	}

	current["net.ipv4.ip_forward"] = "0"
	partialScore := auditor.AuditValues(current)
	if partialScore >= 100.0 {
		t.Errorf("compliance score should drop on non-compliant sysctl, got %f", partialScore)
	}
}
