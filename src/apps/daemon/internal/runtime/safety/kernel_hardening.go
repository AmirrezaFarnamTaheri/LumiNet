package safety

import (
	"sync"
)

type HardeningSetting struct {
	Key            string `json:"key"`
	ExpectedValue  string `json:"expected_value"`
	CurrentValue   string `json:"current_value"`
	Critical       bool   `json:"critical"`
	Compliant      bool   `json:"compliant"`
}

type KernelHardeningAuditor struct {
	mu       sync.Mutex
	settings map[string]*HardeningSetting
}

func NewKernelHardeningAuditor() *KernelHardeningAuditor {
	auditor := &KernelHardeningAuditor{
		settings: make(map[string]*HardeningSetting),
	}
	auditor.registerDefaults()
	return auditor
}

func (a *KernelHardeningAuditor) registerDefaults() {
	defaults := []struct {
		key      string
		expected string
		critical bool
	}{
		{"net.ipv4.ip_forward", "1", true},
		{"net.ipv4.conf.all.rp_filter", "1", true},
		{"net.ipv4.conf.default.rp_filter", "1", true},
		{"net.ipv4.conf.all.accept_source_route", "0", true},
		{"net.ipv4.conf.all.send_redirects", "0", false},
		{"net.ipv4.tcp_syncookies", "1", true},
		{"net.ipv4.tcp_rfc1337", "1", false},
		{"net.ipv6.conf.all.disable_ipv6", "0", false},
	}
	for _, d := range defaults {
		a.settings[d.key] = &HardeningSetting{
			Key:           d.key,
			ExpectedValue: d.expected,
			Critical:      d.critical,
			Compliant:     false,
		}
	}
}

func (a *KernelHardeningAuditor) AuditValues(current map[string]string) float64 {
	a.mu.Lock()
	defer a.mu.Unlock()

	compliantCount := 0
	for key, setting := range a.settings {
		if val, ok := current[key]; ok {
			setting.CurrentValue = val
			setting.Compliant = (val == setting.ExpectedValue)
		} else {
			setting.Compliant = false
		}
		if setting.Compliant {
			compliantCount++
		}
	}

	if len(a.settings) == 0 {
		return 100.0
	}
	return (float64(compliantCount) / float64(len(a.settings))) * 100.0
}
