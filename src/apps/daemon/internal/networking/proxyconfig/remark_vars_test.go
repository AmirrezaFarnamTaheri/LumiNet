// SPDX-License-Identifier: MIT

package proxyconfig

import (
	"strings"
	"testing"
	"time"
)

func TestTranslateUISingleBrackets(t *testing.T) {
	input := "{EMAIL} - {PROTOCOL} - {DATA_USAGE} / {DATA_LIMIT}"
	expected := "{{EMAIL}} - {{PROTOCOL}} - {{TRAFFIC_USED}} / {{TRAFFIC_TOTAL}}"
	actual := TranslateUISingleBrackets(input)
	if actual != expected {
		t.Fatalf("expected %q, got %q", expected, actual)
	}
}

func TestExpandRemarkTemplate_ActiveClient(t *testing.T) {
	now := time.Now().Unix()
	ctx := RemarkContext{
		Email:        "user@example.com",
		Protocol:     "vless",
		Transport:    "ws",
		Security:     "tls",
		InboundTag:   "in-vless-01",
		TrafficUsed:  512 * 1024 * 1024,       // 512 MB (5.0%)
		TrafficTotal: 10 * 1024 * 1024 * 1024, // 10 GB
		ExpiryTime:   now + 86400*10,          // 10 days left
	}

	tmpl := "{STATUS_EMOJI} {EMAIL} | {PROTOCOL}-{TRANSPORT} | 📊 {DATA_USAGE}/{DATA_LIMIT} ({USAGE_PERCENTAGE}) | ⏳ {DAYS_LEFT} days"
	expanded := ExpandRemarkTemplate(tmpl, ctx)

	if !strings.Contains(expanded, "🟢 user@example.com") {
		t.Errorf("expected status emoji and email, got %q", expanded)
	}
	if !strings.Contains(expanded, "vless-ws") {
		t.Errorf("expected protocol-transport, got %q", expanded)
	}
	if !strings.Contains(expanded, "512.00 MB") || !strings.Contains(expanded, "10.00 GB") {
		t.Errorf("expected traffic format, got %q", expanded)
	}
	if !strings.Contains(expanded, "5.0%") {
		t.Errorf("expected 5.0%% usage percentage, got %q", expanded)
	}
	if !strings.Contains(expanded, "⏳ 10 days") && !strings.Contains(expanded, "⏳ 9 days") {
		t.Errorf("expected days left, got %q", expanded)
	}
}

func TestExpandRemarkTemplate_UnlimitedPruning(t *testing.T) {
	ctx := RemarkContext{
		Email:        "admin@example.com",
		Protocol:     "trojan",
		TrafficUsed:  2048,
		TrafficTotal: 0, // Unlimited
		ExpiryTime:   0, // Unlimited
	}

	tmpl := "{EMAIL} | {PROTOCOL} | 📊 {DATA_LIMIT} | ⏳ {DAYS_LEFT} days"
	expanded := ExpandRemarkTemplate(tmpl, ctx)

	if strings.Contains(expanded, "⏳") {
		t.Errorf("expected unlimited days segment to be pruned, got %q", expanded)
	}
	if strings.Contains(expanded, "📊") {
		t.Errorf("expected unlimited traffic segment to be pruned, got %q", expanded)
	}
	if !strings.Contains(expanded, "admin@example.com | trojan") {
		t.Errorf("expected base email and protocol, got %q", expanded)
	}
}

func TestFormatBytes(t *testing.T) {
	cases := []struct {
		bytes int64
		want  string
	}{
		{500, "500 B"},
		{1024, "1.00 KB"},
		{10 * 1024 * 1024, "10.00 MB"},
		{50 * 1024 * 1024 * 1024, "50.00 GB"},
		{2 * 1024 * 1024 * 1024 * 1024, "2.00 TB"},
	}

	for _, c := range cases {
		got := FormatBytes(c.bytes)
		if got != c.want {
			t.Errorf("FormatBytes(%d) = %q, want %q", c.bytes, got, c.want)
		}
	}
}
