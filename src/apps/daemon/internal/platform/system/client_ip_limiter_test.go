package system

import (
	"testing"
)

func TestMergeClientIPs(t *testing.T) {
	staleCutoff := int64(1000)

	oldIPs := []ClientIPRecord{
		{IP: "1.1.1.1", Timestamp: 900},  // Stale, should be dropped
		{IP: "2.2.2.2", Timestamp: 1100}, // Active
		{IP: "3.3.3.3", Timestamp: 1200}, // Active
	}

	newIPs := []ClientIPRecord{
		{IP: "2.2.2.2", Timestamp: 1300}, // Updated timestamp
		{IP: "4.4.4.4", Timestamp: 1400}, // New active IP
		{IP: "5.5.5.5", Timestamp: 800},  // Old timestamp
	}

	// Case 1: newAlwaysLive = false -> 5.5.5.5 dropped
	merged := MergeClientIPs(oldIPs, newIPs, staleCutoff, false)
	if _, ok := merged["1.1.1.1"]; ok {
		t.Errorf("expected 1.1.1.1 to be pruned")
	}
	if ts, ok := merged["2.2.2.2"]; !ok || ts != 1300 {
		t.Errorf("expected 2.2.2.2 timestamp 1300, got %d", ts)
	}
	if ts, ok := merged["3.3.3.3"]; !ok || ts != 1200 {
		t.Errorf("expected 3.3.3.3 timestamp 1200, got %d", ts)
	}
	if ts, ok := merged["4.4.4.4"]; !ok || ts != 1400 {
		t.Errorf("expected 4.4.4.4 timestamp 1400, got %d", ts)
	}
	if _, ok := merged["5.5.5.5"]; ok {
		t.Errorf("expected 5.5.5.5 to be pruned when newAlwaysLive is false")
	}

	// Case 2: newAlwaysLive = true -> 5.5.5.5 kept because it was reported in live scan
	mergedLive := MergeClientIPs(oldIPs, newIPs, staleCutoff, true)
	if ts, ok := mergedLive["5.5.5.5"]; !ok || ts != 800 {
		t.Errorf("expected 5.5.5.5 to be preserved when newAlwaysLive is true, got %d", ts)
	}
}

func TestPartitionLiveIPs(t *testing.T) {
	now := int64(2000)
	windowSec := int64(120) // 2 minutes

	ipMap := map[string]int64{
		"10.0.0.1": 1950, // Recent (now - 50s) -> live via cluster window
		"10.0.0.2": 1700, // Old (now - 300s) -> historical unless observed
		"10.0.0.3": 1600, // Old (now - 400s), but in observedThisScan -> live
	}

	observed := map[string]bool{
		"10.0.0.3": true,
	}

	live, historical := PartitionLiveIPs(ipMap, observed, now, windowSec)

	if len(live) != 2 {
		t.Fatalf("expected 2 live IPs, got %d", len(live))
	}
	if len(historical) != 1 {
		t.Fatalf("expected 1 historical IP, got %d", len(historical))
	}

	// Verify live order: oldest first (1600 before 1950)
	if live[0].IP != "10.0.0.3" || live[0].Timestamp != 1600 {
		t.Errorf("expected live[0] to be 10.0.0.3 with ts 1600, got %+v", live[0])
	}
	if live[1].IP != "10.0.0.1" || live[1].Timestamp != 1950 {
		t.Errorf("expected live[1] to be 10.0.0.1 with ts 1950, got %+v", live[1])
	}

	if historical[0].IP != "10.0.0.2" {
		t.Errorf("expected historical[0] to be 10.0.0.2, got %+v", historical[0])
	}
}

func TestSelectIPsToBan(t *testing.T) {
	live := []ClientIPRecord{
		{IP: "1.1.1.1", Timestamp: 100},
		{IP: "2.2.2.2", Timestamp: 200},
		{IP: "3.3.3.3", Timestamp: 300},
		{IP: "4.4.4.4", Timestamp: 400},
	}

	// Limit is 2: keep newest 2 (3.3.3.3, 4.4.4.4), ban oldest 2 (1.1.1.1, 2.2.2.2)
	kept, banned := SelectIPsToBan(live, 2)
	if len(kept) != 2 {
		t.Fatalf("expected 2 kept, got %d", len(kept))
	}
	if len(banned) != 2 {
		t.Fatalf("expected 2 banned, got %d", len(banned))
	}

	if kept[0].IP != "3.3.3.3" || kept[1].IP != "4.4.4.4" {
		t.Errorf("unexpected kept IPs: %+v", kept)
	}
	if banned[0].IP != "1.1.1.1" || banned[1].IP != "2.2.2.2" {
		t.Errorf("unexpected banned IPs: %+v", banned)
	}

	// Limit >= len(live): keep all, ban none
	keptAll, bannedNone := SelectIPsToBan(live, 4)
	if len(keptAll) != 4 || len(bannedNone) != 0 {
		t.Errorf("expected all kept and none banned when limit=4")
	}

	// Limit <= 0: unlimited
	keptUnlimited, bannedUnlimited := SelectIPsToBan(live, 0)
	if len(keptUnlimited) != 4 || len(bannedUnlimited) != 0 {
		t.Errorf("expected all kept and none banned when limit=0")
	}
}

func TestIPLimitAllowlist(t *testing.T) {
	raw := `
# Office range
192.168.1.0/24
# Operator exact IP
10.20.30.40
2001:db8::1
`
	al := NewIPLimitAllowlist(raw)

	if !al.Contains("192.168.1.50") {
		t.Errorf("expected 192.168.1.50 to match CIDR")
	}
	if !al.Contains("10.20.30.40") {
		t.Errorf("expected 10.20.30.40 to match exact IP")
	}
	if !al.Contains("2001:db8::1") {
		t.Errorf("expected 2001:db8::1 to match IPv6")
	}
	if al.Contains("192.168.2.1") {
		t.Errorf("expected 192.168.2.1 NOT to match")
	}

	live := []ClientIPRecord{
		{IP: "192.168.1.10", Timestamp: 100},
		{IP: "8.8.8.8", Timestamp: 200},
		{IP: "10.20.30.40", Timestamp: 300},
		{IP: "1.1.1.1", Timestamp: 400},
	}

	limited, allowed := al.Split(live)
	if len(allowed) != 2 {
		t.Fatalf("expected 2 allowed, got %d", len(allowed))
	}
	if len(limited) != 2 {
		t.Fatalf("expected 2 limited, got %d", len(limited))
	}
	if limited[0].IP != "8.8.8.8" || limited[1].IP != "1.1.1.1" {
		t.Errorf("unexpected limited list: %+v", limited)
	}
}

func TestBanDeduplicator(t *testing.T) {
	dedup := NewBanDeduplicator()

	banned := []ClientIPRecord{
		{IP: "1.1.1.1", Timestamp: 1000},
		{IP: "2.2.2.2", Timestamp: 1000},
	}

	// First pass: both are actionable
	actionable := dedup.FilterAdvancedSinceLastBan("user@test.com", banned)
	if len(actionable) != 2 {
		t.Fatalf("expected 2 actionable bans on first pass, got %d", len(actionable))
	}

	// Second pass with same timestamps (frozen socket): 0 actionable
	actionableSecond := dedup.FilterAdvancedSinceLastBan("user@test.com", banned)
	if len(actionableSecond) != 0 {
		t.Fatalf("expected 0 actionable bans for unchanged timestamps, got %d", len(actionableSecond))
	}

	// Third pass: 1.1.1.1 advanced its timestamp to 1050 (reconnected / new packet)
	bannedAdvanced := []ClientIPRecord{
		{IP: "1.1.1.1", Timestamp: 1050},
		{IP: "2.2.2.2", Timestamp: 1000}, // Still frozen
	}
	actionableThird := dedup.FilterAdvancedSinceLastBan("user@test.com", bannedAdvanced)
	if len(actionableThird) != 1 || actionableThird[0].IP != "1.1.1.1" {
		t.Fatalf("expected only 1.1.1.1 to be actionable, got %+v", actionableThird)
	}
}
