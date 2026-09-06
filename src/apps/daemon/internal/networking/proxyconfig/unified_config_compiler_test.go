package proxyconfig

import (
	"testing"
)

func TestBuildProxyChain(t *testing.T) {
	hops := []ChainedHop{
		{Tag: "hop1", Protocol: "vmess", Address: "1.1.1.1", Port: 443},
		{Tag: "hop2", Protocol: "shadowsocks", Address: "2.2.2.2", Port: 8388},
		{Tag: "exit", Protocol: "vless", Address: "3.3.3.3", Port: 443},
	}

	outbounds := BuildProxyChain(hops)
	if len(outbounds) != 3 {
		t.Fatalf("expected 3 outbounds, got %d", len(outbounds))
	}

	// Hop 1 dialerProxy should point to hop2
	stream1, ok := outbounds[0]["streamSettings"].(map[string]any)
	if !ok {
		t.Fatalf("missing streamSettings in hop1")
	}
	sockopt1, ok := stream1["sockopt"].(map[string]any)
	if !ok || sockopt1["dialerProxy"] != "hop2" {
		t.Fatalf("expected hop1 dialerProxy to be hop2, got %v", sockopt1)
	}

	// Exit hop should not have dialerProxy
	if _, hasStream := outbounds[2]["streamSettings"]; hasStream {
		t.Fatalf("exit hop should not define streamSettings dialerProxy")
	}
}

func TestBuildSplitDNS(t *testing.T) {
	dnsCfg := BuildSplitDNS([]string{"geosite:cn", "geosite:ir"}, "223.5.5.5", "https://1.1.1.1/dns-query")
	servers, ok := dnsCfg["servers"].([]any)
	if !ok || len(servers) != 3 {
		t.Fatalf("expected 3 servers in split DNS, got %v", servers)
	}
}

func TestCompileRegionalRoutingRules(t *testing.T) {
	rules := CompileRegionalRoutingRules(true, false, true)
	if len(rules) != 4 {
		t.Fatalf("expected 4 rules (adblock, private, iran, china), got %d", len(rules))
	}
	// First rule must be adblock
	if rules[0]["outboundTag"] != "block" {
		t.Fatalf("expected first rule outboundTag to be block, got %v", rules[0]["outboundTag"])
	}
}

func TestBuildSpeedtestConfig(t *testing.T) {
	fullConfig := map[string]any{
		"inbounds": []map[string]any{
			{"tag": "mixed", "port": 2080},
		},
		"outbounds": []map[string]any{
			{"tag": "node1", "protocol": "vless"},
			{"tag": "direct", "protocol": "freedom"},
		},
	}

	speedCfg, err := BuildSpeedtestConfig(fullConfig, "node1", 10888)
	if err != nil {
		t.Fatalf("failed to build speedtest config: %v", err)
	}

	inbounds, ok := speedCfg["inbounds"].([]map[string]any)
	if !ok || len(inbounds) != 1 || inbounds[0]["port"] != 10888 {
		t.Fatalf("invalid speedtest inbounds: %v", inbounds)
	}

	outbounds, ok := speedCfg["outbounds"].([]map[string]any)
	if !ok || len(outbounds) != 2 {
		t.Fatalf("expected 2 outbounds, got %v", outbounds)
	}
}
