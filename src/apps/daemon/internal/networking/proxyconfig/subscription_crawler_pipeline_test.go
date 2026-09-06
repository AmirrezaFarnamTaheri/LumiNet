package proxyconfig

import (
	"encoding/base64"
	"testing"
)

func TestSubscriptionCrawlerPipeline(t *testing.T) {
	pipe := NewSubscriptionCrawlerPipeline()
	pipe.AddSource("https://sub.org/feed1", 3600)

	pending := pipe.DispatchPendingSources(1000)
	if len(pending) != 1 || pending[0] != "https://sub.org/feed1" {
		t.Fatalf("expected 1 pending source, got %v", pending)
	}

	// Dispatch too soon
	pending2 := pipe.DispatchPendingSources(1500)
	if len(pending2) != 0 {
		t.Fatalf("expected 0 pending sources within interval")
	}

	raw := "ss://method:pass@1.1.1.1:8388\ntrojan://pass@2.2.2.2:443"
	ingested := pipe.IngestCrawlContent("https://sub.org/feed1", raw)
	if ingested != 2 || pipe.TotalHarvestedCount() != 2 {
		t.Fatalf("expected 2 ingested proxies, got %d", ingested)
	}

	// Test base64 encoded payload
	encoded := base64.StdEncoding.EncodeToString([]byte("vless://uuid@3.3.3.3:443"))
	ingested2 := pipe.IngestCrawlContent("https://sub.org/feed1", encoded)
	if ingested2 != 1 || pipe.TotalHarvestedCount() != 3 {
		t.Fatalf("expected 1 ingested base64 proxy, got %d", ingested2)
	}
}
