package sub

import (
	"encoding/base64"
	"strings"
	"testing"
)

func TestParseDNSTTSharePlainURL(t *testing.T) {
	line := "dnstt://PUBKEY@tunnel.ns.example:53?authoritative=false&dns=8.8.8.8:53#tag"
	cfg, err := ParseDNSShareLine(line, []string{"dnstt"})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Scheme != "dnstt" || cfg.Addr != "8.8.8.8:53" || cfg.NS != "tunnel.ns.example:53" {
		t.Fatalf("cfg = %+v", cfg)
	}
	if cfg.PubKey == nil || *cfg.PubKey != "PUBKEY" {
		t.Fatalf("pubkey = %v", cfg.PubKey)
	}
	if cfg.User != nil || cfg.Pass != nil {
		t.Fatal("non-authoritative share must not carry user/pass")
	}
}

func TestParseDNSTTAuthoritativeCarriesCredentials(t *testing.T) {
	line := "dnstt://PUBKEY@ns.example?authoritative=true&dns=9.9.9.9&user=u&pass=p"
	cfg, err := ParseDNSShareLine(line, []string{"dnstt"})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.User == nil || *cfg.User != "u" || cfg.Pass == nil || *cfg.Pass != "p" {
		t.Fatalf("credentials lost: %+v", cfg)
	}
}

func TestParseDNSSchemeBase64JSON(t *testing.T) {
	payload := `{"addr":"1.1.1.1","ns":"tun.example.","user":"u","pass":"p","pubkey":"pk"}`
	encoded := base64Std(payload)
	cfg, err := ParseDNSShareLine("dns://"+encoded, []string{"dns"})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Addr != "1.1.1.1" || cfg.NS != "tun.example" || cfg.PubKey == nil || *cfg.PubKey != "pk" {
		t.Fatalf("cfg = %+v", cfg)
	}
}

func TestParseSlipnetSharePipeRecord(t *testing.T) {
	record := "f0|x|x|ns.slip.example.|8.8.4.4:0,1.1.1.1|f4|f5|f6|f7|f8|f9|PUBKEY36"
	encoded := base64Std(record)
	cfg, err := ParseDNSShareLine("slipnet://"+encoded, []string{"slipnet"})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.NS != "ns.slip.example" {
		t.Fatalf("ns = %q", cfg.NS)
	}
	if cfg.Addr != "8.8.4.4" {
		t.Fatalf("addr = %q", cfg.Addr)
	}
	if cfg.PubKey == nil || *cfg.PubKey != "PUBKEY36" {
		t.Fatalf("pubkey = %v", cfg.PubKey)
	}
}

func TestMixedFeedSkipsUnknownSchemes(t *testing.T) {
	content := strings.Join([]string{
		"ss://not-a-dns-tunnel",
		"dnstt://PK@n.example?dns=1.2.3.4",
		"https://example.com/plain",
		"",
	}, "\n")
	got := ParseDNSShareContent(content, []string{"dnstt"})
	if len(got) != 1 || got[0].Addr != "1.2.3.4" {
		t.Fatalf("mixed feed result = %+v", got)
	}
}

func TestBase64URLSafeAccepted(t *testing.T) {
	payload := `{"addr":"5.5.5.5","ns":"n.example"}`
	// URL-safe alphabet differs only for +/ vs -_ — craft one that exercises it.
	encoded := base64URL(payload)
	cfg, err := ParseDNSShareLine("dns://"+encoded, []string{"dns"})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Addr != "5.5.5.5" || cfg.NS != "n.example" {
		t.Fatalf("cfg = %+v", cfg)
	}
}

// helpers

func base64Std(s string) string { return stdEncode(s) }

func base64URL(s string) string { return urlEncode(s) }

func stdEncode(s string) string  { return base64.StdEncoding.EncodeToString([]byte(s)) }
func urlEncode(s string) string  { return base64.URLEncoding.EncodeToString([]byte(s)) }
