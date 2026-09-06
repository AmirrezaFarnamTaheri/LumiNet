package proxyconfig

import "testing"

const (
	hopOne = "wg://sk1@hop1.example.com:51820?publickey=pk1#HopOne"
	hopTwo = "awg://sk2@hop2.example.com:51820?publickey=pk2&jc=4&h1=1111#HopTwo"
)

func TestParseWgHopChainTwoHops(t *testing.T) {
	chain, err := ParseWgHopChain(hopOne + "|" + hopTwo)
	if err != nil {
		t.Fatal(err)
	}
	if len(chain.Hops) != 2 {
		t.Fatalf("hops = %d, want 2", len(chain.Hops))
	}
	if chain.Entry().Address != "hop1.example.com" {
		t.Fatalf("entry = %s", chain.Entry().Address)
	}
	if chain.Exit().Protocol != ProtocolAmneziaWG {
		t.Fatalf("exit protocol = %s", chain.Exit().Protocol)
	}
	if got := chain.Describe(); got != "hop1.example.com:51820 -> hop2.example.com:51820" {
		t.Fatalf("describe = %q", got)
	}
}

func TestParseWgHopChainRejectsEmptyAndDuplicateEndpoints(t *testing.T) {
	if _, err := ParseWgHopChain(""); err == nil {
		t.Fatal("empty chain accepted")
	}
	if _, err := ParseWgHopChain(hopOne + "| |" + hopTwo); err == nil {
		t.Fatal("blank segment accepted")
	}
	dup := "wg://ka@same.example.com:51820?publickey=a|wg://kb@same.example.com:51820?publickey=b"
	if _, err := ParseWgHopChain(dup); err == nil {
		t.Fatal("duplicate endpoint accepted")
	}
}

func TestWgHopChainValidateRequiresPeerKeys(t *testing.T) {
	chain, err := ParseWgHopChain(hopOne + "|" + hopTwo)
	if err != nil {
		t.Fatal(err)
	}
	if err := chain.Validate(); err != nil {
		t.Fatalf("valid chain rejected: %v", err)
	}
	// strip a key to simulate a malformed hop
	saved := chain.Hops[0].PublicKey
	chain.Hops[0].PublicKey = ""
	if err := chain.Validate(); err == nil {
		t.Fatal("missing public key accepted")
	}
	chain.Hops[0].PublicKey = saved

	// self-loop: build directly since Parse rejects consecutive duplicates
	loop := &WgHopChain{Hops: []*ProxyConfig{chain.Hops[0], chain.Hops[1]}}
	if err := loop.Validate(); err != nil {
		t.Fatalf("hand-built valid chain rejected: %v", err)
	}
	loop.Hops[1].Address = loop.Hops[0].Address
	loop.Hops[1].Port = loop.Hops[0].Port
	if err := loop.Validate(); err == nil {
		t.Fatal("consecutive duplicate endpoint accepted")
	}
}

func TestSingleHopChainIsDegenerateButValid(t *testing.T) {
	chain, err := ParseWgHopChain(hopOne)
	if err != nil {
		t.Fatal(err)
	}
	if chain.Entry() == nil || chain.Exit() == nil || chain.Entry() != chain.Exit() {
		t.Fatal("single-hop entry/exit should alias")
	}
	if err := chain.Validate(); err != nil {
		t.Fatalf("single hop rejected: %v", err)
	}
}
