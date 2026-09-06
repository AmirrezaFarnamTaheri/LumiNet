package proxy

import (
	"errors"
	"net"
)

type RelayHopInfo struct {
	HopIndex  int    `json:"hop_index"`
	Endpoint  string `json:"endpoint"`
	PublicKey string `json:"public_key"`
}

type MultihopRelayChain struct {
	EntryHop            RelayHopInfo `json:"entry_hop"`
	ExitHop             RelayHopInfo `json:"exit_hop"`
	QuantumResistantPSK [32]byte     `json:"quantum_resistant_psk"`
}

func NewMultihopRelayChain(entry, exit RelayHopInfo, psk [32]byte) (*MultihopRelayChain, error) {
	if _, _, err := net.SplitHostPort(entry.Endpoint); err != nil {
		return nil, errors.New("invalid entry endpoint")
	}
	if _, _, err := net.SplitHostPort(exit.Endpoint); err != nil {
		return nil, errors.New("invalid exit endpoint")
	}

	return &MultihopRelayChain{
		EntryHop:            entry,
		ExitHop:             exit,
		QuantumResistantPSK: psk,
	}, nil
}

func (c *MultihopRelayChain) NestedAllowedIPs() (string, string) {
	return "10.64.0.1/32", "0.0.0.0/0, ::/0"
}
