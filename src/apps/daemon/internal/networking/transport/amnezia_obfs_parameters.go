package transport

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// AmneziaObfsParameters stores AmneziaWG junk packet and header obfuscation parameters (Jc, Jmin, Jmax, S1, S2, H1, H2, H3, H4)
type AmneziaObfsParameters struct {
	Jc   int    // Junk packet count
	Jmin int    // Junk packet min size
	Jmax int    // Junk packet max size
	S1   int    // Initiation packet padding
	S2   int    // Response packet padding
	H1   uint32 // Obfuscated Handshake Initiation message type
	H2   uint32 // Obfuscated Handshake Response message type
	H3   uint32 // Obfuscated Cookie Reply message type
	H4   uint32 // Obfuscated Data packet message type
}

// DefaultAmneziaParams returns standard default parameters
func DefaultAmneziaParams() AmneziaObfsParameters {
	return AmneziaObfsParameters{
		Jc:   4,
		Jmin: 40,
		Jmax: 70,
		S1:   56,
		S2:   56,
		H1:   0x01000000,
		H2:   0x02000000,
		H3:   0x03000000,
		H4:   0x04000000,
	}
}

// Validate ensures parameter bounds are legal
func (p *AmneziaObfsParameters) Validate() error {
	if p.Jc < 0 || p.Jc > 128 {
		return errors.New("Jc (junk count) must be between 0 and 128")
	}
	if p.Jmin < 0 || p.Jmax < p.Jmin || p.Jmax > 1500 {
		return errors.New("invalid Jmin / Jmax bounds")
	}
	if p.S1 < 0 || p.S1 > 1024 || p.S2 < 0 || p.S2 > 1024 {
		return errors.New("invalid S1 / S2 padding sizes")
	}
	return nil
}

// ParseAmneziaConfigLine parses "Key = Value" formatted configuration lines
func (p *AmneziaObfsParameters) ParseAmneziaConfigLine(line string) error {
	parts := strings.SplitN(line, "=", 2)
	if len(parts) != 2 {
		return errors.New("invalid key=value syntax")
	}
	key := strings.TrimSpace(parts[0])
	val := strings.TrimSpace(parts[1])

	num, err := strconv.ParseUint(val, 0, 32)
	if err != nil {
		return fmt.Errorf("failed to parse integer for %s: %v", key, err)
	}

	switch strings.ToUpper(key) {
	case "JC":
		p.Jc = int(num)
	case "JMIN":
		p.Jmin = int(num)
	case "JMAX":
		p.Jmax = int(num)
	case "S1":
		p.S1 = int(num)
	case "S2":
		p.S2 = int(num)
	case "H1":
		p.H1 = uint32(num)
	case "H2":
		p.H2 = uint32(num)
	case "H3":
		p.H3 = uint32(num)
	case "H4":
		p.H4 = uint32(num)
	default:
		return fmt.Errorf("unknown Amnezia parameter: %s", key)
	}
	return nil
}
