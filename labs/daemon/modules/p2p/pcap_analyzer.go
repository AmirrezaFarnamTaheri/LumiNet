// Package p2p manages peer-to-peer DHT tracking.
package p2p

import (
	"encoding/binary"
	"fmt"
	"io"
	"log/slog"
	"os"
	"time"
)

// PCAPGlobalHeader is the 24-byte file header of a .pcap file.
type PCAPGlobalHeader struct {
	MagicNumber  uint32
	VersionMajor uint16
	VersionMinor uint16
	ThisZone     int32
	SigFigs      uint32
	SnapLen      uint32
	Network      uint32
}

// PCAPPacketHeader is the per-packet header (16 bytes).
type PCAPPacketHeader struct {
	TsSec   uint32
	TsUsec  uint32
	InclLen uint32
	OrigLen uint32
}

// PCAPPacket is a single captured packet with metadata.
type PCAPPacket struct {
	Timestamp time.Time
	Data      []byte
	OrigLen   uint32
}

// DPISignature is a known DPI blocking pattern to detect in packet payloads.
type DPISignature struct {
	Name    string
	Pattern []byte
}

// DefaultDPISignatures contains common DPI blocking fingerprints.
var DefaultDPISignatures = []DPISignature{
	{Name: "RST-injection", Pattern: []byte{0x00, 0x14, 0x00, 0x01}},
	{Name: "TLS-ClientHello-SNI-block", Pattern: []byte{0x16, 0x03}},
	{Name: "HTTP-RST", Pattern: []byte("HTTP/1.1 403")},
	{Name: "DNS-poisoned-A", Pattern: []byte{0x00, 0x01, 0x00, 0x01}},
}

// PCAPAnalyzer parses PCAP files and detects known DPI blocking signatures.
type PCAPAnalyzer struct {
	// Signatures lists DPI patterns to detect; defaults to DefaultDPISignatures.
	Signatures []DPISignature
}

func NewPCAPAnalyzer() *PCAPAnalyzer {
	return &PCAPAnalyzer{Signatures: DefaultDPISignatures}
}

// Analyze reads a .pcap file at path, scans all packets for DPI signatures,
// and returns matching findings keyed by signature name.
func (p *PCAPAnalyzer) Analyze(path string) (map[string]int, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("PCAPAnalyzer.Analyze: open: %w", err)
	}
	defer f.Close()

	packets, err := p.readPCAP(f)
	if err != nil {
		return nil, fmt.Errorf("PCAPAnalyzer.Analyze: read: %w", err)
	}

	hits := make(map[string]int)
	for _, pkt := range packets {
		for _, sig := range p.Signatures {
			if contains(pkt.Data, sig.Pattern) {
				hits[sig.Name]++
			}
		}
	}

	slog.Info("PCAPAnalyzer: scan complete",
		"file", path, "packets", len(packets), "signatures", len(p.Signatures), "hits", len(hits))
	return hits, nil
}

func (p *PCAPAnalyzer) readPCAP(r io.Reader) ([]PCAPPacket, error) {
	var gh PCAPGlobalHeader
	if err := binary.Read(r, binary.LittleEndian, &gh); err != nil {
		return nil, fmt.Errorf("read global header: %w", err)
	}
	if gh.MagicNumber != 0xa1b2c3d4 && gh.MagicNumber != 0xd4c3b2a1 {
		return nil, fmt.Errorf("invalid pcap magic: %x", gh.MagicNumber)
	}
	bigEndian := gh.MagicNumber == 0xd4c3b2a1

	var packets []PCAPPacket
	for {
		var ph PCAPPacketHeader
		bo := binary.ByteOrder(binary.LittleEndian); if bigEndian { bo = binary.BigEndian }
		if err := binary.Read(r, bo, &ph); err != nil {
			if err == io.EOF {
				break
			}
			return nil, err
		}
		data := make([]byte, ph.InclLen)
		if _, err := io.ReadFull(r, data); err != nil {
			return nil, err
		}
		packets = append(packets, PCAPPacket{
			Timestamp: time.Unix(int64(ph.TsSec), int64(ph.TsUsec)*1000).UTC(),
			Data:      data,
			OrigLen:   ph.OrigLen,
		})
	}
	return packets, nil
}

func contains(haystack, needle []byte) bool {
	if len(needle) == 0 || len(haystack) < len(needle) {
		return false
	}
	for i := 0; i <= len(haystack)-len(needle); i++ {
		match := true
		for j, b := range needle {
			if haystack[i+j] != b {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}
