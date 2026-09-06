package transport

import (
	"encoding/binary"
	"errors"
)

// SniFragmentConfig defines the fragmentation slicing ranges and delay ranges across 3 TLS zones.
type SniFragmentConfig struct {
	BeforeSniMin int
	BeforeSniMax int
	SniMin       int
	SniMax       int
	AfterSniMin  int
	AfterSniMax  int
	DelayMsMin   int64
	DelayMsMax   int64
}

// DefaultSniFragmentConfig returns safe evasion defaults.
func DefaultSniFragmentConfig() SniFragmentConfig {
	return SniFragmentConfig{
		BeforeSniMin: 1,
		BeforeSniMax: 5,
		SniMin:       1,
		SniMax:       3,
		AfterSniMin:  5,
		AfterSniMax:  20,
		DelayMsMin:   1,
		DelayMsMax:   5,
	}
}

// FragmentSlice represents an individual sub-packet fragment scheduled with an optional jitter delay.
type FragmentSlice struct {
	Zone    string `json:"zone"`
	Payload []byte `json:"payload"`
	DelayMs int64  `json:"delay_ms"`
}

// SniFragmentPlan describes the scheduled fragmentation slices and detected SNI metadata.
type SniFragmentPlan struct {
	Slices      []FragmentSlice `json:"slices"`
	TotalBytes  int             `json:"total_bytes"`
	DetectedSNI string          `json:"detected_sni,omitempty"`
}

// SniFragmenter provides DPI evasion through 3-zone TLS ClientHello fragmentation.
type SniFragmenter struct{}

// ExtractSNI inspects a raw TLS packet and returns the SNI server name if present.
func (f *SniFragmenter) ExtractSNI(packet []byte) (string, error) {
	_, _, sni, err := f.LocateSNI(packet)
	return sni, err
}

// LocateSNI finds the byte offset range (start, end, server_name) inside a TLS ClientHello packet.
func (f *SniFragmenter) LocateSNI(packet []byte) (int, int, string, error) {
	// Minimum TLS record + handshake header length
	if len(packet) < 5+4+2+32+1 {
		return 0, 0, "", errors.New("packet too short for TLS ClientHello")
	}

	// ContentType 0x16 = Handshake
	if packet[0] != 0x16 {
		return 0, 0, "", errors.New("not a TLS handshake record")
	}

	recordLen := int(binary.BigEndian.Uint16(packet[3:5]))
	if len(packet) < 5+recordLen {
		return 0, 0, "", errors.New("incomplete TLS record")
	}

	offset := 5
	// Handshake type 0x01 = ClientHello
	if packet[offset] != 0x01 {
		return 0, 0, "", errors.New("not a ClientHello handshake")
	}

	handshakeLen := int(packet[offset+1])<<16 | int(packet[offset+2])<<8 | int(packet[offset+3])
	if len(packet) < offset+4+handshakeLen {
		return 0, 0, "", errors.New("incomplete handshake body")
	}
	offset += 4

	// Version (2) + Random (32)
	if len(packet) < offset+2+32+1 {
		return 0, 0, "", errors.New("truncated client hello")
	}
	offset += 2 + 32

	// Session ID
	sessionIDLen := int(packet[offset])
	offset++
	if len(packet) < offset+sessionIDLen+2 {
		return 0, 0, "", errors.New("truncated session ID")
	}
	offset += sessionIDLen

	// Cipher Suites
	cipherSuitesLen := int(binary.BigEndian.Uint16(packet[offset : offset+2]))
	offset += 2
	if len(packet) < offset+cipherSuitesLen+1 {
		return 0, 0, "", errors.New("truncated cipher suites")
	}
	offset += cipherSuitesLen

	// Compression Methods
	compressionLen := int(packet[offset])
	offset++
	if len(packet) < offset+compressionLen+2 {
		return 0, 0, "", errors.New("truncated compression methods")
	}
	offset += compressionLen

	// Extensions
	extensionsLen := int(binary.BigEndian.Uint16(packet[offset : offset+2]))
	offset += 2
	extensionsEnd := offset + extensionsLen
	if len(packet) < extensionsEnd {
		return 0, 0, "", errors.New("truncated extensions block")
	}

	for offset+4 <= extensionsEnd {
		extType := binary.BigEndian.Uint16(packet[offset : offset+2])
		extLen := int(binary.BigEndian.Uint16(packet[offset+2 : offset+4]))
		offset += 4

		if offset+extLen > extensionsEnd {
			break
		}

		if extType == 0x0000 { // Server Name Indication
			if extLen < 5 {
				return 0, 0, "", errors.New("malformed SNI extension")
			}
			listLen := int(binary.BigEndian.Uint16(packet[offset : offset+2]))
			listOff := offset + 2
			listEnd := offset + 2 + listLen

			for listOff+3 <= listEnd {
				nameType := packet[listOff]
				nameLen := int(binary.BigEndian.Uint16(packet[listOff+1 : listOff+3]))
				listOff += 3

				if listOff+nameLen > listEnd {
					break
				}

				if nameType == 0x00 { // Hostname
					sniBytes := packet[listOff : listOff+nameLen]
					return listOff, listOff + nameLen, string(sniBytes), nil
				}
				listOff += nameLen
			}
		}

		offset += extLen
	}

	return 0, 0, "", errors.New("SNI extension not found")
}

// PlanFragments breaks down the packet into a sequence of delayed fragment slices across the 3 zones.
func (f *SniFragmenter) PlanFragments(packet []byte, config SniFragmentConfig) SniFragmentPlan {
	sniStart, sniEnd, sniName, err := f.LocateSNI(packet)
	if err != nil || sniEnd <= sniStart {
		// Pass-through without modification
		return SniFragmentPlan{
			Slices: []FragmentSlice{
				{
					Zone:    "passthrough",
					Payload: append([]byte(nil), packet...),
					DelayMs: 0,
				},
			},
			TotalBytes:  len(packet),
			DetectedSNI: "",
		}
	}

	var slices []FragmentSlice

	// Zone 0: Before SNI
	f.chunkZone(packet[:sniStart], config.BeforeSniMin, config.BeforeSniMax, config.DelayMsMin, config.DelayMsMax, "before_sni", &slices)

	// Zone 1: SNI Hostname
	f.chunkZone(packet[sniStart:sniEnd], config.SniMin, config.SniMax, config.DelayMsMin, config.DelayMsMax, "sni", &slices)

	// Zone 2: After SNI
	f.chunkZone(packet[sniEnd:], config.AfterSniMin, config.AfterSniMax, config.DelayMsMin, config.DelayMsMax, "after_sni", &slices)

	totalBytes := 0
	for _, s := range slices {
		totalBytes += len(s.Payload)
	}

	return SniFragmentPlan{
		Slices:      slices,
		TotalBytes:  totalBytes,
		DetectedSNI: sniName,
	}
}

func (f *SniFragmenter) chunkZone(
	data []byte,
	minChunk, maxChunk int,
	minDelay, maxDelay int64,
	zoneName string,
	out *[]FragmentSlice,
) {
	if len(data) == 0 {
		return
	}

	if minChunk <= 0 || maxChunk < minChunk {
		minChunk = 1
		if maxChunk < 1 {
			maxChunk = 1
		}
	}

	if minDelay < 0 || maxDelay < minDelay {
		minDelay = 0
		maxDelay = minDelay
	}

	offset := 0
	step := 0
	span := maxChunk - minChunk + 1
	delaySpan := maxDelay - minDelay + 1

	for offset < len(data) {
		chunkSize := minChunk + (step % span)
		end := offset + chunkSize
		if end > len(data) {
			end = len(data)
		}

		delayMs := minDelay + (int64(step) % delaySpan)

		*out = append(*out, FragmentSlice{
			Zone:    zoneName,
			Payload: append([]byte(nil), data[offset:end]...),
			DelayMs: delayMs,
		})

		offset = end
		step++
	}
}
