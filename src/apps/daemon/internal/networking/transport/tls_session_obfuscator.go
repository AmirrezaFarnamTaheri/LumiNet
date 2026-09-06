package transport

import (
	"encoding/binary"
	"errors"
)

// Canonical TLS session ticket padding bucket sizes matching typical server distributions.
var CanonicalPaddedTicketSizes = []int{160, 176, 192, 208, 218, 224, 240, 255}

// PadSessionTicket pads raw TLS ticket bytes to the nearest standard size to defeat fingerprinting.
func PadSessionTicket(ticket []byte) []byte {
	currLen := len(ticket)
	targetSize := 0
	for _, s := range CanonicalPaddedTicketSizes {
		if s >= currLen {
			targetSize = s
			break
		}
	}
	if targetSize == 0 {
		// If larger than 255, pad to next 16-byte boundary
		targetSize = (currLen + 15) &^ 15
	}

	out := make([]byte, targetSize)
	copy(out, ticket)
	return out
}

// UnpadSessionTicket strips trailing zero padding.
func UnpadSessionTicket(padded []byte) []byte {
	end := len(padded)
	for end > 0 && padded[end-1] == 0x00 {
		end--
	}
	return padded[:end]
}

// ObfuscatedClientSessionState stores resumable session state with padded tickets.
type ObfuscatedClientSessionState struct {
	Ticket       []byte
	Vers         uint16
	CipherSuite  uint16
	MasterSecret []byte
	CreatedAt    uint64
	AgeAdd       uint32
	UseBy        uint64
}

// NewObfuscatedClientSessionState creates state with padded ticket.
func NewObfuscatedClientSessionState(
	ticket []byte,
	vers uint16,
	cipherSuite uint16,
	masterSecret []byte,
	createdAt uint64,
	ageAdd uint32,
	useBy uint64,
) *ObfuscatedClientSessionState {
	return &ObfuscatedClientSessionState{
		Ticket:       PadSessionTicket(ticket),
		Vers:         vers,
		CipherSuite:  cipherSuite,
		MasterSecret: append([]byte(nil), masterSecret...),
		CreatedAt:    createdAt,
		AgeAdd:       ageAdd,
		UseBy:        useBy,
	}
}

// Serialize encodes session state into binary buffer.
func (s *ObfuscatedClientSessionState) Serialize() []byte {
	buf := make([]byte, 0, 28+len(s.MasterSecret)+len(s.Ticket))
	buf = binary.BigEndian.AppendUint16(buf, s.Vers)
	buf = binary.BigEndian.AppendUint16(buf, s.CipherSuite)
	buf = binary.BigEndian.AppendUint64(buf, s.CreatedAt)
	buf = binary.BigEndian.AppendUint32(buf, s.AgeAdd)
	buf = binary.BigEndian.AppendUint64(buf, s.UseBy)

	buf = binary.BigEndian.AppendUint16(buf, uint16(len(s.MasterSecret)))
	buf = append(buf, s.MasterSecret...)

	buf = binary.BigEndian.AppendUint16(buf, uint16(len(s.Ticket)))
	buf = append(buf, s.Ticket...)
	return buf
}

// DeserializeObfuscatedClientSessionState decodes binary session buffer.
func DeserializeObfuscatedClientSessionState(data []byte) (*ObfuscatedClientSessionState, error) {
	if len(data) < 28 {
		return nil, errors.New("tls_obfuscator: buffer too short")
	}

	vers := binary.BigEndian.Uint16(data[0:2])
	cipherSuite := binary.BigEndian.Uint16(data[2:4])
	createdAt := binary.BigEndian.Uint64(data[4:12])
	ageAdd := binary.BigEndian.Uint32(data[12:16])
	useBy := binary.BigEndian.Uint64(data[16:24])

	secretLen := int(binary.BigEndian.Uint16(data[24:26]))
	offset := 26
	if len(data) < offset+secretLen+2 {
		return nil, errors.New("tls_obfuscator: buffer truncated at master secret")
	}
	masterSecret := append([]byte(nil), data[offset:offset+secretLen]...)
	offset += secretLen

	ticketLen := int(binary.BigEndian.Uint16(data[offset : offset+2]))
	offset += 2
	if len(data) < offset+ticketLen {
		return nil, errors.New("tls_obfuscator: buffer truncated at ticket")
	}
	ticket := append([]byte(nil), data[offset:offset+ticketLen]...)

	return &ObfuscatedClientSessionState{
		Ticket:       ticket,
		Vers:         vers,
		CipherSuite:  cipherSuite,
		MasterSecret: masterSecret,
		CreatedAt:    createdAt,
		AgeAdd:       ageAdd,
		UseBy:        useBy,
	}, nil
}

// TLSPassthroughDeflector manages active probing defense by forwarding unauthorized TLS handshakes.
type TLSPassthroughDeflector struct {
	PassthroughAddress string
	AuthorizedTokens   []string
}

func NewTLSPassthroughDeflector(addr string, tokens []string) *TLSPassthroughDeflector {
	return &TLSPassthroughDeflector{
		PassthroughAddress: addr,
		AuthorizedTokens:   tokens,
	}
}

// ShouldDeflect returns true if the connection lacks credentials and should be passed through.
func (d *TLSPassthroughDeflector) ShouldDeflect(presentedToken string) bool {
	if d.PassthroughAddress == "" {
		return false
	}
	if presentedToken == "" {
		return true
	}
	for _, tok := range d.AuthorizedTokens {
		if tok == presentedToken {
			return false
		}
	}
	return true
}

// ECHCipher represents symmetric cipher suite in ECH config.
type ECHCipher struct {
	KDFID  uint16
	AEADID uint16
}

// ECHConfig represents parsed draft-ietf-tls-esni-18 configuration.
type ECHConfig struct {
	Version       uint16
	ConfigID      uint8
	KemID         uint16
	PublicKey     []byte
	CipherSuites  []ECHCipher
	MaxNameLength uint8
	PublicName    string
}

// ParseECHConfigList parses a draft-ietf-tls-esni-18 ECHConfigList byte slice.
func ParseECHConfigList(data []byte) ([]ECHConfig, error) {
	if len(data) < 2 {
		return nil, errors.New("ech: buffer too short")
	}

	listLen := int(binary.BigEndian.Uint16(data[0:2]))
	if len(data) != 2+listLen {
		return nil, errors.New("ech: malformed config list length")
	}

	offset := 2
	var configs []ECHConfig

	for offset < len(data) {
		if len(data) < offset+4 {
			return nil, errors.New("ech: malformed config entry header")
		}

		vers := binary.BigEndian.Uint16(data[offset : offset+2])
		cfgLen := int(binary.BigEndian.Uint16(data[offset+2 : offset+4]))
		offset += 4

		if len(data) < offset+cfgLen {
			return nil, errors.New("ech: truncated config entry body")
		}

		entry := data[offset : offset+cfgLen]
		offset += cfgLen

		if len(entry) < 5 {
			return nil, errors.New("ech: entry too short")
		}

		cfgID := entry[0]
		kemID := binary.BigEndian.Uint16(entry[1:3])
		pkLen := int(binary.BigEndian.Uint16(entry[3:5]))
		cOffset := 5

		if len(entry) < cOffset+pkLen+2 {
			return nil, errors.New("ech: entry truncated at public key")
		}
		publicKey := append([]byte(nil), entry[cOffset:cOffset+pkLen]...)
		cOffset += pkLen

		ciphersLen := int(binary.BigEndian.Uint16(entry[cOffset : cOffset+2]))
		cOffset += 2

		if len(entry) < cOffset+ciphersLen+2 {
			return nil, errors.New("ech: entry truncated at ciphers")
		}

		var ciphers []ECHCipher
		cEnd := cOffset + ciphersLen
		for cOffset+4 <= cEnd {
			kdf := binary.BigEndian.Uint16(entry[cOffset : cOffset+2])
			aead := binary.BigEndian.Uint16(entry[cOffset+2 : cOffset+4])
			ciphers = append(ciphers, ECHCipher{KDFID: kdf, AEADID: aead})
			cOffset += 4
		}
		cOffset = cEnd

		maxNameLen := entry[cOffset]
		cOffset++

		if len(entry) < cOffset+1 {
			return nil, errors.New("ech: missing public name length")
		}
		nameLen := int(entry[cOffset])
		cOffset++

		if len(entry) < cOffset+nameLen {
			return nil, errors.New("ech: truncated public name")
		}
		publicName := string(entry[cOffset : cOffset+nameLen])

		configs = append(configs, ECHConfig{
			Version:       vers,
			ConfigID:      cfgID,
			KemID:         kemID,
			PublicKey:     publicKey,
			CipherSuites:  ciphers,
			MaxNameLength: maxNameLen,
			PublicName:    publicName,
		})
	}

	return configs, nil
}
