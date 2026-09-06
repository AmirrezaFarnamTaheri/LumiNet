package proxy

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"math/rand"
	"net"
	"sync"
	"time"

	"github.com/cespare/xxhash/v2"
)

// WireGuard packet type constants.
const (
	MessageInitiationType      = 1
	MessageResponseType        = 2
	MessageCookieReplyType     = 3
	MessageTransportType       = 4
	MessageInitiationSize      = 148
	MessageResponseSize        = 92
	MessageCookieReplySize     = 64
	MessageTransportHeaderSize = 16
	MinMessageSize             = 32
)

const (
	kObfuscateRandomSuffixMaxLength  = 384
	kObfuscateSuffixAsNonceMinLength = 256
	kObfuscateNonceLength            = 16
	kObfuscateXORKeyLength           = 8
	kMessageInitiationTypeMAC2Offset = 132
	kMessageResponseTypeMAC2Offset   = 76
)

const (
	PacketFlagDeobfuscatedAfterReceived = 1 << iota
	PacketFlagObfuscateBeforeSend
)

// WgPacket represents a WireGuard packet wrapper.
type WgPacket struct {
	Data        []byte
	Length      int
	Source      *net.UDPAddr
	Destination *net.UDPAddr
	Flags       uint64
}

// Reset resets the packet state.
func (p *WgPacket) Reset() {
	p.Length = 0
	p.Source = nil
	p.Destination = nil
	p.Flags = 0
}

// MessageType returns the WireGuard message type byte.
func (p *WgPacket) MessageType() int {
	if p.Length < 1 {
		return -1
	}
	return int(p.Data[0])
}

// ReceiverIndex parses and returns the receiver index.
func (p *WgPacket) ReceiverIndex() (uint32, error) {
	messageType := p.MessageType()
	switch messageType {
	case MessageInitiationType:
		return p.getLEUint32Offset(8)
	case MessageResponseType:
		return p.getLEUint32Offset(8)
	case MessageCookieReplyType:
		return p.getLEUint32Offset(4)
	case MessageTransportType:
		return p.getLEUint32Offset(4)
	default:
		return 0, fmt.Errorf("cannot get receiver_index for message type %d", messageType)
	}
}

// SetSenderIndex writes the sender index.
func (p *WgPacket) SetSenderIndex(index uint32) error {
	messageType := p.MessageType()
	switch messageType {
	case MessageInitiationType:
		return p.putLEUint32Offset(4, index)
	case MessageResponseType:
		return p.putLEUint32Offset(4, index)
	default:
		return fmt.Errorf("cannot set sender_index for message type %d", messageType)
	}
}

// SetReceiverIndex writes the receiver index.
func (p *WgPacket) SetReceiverIndex(index uint32) error {
	messageType := p.MessageType()
	switch messageType {
	case MessageInitiationType:
		return p.putLEUint32Offset(8, index)
	case MessageResponseType:
		return p.putLEUint32Offset(8, index)
	case MessageCookieReplyType:
		return p.putLEUint32Offset(4, index)
	case MessageTransportType:
		return p.putLEUint32Offset(4, index)
	default:
		return fmt.Errorf("cannot set receiver_index for message type %d", messageType)
	}
}

func (p *WgPacket) getLEUint32Offset(offset int) (uint32, error) {
	if p.Length < offset+4 {
		return 0, fmt.Errorf("packet too short for uint32 at offset %d", offset)
	}
	return binary.LittleEndian.Uint32(p.Data[offset:]), nil
}

func (p *WgPacket) putLEUint32Offset(offset int, value uint32) error {
	if p.Length < offset+4 {
		return fmt.Errorf("packet too short to write uint32 at offset %d", offset)
	}
	binary.LittleEndian.PutUint32(p.Data[offset:], value)
	return nil
}

// WireGuardObfuscator implements mwgp-2 compatible packet obfuscation and multiplexer routing.
type WireGuardObfuscator struct {
	enabled     bool
	userKeyHash [sha256.Size]byte
	rnd         *rand.Rand
	indexMap    map[uint32]uint32 // maps client index -> backend index
	reverseMap  map[uint32]uint32 // maps backend index -> client index
	mapMu       sync.RWMutex
}

// NewWireGuardObfuscator creates and initializes a WireGuardObfuscator.
func NewWireGuardObfuscator(userKey string) *WireGuardObfuscator {
	o := &WireGuardObfuscator{
		rnd:        rand.New(rand.NewSource(time.Now().UnixNano())),
		indexMap:   make(map[uint32]uint32),
		reverseMap: make(map[uint32]uint32),
	}
	if len(userKey) > 0 {
		o.enabled = true
		h := sha256.New()
		h.Write([]byte(userKey))
		h.Sum(o.userKeyHash[:0])
	}
	return o
}

// MapIndex maps a client index to a backend index.
func (o *WireGuardObfuscator) MapIndex(clientIdx, backendIdx uint32) {
	o.mapMu.Lock()
	defer o.mapMu.Unlock()
	o.indexMap[clientIdx] = backendIdx
	o.reverseMap[backendIdx] = clientIdx
}

// GetBackendIndex returns the mapped backend index for a client index.
func (o *WireGuardObfuscator) GetBackendIndex(clientIdx uint32) (uint32, bool) {
	o.mapMu.RLock()
	defer o.mapMu.RUnlock()
	idx, ok := o.indexMap[clientIdx]
	return idx, ok
}

// GetClientIndex returns the mapped client index for a backend index.
func (o *WireGuardObfuscator) GetClientIndex(backendIdx uint32) (uint32, bool) {
	o.mapMu.RLock()
	defer o.mapMu.RUnlock()
	idx, ok := o.reverseMap[backendIdx]
	return idx, ok
}

// Obfuscate applies mwgp-2 XOR obfuscation to a packet.
func (o *WireGuardObfuscator) Obfuscate(packet *WgPacket) {
	if !o.enabled {
		return
	}
	if packet.Flags&PacketFlagObfuscateBeforeSend == 0 {
		return
	}

	isAllZero := func(b []byte) bool {
		for _, v := range b {
			if v != 0 {
				return false
			}
		}
		return true
	}

	messageType := packet.MessageType()
	var obfsPartLength int
	switch messageType {
	case MessageInitiationType:
		packet.Length = MessageInitiationSize + kObfuscateNonceLength + o.rnd.Int()%kObfuscateRandomSuffixMaxLength
		obfsPartLength = MessageInitiationSize
		if isAllZero(packet.Data[kMessageInitiationTypeMAC2Offset:MessageInitiationSize]) {
			packet.Data[1] = 0x01
			obfsPartLength = kMessageInitiationTypeMAC2Offset
		}
		o.rnd.Read(packet.Data[obfsPartLength:packet.Length])
	case MessageResponseType:
		packet.Length = MessageResponseSize + kObfuscateNonceLength + o.rnd.Int()%kObfuscateRandomSuffixMaxLength
		obfsPartLength = MessageResponseSize
		if isAllZero(packet.Data[kMessageResponseTypeMAC2Offset:MessageResponseSize]) {
			packet.Data[1] = 0x01
			obfsPartLength = kMessageResponseTypeMAC2Offset
		}
		o.rnd.Read(packet.Data[obfsPartLength:packet.Length])
	case MessageCookieReplyType:
		packet.Length = MessageCookieReplySize + kObfuscateNonceLength + o.rnd.Int()%kObfuscateRandomSuffixMaxLength
		obfsPartLength = MessageCookieReplySize
		o.rnd.Read(packet.Data[obfsPartLength:packet.Length])
	case MessageTransportType:
		obfsPartLength = MessageTransportHeaderSize
		if packet.Length < kObfuscateSuffixAsNonceMinLength {
			packet.Data[1] = 0x01
			packet.Length += kObfuscateNonceLength
			o.rnd.Read(packet.Data[packet.Length-kObfuscateNonceLength : packet.Length])
		}
	default:
		return
	}

	var nonce [kObfuscateNonceLength]byte
	copy(nonce[:], packet.Data[packet.Length-kObfuscateNonceLength:])

	var digest xxhash.Digest
	digest.Reset()
	_, _ = digest.Write(nonce[:])
	for i := 0; i < obfsPartLength; i += kObfuscateXORKeyLength {
		_, _ = digest.Write(o.userKeyHash[:])
		var xorKey [kObfuscateXORKeyLength]byte
		digest.Sum(xorKey[:0])
		if i == 0 {
			o.modifyHashMaskForWireGuardHeaderConflict(xorKey[:])
		}
		for j := i; j < i+kObfuscateXORKeyLength && j < obfsPartLength; j++ {
			packet.Data[j] ^= xorKey[j-i]
		}
	}
}

// Deobfuscate removes mwgp-2 XOR obfuscation from a packet.
func (o *WireGuardObfuscator) Deobfuscate(packet *WgPacket) {
	if !o.enabled {
		return
	}
	if packet.Length < MinMessageSize {
		return
	}
	if packet.Data[0] >= 1 && packet.Data[0] <= 4 && packet.Data[1] == 0 && packet.Data[2] == 0 && packet.Data[3] == 0 {
		// Valid non-obfuscated WireGuard packet
		return
	}

	var nonce [kObfuscateNonceLength]byte
	copy(nonce[:], packet.Data[packet.Length-kObfuscateNonceLength:])

	var digest xxhash.Digest
	digest.Reset()
	_, _ = digest.Write(nonce[:])

	// Decode first 8 bytes for message type
	_, _ = digest.Write(o.userKeyHash[:])
	var xorKey [kObfuscateXORKeyLength]byte
	digest.Sum(xorKey[:0])
	o.modifyHashMaskForWireGuardHeaderConflict(xorKey[:])
	for i := 0; i < kObfuscateXORKeyLength; i++ {
		packet.Data[i] ^= xorKey[i]
	}

	messageType := packet.MessageType()
	var obfsPartLength int
	switch messageType {
	case MessageInitiationType:
		packet.Length = MessageInitiationSize
		obfsPartLength = MessageInitiationSize
		if packet.Data[1] == 0x01 {
			packet.Data[1] = 0
			obfsPartLength = kMessageInitiationTypeMAC2Offset
			for i := kMessageInitiationTypeMAC2Offset; i < MessageInitiationSize; i++ {
				packet.Data[i] = 0
			}
		}
	case MessageResponseType:
		packet.Length = MessageResponseSize
		obfsPartLength = MessageResponseSize
		if packet.Data[1] == 0x01 {
			packet.Data[1] = 0
			obfsPartLength = kMessageResponseTypeMAC2Offset
			for i := kMessageResponseTypeMAC2Offset; i < MessageResponseSize; i++ {
				packet.Data[i] = 0
			}
		}
	case MessageCookieReplyType:
		packet.Length = MessageCookieReplySize
		obfsPartLength = MessageCookieReplySize
	case MessageTransportType:
		obfsPartLength = MessageTransportHeaderSize
		if packet.Data[1] == 0x01 {
			packet.Data[1] = 0
			packet.Length -= kObfuscateNonceLength
		}
	default:
		return
	}

	// Decode the rest
	for i := kObfuscateXORKeyLength; i < obfsPartLength; i += kObfuscateXORKeyLength {
		_, _ = digest.Write(o.userKeyHash[:])
		digest.Sum(xorKey[:0])
		for j := i; j < i+kObfuscateXORKeyLength && j < obfsPartLength; j++ {
			packet.Data[j] ^= xorKey[j-i]
		}
	}

	packet.Flags |= PacketFlagDeobfuscatedAfterReceived
}

func (o *WireGuardObfuscator) modifyHashMaskForWireGuardHeaderConflict(b []byte) {
	if b[0]&0b11111000 == 0 && b[1]&0b11111110 == 0 {
		b[0] |= 0b11010111
		b[1] |= 0b01101001
	}
}
