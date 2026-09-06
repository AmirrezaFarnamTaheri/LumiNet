package transport

import (
	"net"
	"sync"
	"time"
)

type ScrambleAction int

const (
	ActionAccept ScrambleAction = iota
	ActionAlterTTL
	ActionMarkPacket
)

type ShortcutEntry struct {
	CreatedAt   time.Time
	TTL         time.Duration
	PacketCount uint64
}

type PacketScrambler struct {
	QueueNum        uint16
	DefaultMark     uint32
	TTLHopLimit     uint8
	shortcuts       map[string]*ShortcutEntry
	totalScrambled  uint64
	mu              sync.Mutex
}

func NewPacketScrambler(queue uint16, mark uint32) *PacketScrambler {
	return &PacketScrambler{
		QueueNum:    queue,
		DefaultMark: mark,
		TTLHopLimit: 64,
		shortcuts:   make(map[string]*ShortcutEntry),
	}
}

func (s *PacketScrambler) AddShortcut(dest string, ttl time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.shortcuts[dest] = &ShortcutEntry{
		CreatedAt: time.Now(),
		TTL:       ttl,
	}
}

func (s *PacketScrambler) HasActiveShortcut(dest string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if entry, ok := s.shortcuts[dest]; ok {
		if time.Since(entry.CreatedAt) < entry.TTL {
			entry.PacketCount++
			return true
		}
	}
	return false
}

func (s *PacketScrambler) ProcessIPPacket(dest *net.TCPAddr, packet []byte) ScrambleAction {
	if s.HasActiveShortcut(dest.String()) {
		return ActionMarkPacket
	}

	s.mu.Lock()
	s.totalScrambled++
	s.mu.Unlock()

	if len(packet) < 40 {
		return ActionAccept
	}

	// IPv4 check
	if (packet[0] >> 4) == 4 {
		proto := packet[9]
		if proto == 6 { // TCP
			ihl := int(packet[0]&0x0F) * 4
			if ihl+13 < len(packet) {
				flags := packet[ihl+13]
				// SYN+ACK check
				if (flags & 0x12) == 0x12 {
					packet[8] = s.TTLHopLimit
					return ActionAlterTTL
				}
			}
		}
	}

	return ActionAccept
}
