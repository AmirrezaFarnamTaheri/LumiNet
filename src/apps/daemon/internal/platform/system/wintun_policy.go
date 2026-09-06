package system

import "fmt"

const (
	wintunMinRingCapacity = uint32(128 << 10)
	wintunMaxRingCapacity = uint32(64 << 20)
	wintunMaxPacketSize   = 0xffff
)

func validateWintunRingCapacity(capacity uint32) error {
	if capacity < wintunMinRingCapacity || capacity > wintunMaxRingCapacity {
		return fmt.Errorf("Wintun ring capacity must be between %d and %d bytes", wintunMinRingCapacity, wintunMaxRingCapacity)
	}
	if capacity&(capacity-1) != 0 {
		return fmt.Errorf("Wintun ring capacity must be a power of two: %d", capacity)
	}
	return nil
}

func validateWintunPacketSize(size int) error {
	if size <= 0 || size > wintunMaxPacketSize {
		return fmt.Errorf("Wintun packet size must be between 1 and %d bytes: %d", wintunMaxPacketSize, size)
	}
	return nil
}
