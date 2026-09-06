package system

import "testing"

func TestPostRefactor225WintunRingCapacityContract(t *testing.T) {
	for _, capacity := range []uint32{128 << 10, 1 << 20, 64 << 20} {
		if err := validateWintunRingCapacity(capacity); err != nil {
			t.Fatalf("valid capacity %d rejected: %v", capacity, err)
		}
	}
	for _, capacity := range []uint32{0, 64 << 10, 129 << 10, (64 << 20) + 1} {
		if err := validateWintunRingCapacity(capacity); err == nil {
			t.Fatalf("invalid capacity %d accepted", capacity)
		}
	}
}

func TestPostRefactor225WintunPacketSizeContract(t *testing.T) {
	for _, size := range []int{1, 1500, 0xffff} {
		if err := validateWintunPacketSize(size); err != nil {
			t.Fatalf("valid packet size %d rejected: %v", size, err)
		}
	}
	for _, size := range []int{-1, 0, 0x10000} {
		if err := validateWintunPacketSize(size); err == nil {
			t.Fatalf("invalid packet size %d accepted", size)
		}
	}
}
