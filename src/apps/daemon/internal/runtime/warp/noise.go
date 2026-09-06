package warp

import (
	"context"
	"crypto/rand"
	"net"
	"time"
)

// InjectNoise sends count random UDP packets to target. Noise is WARP runtime
// behavior and is intentionally kept behind the WARP module interface.
func InjectNoise(ctx context.Context, target string, count int) error {
	if err := ValidateNoiseCount(count); err != nil {
		return err
	}
	if count == 0 {
		return nil
	}
	addr, err := net.ResolveUDPAddr("udp", target)
	if err != nil {
		return err
	}
	conn, err := net.DialUDP("udp", nil, addr)
	if err != nil {
		return err
	}
	defer conn.Close()
	for i := 0; i < count; i++ {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		size := 16 + int(time.Now().UnixNano()%48)
		payload := make([]byte, size)
		if _, err := rand.Read(payload); err != nil {
			return err
		}
		if _, err := conn.Write(payload); err != nil {
			return err
		}
		timer := time.NewTimer(10 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
	return nil
}
