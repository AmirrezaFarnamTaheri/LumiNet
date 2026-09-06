// Ported from: sing-mux-main
// Target path: server/internal/proxy/sing_brutal.go

package proxy

import (
	"context"
	"math"
	"sync"
	"time"
)

// BrutalRateController controls sender pacing using a constant transmit rate target.
type BrutalRateController struct {
	mu          sync.RWMutex
	sendRateBps int64 // Targeted upload speed in bps
	packetSize  int   // MTU packet size
	ticker      *time.Ticker
	tokenBucket int64
	bucketMax   int64
	lastUpdate  time.Time
}

// NewBrutalRateController creates a new rate controller.
func NewBrutalRateController(sendRateBps int64, packetSize int) *BrutalRateController {
	if packetSize <= 0 {
		packetSize = 1400
	}
	// Max burst size is 10 times MTU
	bucketMax := int64(packetSize * 10)
	return &BrutalRateController{
		sendRateBps: sendRateBps,
		packetSize:  packetSize,
		bucketMax:   bucketMax,
		tokenBucket: bucketMax,
		lastUpdate:  time.Now(),
	}
}

// SetRate updates the targeted constant send rate.
func (c *BrutalRateController) SetRate(rateBps int64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.sendRateBps = rateBps
}

// Pace blocks until the token bucket has enough capacity to send a packet.
func (c *BrutalRateController) Pace(ctx context.Context, bytesToSend int) error {
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		c.mu.Lock()
		now := time.Now()
		elapsed := now.Sub(c.lastUpdate).Seconds()
		c.lastUpdate = now

		// Accumulate tokens
		addedTokens := int64(elapsed * float64(c.sendRateBps) / 8.0)
		c.tokenBucket += addedTokens
		if c.tokenBucket > c.bucketMax {
			c.tokenBucket = c.bucketMax
		}

		if c.tokenBucket >= int64(bytesToSend) {
			c.tokenBucket -= int64(bytesToSend)
			c.mu.Unlock()
			return nil
		}
		c.mu.Unlock()

		// Calculate sleep time needed to reach required tokens
		c.mu.RLock()
		deficit := int64(bytesToSend) - c.tokenBucket
		sleepSec := float64(deficit) / (float64(c.sendRateBps) / 8.0)
		c.mu.RUnlock()

		sleepDur := time.Duration(math.Max(1.0, sleepSec*1000.0)) * time.Millisecond
		if sleepDur > 500*time.Millisecond {
			sleepDur = 500 * time.Millisecond
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(sleepDur):
		}
	}
}
