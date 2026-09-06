package proxy

import (
	"context"
	"sync"
	"time"
)

// DNSPacketConn handles dynamic window scaling and polling backoffs for DNS tunneling.
type DNSPacketConn struct {
	mu            sync.Mutex
	pollLimit     int
	minDelay      time.Duration
	maxDelay      time.Duration
	currentDelay  time.Duration
	inFlightCount int
	trafficChan   chan struct{}
	cancelFunc    context.CancelFunc
}

// NewDNSPacketConn creates a new scaled DNSPacketConn.
func NewDNSPacketConn() *DNSPacketConn {
	return &DNSPacketConn{
		pollLimit:    16,
		minDelay:     500 * time.Millisecond,
		maxDelay:     10 * time.Second,
		currentDelay: 500 * time.Millisecond,
		trafficChan:  make(chan struct{}, 100),
	}
}

// StartLoop starts the background recvLoop and polling coordination loop.
func (c *DNSPacketConn) StartLoop(ctx context.Context, sendPollFunc func() error) {
	loopCtx, cancel := context.WithCancel(ctx)
	c.cancelFunc = cancel

	// RecvLoop monitoring incoming downstream traffic records
	go func() {
		for {
			select {
			case <-loopCtx.Done():
				return
			case <-c.trafficChan:
				c.mu.Lock()
				// Traffic detected: reset poll delay back to minimum
				c.currentDelay = c.minDelay
				c.mu.Unlock()

				// Queue immediate polling query packets in a burst up to pollLimit
				go func() {
					c.mu.Lock()
					burst := c.pollLimit - c.inFlightCount
					if burst <= 0 {
						c.mu.Unlock()
						return
					}
					c.inFlightCount += burst
					c.mu.Unlock()

					for i := 0; i < burst; i++ {
						_ = sendPollFunc()
					}

					c.mu.Lock()
					c.inFlightCount -= burst
					c.mu.Unlock()
				}()
			}
		}
	}()

	// Polling loop with exponential scaling
	go func() {
		for {
			select {
			case <-loopCtx.Done():
				return
			case <-time.After(c.getDelay()):
				c.mu.Lock()
				inFlight := c.inFlightCount
				c.mu.Unlock()

				if inFlight < c.pollLimit {
					c.mu.Lock()
					c.inFlightCount++
					c.mu.Unlock()

					err := sendPollFunc()

					c.mu.Lock()
					c.inFlightCount--
					if err != nil {
						// Double delay when idle or query fails, clamped to maxDelay
						c.currentDelay *= 2
						if c.currentDelay > c.maxDelay {
							c.currentDelay = c.maxDelay
						}
					}
					c.mu.Unlock()
				}
			}
		}
	}()
}

// NotifyTraffic signals that a downstream record has been received.
func (c *DNSPacketConn) NotifyTraffic() {
	select {
	case c.trafficChan <- struct{}{}:
	default:
		// Channel full, traffic notification already queued
	}
}

// Stop terminates the polling loops.
func (c *DNSPacketConn) Stop() {
	if c.cancelFunc != nil {
		c.cancelFunc()
	}
}

func (c *DNSPacketConn) getDelay() time.Duration {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.currentDelay
}
