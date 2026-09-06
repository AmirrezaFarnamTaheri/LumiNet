// Package kcppolicy resolves bounded KCP transport intent into one concrete
// policy shared by planner and runtime owners. It deliberately contains no
// sockets or daemon side effects.
package kcppolicy

import (
	"errors"
	"fmt"
	"math"
	"strings"
)

const MaxFECShards = 64

// Overrides contains explicit operator values. Pointers are intentional: zero
// and false are valid explicit choices and must not be confused with absence.
type Overrides struct {
	DataShards        *int   `json:"data_shards,omitempty"`
	ParityShards      *int   `json:"parity_shards,omitempty"`
	NoDelay           *int   `json:"nodelay,omitempty"`
	Interval          *int   `json:"interval,omitempty"`
	Resend            *int   `json:"resend,omitempty"`
	NoCongestion      *int   `json:"no_congestion,omitempty"`
	SendWindow        *int   `json:"send_window,omitempty"`
	ReceiveWindow     *int   `json:"receive_window,omitempty"`
	MTU               *int   `json:"mtu,omitempty"`
	ACKNoDelay        *bool  `json:"ack_no_delay,omitempty"`
	WriteDelay        *bool  `json:"write_delay,omitempty"`
	DSCP              *int   `json:"dscp,omitempty"`
	ReadBufferBytes   *int   `json:"read_buffer_bytes,omitempty"`
	WriteBufferBytes  *int   `json:"write_buffer_bytes,omitempty"`
	PacketDuplication *int   `json:"packet_duplication,omitempty"`
	RateLimitBPS      *int64 `json:"rate_limit_bps,omitempty"`
}

// Input is the side-effect-free planner contract.
type Input struct {
	Intent              string    `json:"intent,omitempty"`
	ObservedLossPercent *float64  `json:"observed_loss_percent,omitempty"`
	Overrides           Overrides `json:"overrides,omitempty"`
}

// Policy is the complete runtime policy consumed by both KCP dialer/listener
// paths and the operator planning surface.
type Policy struct {
	Intent              string  `json:"intent"`
	ObservedLossPercent float64 `json:"observed_loss_percent"`
	DataShards          int     `json:"data_shards"`
	ParityShards        int     `json:"parity_shards"`
	NoDelay             int     `json:"nodelay"`
	Interval            int     `json:"interval"`
	Resend              int     `json:"resend"`
	NoCongestion        int     `json:"no_congestion"`
	SendWindow          int     `json:"send_window"`
	ReceiveWindow       int     `json:"receive_window"`
	MTU                 int     `json:"mtu"`
	ACKNoDelay          bool    `json:"ack_no_delay"`
	WriteDelay          bool    `json:"write_delay"`
	DSCP                int     `json:"dscp"`
	ReadBufferBytes     int     `json:"read_buffer_bytes"`
	WriteBufferBytes    int     `json:"write_buffer_bytes"`
	PacketDuplication   int     `json:"packet_duplication"`
	RateLimitBPS        int64   `json:"rate_limit_bps"`
}

func defaultPolicy(intent string) (Policy, error) {
	name := strings.ToLower(strings.TrimSpace(intent))
	if name == "" {
		name = "legacy"
	}
	// legacy matches the pre-convergence runtime exactly: 10/3 FEC,
	// nodelay=1, interval=20, resend=2, nc=1, wnd=128, no MTU/socket extras.
	p := Policy{
		Intent: name, DataShards: 10, ParityShards: 3,
		NoDelay: 1, Interval: 20, Resend: 2, NoCongestion: 1,
		SendWindow: 128, ReceiveWindow: 128,
	}
	switch name {
	case "legacy":
	case "balanced":
		p.NoDelay, p.Interval, p.Resend, p.NoCongestion = 0, 20, 2, 0
		p.SendWindow, p.ReceiveWindow, p.MTU = 512, 512, 1350
	case "latency":
		p.NoDelay, p.Interval, p.Resend, p.NoCongestion = 1, 5, 1, 1
		p.SendWindow, p.ReceiveWindow, p.MTU = 256, 256, 1200
		p.ACKNoDelay = true
	case "throughput", "aggressive":
		p.Intent = "throughput"
		p.NoDelay, p.Interval, p.Resend, p.NoCongestion = 0, 10, 2, 1
		p.SendWindow, p.ReceiveWindow, p.MTU = 2048, 2048, 1400
		p.DataShards, p.ParityShards = 20, 4
		p.WriteDelay = true
		p.ReadBufferBytes, p.WriteBufferBytes = 4<<20, 4<<20
	case "loss-recovery":
		p.NoDelay, p.Interval, p.Resend, p.NoCongestion = 1, 10, 1, 1
		p.SendWindow, p.ReceiveWindow, p.MTU = 512, 512, 1200
		p.DataShards, p.ParityShards = 10, 6
		p.ACKNoDelay = true
	case "cpu-efficient":
		p.NoDelay, p.Interval, p.Resend, p.NoCongestion = 0, 50, 2, 0
		p.SendWindow, p.ReceiveWindow, p.MTU = 128, 128, 1400
		p.DataShards, p.ParityShards = 10, 2
		p.WriteDelay = true
	default:
		return Policy{}, fmt.Errorf("unsupported KCP intent %q", intent)
	}
	return p, nil
}

// Resolve returns one validated policy. Explicit overrides are applied after
// intent and loss advice, so operator choices remain authoritative.
func Resolve(input Input) (Policy, error) {
	p, err := defaultPolicy(input.Intent)
	if err != nil {
		return Policy{}, err
	}
	if input.ObservedLossPercent != nil {
		loss := *input.ObservedLossPercent
		if math.IsNaN(loss) || math.IsInf(loss, 0) || loss < 0 || loss >= 100 {
			return Policy{}, errors.New("observed KCP loss percent must be finite and in [0,100)")
		}
		p.ObservedLossPercent = loss
		p.ParityShards = adaptiveParity(p.DataShards, p.ParityShards, loss)
	}

	o := input.Overrides
	if o.DataShards != nil {
		p.DataShards = *o.DataShards
	}
	if o.ParityShards != nil {
		p.ParityShards = *o.ParityShards
	}
	if o.NoDelay != nil {
		p.NoDelay = *o.NoDelay
	}
	if o.Interval != nil {
		p.Interval = *o.Interval
	}
	if o.Resend != nil {
		p.Resend = *o.Resend
	}
	if o.NoCongestion != nil {
		p.NoCongestion = *o.NoCongestion
	}
	if o.SendWindow != nil {
		p.SendWindow = *o.SendWindow
	}
	if o.ReceiveWindow != nil {
		p.ReceiveWindow = *o.ReceiveWindow
	}
	if o.MTU != nil {
		p.MTU = *o.MTU
	}
	if o.ACKNoDelay != nil {
		p.ACKNoDelay = *o.ACKNoDelay
	}
	if o.WriteDelay != nil {
		p.WriteDelay = *o.WriteDelay
	}
	if o.DSCP != nil {
		p.DSCP = *o.DSCP
	}
	if o.ReadBufferBytes != nil {
		p.ReadBufferBytes = *o.ReadBufferBytes
	}
	if o.WriteBufferBytes != nil {
		p.WriteBufferBytes = *o.WriteBufferBytes
	}
	if o.PacketDuplication != nil {
		p.PacketDuplication = *o.PacketDuplication
	}
	if o.RateLimitBPS != nil {
		p.RateLimitBPS = *o.RateLimitBPS
	}

	if err := validate(p); err != nil {
		return Policy{}, err
	}
	return p, nil
}

func adaptiveParity(data, baseline int, loss float64) int {
	if data <= 0 || loss <= 0 {
		return baseline
	}
	// Two-loss-window safety margin keeps the planner conservative without
	// allowing FEC to grow unbounded under hostile/noisy observations.
	candidate := int(math.Ceil(float64(data) * loss / 100 * 2))
	if candidate < baseline {
		candidate = baseline
	}
	if max := MaxFECShards - data; candidate > max {
		candidate = max
	}
	return candidate
}

func validate(p Policy) error {
	if p.DataShards < 0 || p.ParityShards < 0 || p.DataShards+p.ParityShards > MaxFECShards {
		return fmt.Errorf("KCP FEC shards must be non-negative and total at most %d", MaxFECShards)
	}
	if (p.DataShards == 0) != (p.ParityShards == 0) {
		return errors.New("KCP FEC must set both data and parity shards, or disable both")
	}
	if p.NoDelay < 0 || p.NoDelay > 1 || p.NoCongestion < 0 || p.NoCongestion > 1 {
		return errors.New("KCP nodelay and no-congestion values must be 0 or 1")
	}
	if p.Interval < 5 || p.Interval > 5000 {
		return errors.New("KCP interval must be between 5 and 5000 milliseconds")
	}
	if p.Resend < 0 || p.Resend > 2 {
		return errors.New("KCP fast-resend must be between 0 and 2")
	}
	if p.SendWindow < 32 || p.SendWindow > 65535 || p.ReceiveWindow < 32 || p.ReceiveWindow > 65535 {
		return errors.New("KCP send/receive windows must be between 32 and 65535")
	}
	if p.MTU != 0 && (p.MTU < 576 || p.MTU > 1500) {
		return errors.New("KCP MTU must be 0 or between 576 and 1500")
	}
	if p.DSCP < 0 || p.DSCP > 63 {
		return errors.New("KCP DSCP must be between 0 and 63")
	}
	for name, value := range map[string]int{"read buffer": p.ReadBufferBytes, "write buffer": p.WriteBufferBytes} {
		if value != 0 && (value < 32<<10 || value > 16<<20) {
			return fmt.Errorf("KCP %s must be 0 or between 32768 and 16777216 bytes", name)
		}
	}
	if p.PacketDuplication < 0 || p.PacketDuplication > 5 {
		return errors.New("KCP packet duplication must be between 0 and 5")
	}
	if p.RateLimitBPS < 0 || p.RateLimitBPS > 1<<30 {
		return errors.New("KCP rate limit must be between 0 and 1073741824 bytes/second")
	}
	return nil
}
