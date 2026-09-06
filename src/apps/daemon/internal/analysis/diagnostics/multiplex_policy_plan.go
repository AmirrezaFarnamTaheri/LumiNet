package diagnostics

import (
	"fmt"
	"runtime"
	"strings"
)

const (
	maxMuxConnections          = 64
	maxMuxStreamsPerConnection = 1024
	maxMuxPaddingBytes         = 4096
	maxMuxFrameBytes           = 65535
	maxMuxReceiveBufferBytes   = 64 << 20
	maxMuxStreamBufferBytes    = 4 << 20
)

type MultiplexPolicyRequest struct {
	Protocol                string `json:"protocol"`
	Version                 int    `json:"version,omitempty"`
	MaxConnections          int    `json:"max_connections,omitempty"`
	MaxStreamsPerConnection int    `json:"max_streams_per_connection,omitempty"`
	MinStreams              int    `json:"min_streams,omitempty"`
	Padding                 bool   `json:"padding,omitempty"`
	MaxPaddingBytes         int    `json:"max_padding_bytes,omitempty"`
	BandwidthUpBPS          int64  `json:"bandwidth_up_bps,omitempty"`
	BandwidthDownBPS        int64  `json:"bandwidth_down_bps,omitempty"`
	Platform                string `json:"platform,omitempty"`
	KeepAliveDisabled       bool   `json:"keep_alive_disabled,omitempty"`
	KeepAliveIntervalMS     int    `json:"keep_alive_interval_ms,omitempty"`
	KeepAliveTimeoutMS      int    `json:"keep_alive_timeout_ms,omitempty"`
	MaxFrameSize            int    `json:"max_frame_size,omitempty"`
	MaxReceiveBuffer        int    `json:"max_receive_buffer,omitempty"`
	MaxStreamBuffer         int    `json:"max_stream_buffer,omitempty"`
}

type MultiplexPolicyPlan struct {
	Protocol                      string   `json:"protocol"`
	RuntimeSupported              bool     `json:"runtime_supported"`
	Version                       int      `json:"version"`
	MaxConnections                int      `json:"max_connections"`
	MaxStreamsPerConnection       int      `json:"max_streams_per_connection"`
	EstimatedMaxConcurrentStreams int      `json:"estimated_max_concurrent_streams,omitempty"`
	SessionSelection              string   `json:"session_selection"`
	Padding                       bool     `json:"padding"`
	MaxPaddingBytes               int      `json:"max_padding_bytes,omitempty"`
	BandwidthControlSupported     bool     `json:"bandwidth_control_supported"`
	KeepAliveDisabled             bool     `json:"keep_alive_disabled"`
	KeepAliveIntervalMS           int      `json:"keep_alive_interval_ms"`
	KeepAliveTimeoutMS            int      `json:"keep_alive_timeout_ms"`
	MaxFrameSize                  int      `json:"max_frame_size"`
	MaxReceiveBuffer              int      `json:"max_receive_buffer"`
	MaxStreamBuffer               int      `json:"max_stream_buffer"`
	Warnings                      []string `json:"warnings"`
	Invariants                    []string `json:"invariants"`
	ReadOnly                      bool     `json:"read_only"`
}

func BuildMultiplexPolicyPlan(req MultiplexPolicyRequest) (MultiplexPolicyPlan, error) {
	protocol := strings.ToLower(strings.TrimSpace(req.Protocol))
	if protocol == "" {
		protocol = "smux"
	}
	if protocol != "smux" && protocol != "yamux" && protocol != "h2mux" {
		return MultiplexPolicyPlan{}, fmt.Errorf("unsupported multiplex protocol %q", protocol)
	}
	version := req.Version
	if version == 0 {
		version = 1 // target runtime compatibility default; SMUX v2 may be requested explicitly.
	}
	if version != 1 && version != 2 {
		return MultiplexPolicyPlan{}, fmt.Errorf("multiplex version must be 1 or 2")
	}
	maxConn := req.MaxConnections
	if maxConn == 0 {
		maxConn = 1
	}
	if maxConn < 1 || maxConn > maxMuxConnections {
		return MultiplexPolicyPlan{}, fmt.Errorf("max connections must be between 1 and %d", maxMuxConnections)
	}
	maxStreams := req.MaxStreamsPerConnection
	if maxStreams == 0 {
		maxStreams = 128
	}
	if maxStreams < 1 || maxStreams > maxMuxStreamsPerConnection {
		return MultiplexPolicyPlan{}, fmt.Errorf("max streams per connection must be between 1 and %d", maxMuxStreamsPerConnection)
	}
	if req.MinStreams < 0 || req.MinStreams > maxStreams {
		return MultiplexPolicyPlan{}, fmt.Errorf("min streams must be between 0 and max streams")
	}
	paddingMax := req.MaxPaddingBytes
	if req.Padding && paddingMax == 0 {
		paddingMax = 768
	}
	if paddingMax < 0 || paddingMax > maxMuxPaddingBytes {
		return MultiplexPolicyPlan{}, fmt.Errorf("padding bound must be between 0 and %d bytes", maxMuxPaddingBytes)
	}
	if req.BandwidthUpBPS < 0 || req.BandwidthDownBPS < 0 {
		return MultiplexPolicyPlan{}, fmt.Errorf("bandwidth limits cannot be negative")
	}
	keepInterval := req.KeepAliveIntervalMS
	keepTimeout := req.KeepAliveTimeoutMS
	if !req.KeepAliveDisabled {
		if keepInterval == 0 {
			keepInterval = 10000
		}
		if keepTimeout == 0 {
			keepTimeout = 30000
		}
		if keepInterval < 1000 || keepInterval > 300000 {
			return MultiplexPolicyPlan{}, fmt.Errorf("keep-alive interval must be 1000..300000 ms")
		}
		if keepTimeout < keepInterval || keepTimeout > 900000 {
			return MultiplexPolicyPlan{}, fmt.Errorf("keep-alive timeout must be >= interval and <=900000 ms")
		}
	} else if keepInterval != 0 || keepTimeout != 0 {
		return MultiplexPolicyPlan{}, fmt.Errorf("disabled keep-alive cannot carry interval/timeout")
	}
	frame := req.MaxFrameSize
	if frame == 0 {
		frame = 32768
	}
	if frame < 1 || frame > maxMuxFrameBytes {
		return MultiplexPolicyPlan{}, fmt.Errorf("max frame size must be 1..%d", maxMuxFrameBytes)
	}
	receive := req.MaxReceiveBuffer
	if receive == 0 {
		receive = 4 << 20
	}
	if receive < frame || receive > maxMuxReceiveBufferBytes {
		return MultiplexPolicyPlan{}, fmt.Errorf("max receive buffer must be between frame size and %d", maxMuxReceiveBufferBytes)
	}
	stream := req.MaxStreamBuffer
	if stream == 0 {
		stream = 64 << 10
	}
	if stream < frame || stream > receive || stream > maxMuxStreamBufferBytes {
		return MultiplexPolicyPlan{}, fmt.Errorf("max stream buffer must be between frame size and min(receive buffer,%d)", maxMuxStreamBufferBytes)
	}
	platform := strings.ToLower(strings.TrimSpace(req.Platform))
	if platform == "" {
		platform = runtime.GOOS
	}
	bandwidthRequested := req.BandwidthUpBPS > 0 || req.BandwidthDownBPS > 0
	plan := MultiplexPolicyPlan{
		Protocol: protocol, RuntimeSupported: protocol == "smux", Version: version,
		MaxConnections: maxConn, MaxStreamsPerConnection: maxStreams,
		EstimatedMaxConcurrentStreams: maxConn * maxStreams,
		SessionSelection:              "least-active-streams-with-bounded-admission",
		Padding:                       req.Padding, MaxPaddingBytes: paddingMax, ReadOnly: true,
		KeepAliveDisabled: req.KeepAliveDisabled, KeepAliveIntervalMS: keepInterval, KeepAliveTimeoutMS: keepTimeout,
		MaxFrameSize: frame, MaxReceiveBuffer: receive, MaxStreamBuffer: stream,
		Warnings: []string{}, Invariants: []string{
			"first Write reports application payload bytes, never framing/padding overhead",
			"peer-supplied padding length is bounded before discard/allocation",
			"half-close and terminal errors close session ownership exactly once",
			"stream-open retry is bounded",
			"SMUX protocol version is explicit and limited to v1/v2; zero means target-compatible v1 default",
			"keep-alive timeout is never shorter than its interval and frame/receive/stream buffers are mutually bounded",
		},
	}
	if bandwidthRequested {
		plan.BandwidthControlSupported = platform == "linux" && protocol == "smux"
		if !plan.BandwidthControlSupported {
			plan.Warnings = append(plan.Warnings, "requested brutal/bandwidth control has no target runtime owner on this protocol/platform")
		}
	}
	if protocol != "smux" {
		plan.Warnings = append(plan.Warnings, "target runtime currently owns SMUX only; this protocol is evidence-only")
	}
	return plan, nil
}
