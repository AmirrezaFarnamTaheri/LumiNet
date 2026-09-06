package diagnostics

import "fmt"

const maxSNIDecoyPayloadBytes = 4096

// SNIDecoyHandshakePlanRequest contains caller-observed TCP handshake evidence.
// The planner never captures packets or injects traffic.
type SNIDecoyHandshakePlanRequest struct {
	SYNSeen          bool   `json:"syn_seen"`
	SYNSeq           uint32 `json:"syn_seq"`
	SYNACKSeen       bool   `json:"syn_ack_seen"`
	SYNACKAck        uint32 `json:"syn_ack_ack"`
	ServerSeq        uint32 `json:"server_seq"`
	ThirdACKSeen     bool   `json:"third_ack_seen"`
	ThirdACKSeq      uint32 `json:"third_ack_seq"`
	ThirdACKAck      uint32 `json:"third_ack_ack"`
	FakeInjected     bool   `json:"fake_injected"`
	FakePayloadBytes int    `json:"fake_payload_bytes"`
	ServerACKSeen    bool   `json:"server_ack_seen"`
	ServerACK        uint32 `json:"server_ack"`
	RSTSeen          bool   `json:"rst_seen"`
}

// SNIDecoyHandshakePlan models the evidence gates around out-of-window SNI
// decoy injection. It does not grant raw-packet authority.
type SNIDecoyHandshakePlan struct {
	State                      string   `json:"state"`
	ReadyToInject              bool     `json:"ready_to_inject"`
	ReadyToRelay               bool     `json:"ready_to_relay"`
	ExpectedRealSeq            uint32   `json:"expected_real_seq"`
	ExpectedServerACK          uint32   `json:"expected_server_ack"`
	ExpectedThirdACK           uint32   `json:"expected_third_ack"`
	ExpectedFakeSeq            uint32   `json:"expected_fake_seq"`
	PerformsNetworkIO          bool     `json:"performs_network_io"`
	RequiresRawPacketAuthority bool     `json:"requires_raw_packet_authority"`
	Reasons                    []string `json:"reasons"`
	Invariants                 []string `json:"invariants"`
}

// BuildSNIDecoyHandshakePlan evaluates supplied observations only. It hardens
// the donor lifecycle by requiring both halves of the TCP three-way handshake
// to match before injection can be considered eligible.
func BuildSNIDecoyHandshakePlan(req SNIDecoyHandshakePlanRequest) (SNIDecoyHandshakePlan, error) {
	if req.FakePayloadBytes <= 0 || req.FakePayloadBytes > maxSNIDecoyPayloadBytes {
		return SNIDecoyHandshakePlan{}, fmt.Errorf("fake_payload_bytes must be in 1..%d", maxSNIDecoyPayloadBytes)
	}

	plan := SNIDecoyHandshakePlan{
		State:                      "awaiting-syn",
		PerformsNetworkIO:          false,
		RequiresRawPacketAuthority: true,
		Invariants: []string{
			"the planner consumes caller-supplied observations only and captures no packet",
			"connection identity must be bound outside this planner to an exact source/destination IP and port tuple",
			"decoy injection is eligible only after a coherent SYN, SYN-ACK, and payload-free third ACK",
			"the decoy sequence ends immediately before the first real payload sequence",
			"relay readiness requires explicit server acknowledgement that the next expected client sequence remains ISN+1",
			"RST evidence fails the lifecycle closed",
			"this planner never grants raw-packet authority or injects traffic",
		},
	}

	if req.RSTSeen {
		plan.State = "failed-rst"
		plan.Reasons = append(plan.Reasons, "server RST observed")
		return plan, nil
	}
	if !req.SYNSeen {
		plan.Reasons = append(plan.Reasons, "client SYN not observed")
		return plan, nil
	}

	plan.ExpectedRealSeq = req.SYNSeq + 1
	plan.ExpectedServerACK = plan.ExpectedRealSeq
	plan.ExpectedFakeSeq = plan.ExpectedRealSeq - uint32(req.FakePayloadBytes)
	plan.State = "awaiting-syn-ack"
	if !req.SYNACKSeen {
		plan.Reasons = append(plan.Reasons, "server SYN-ACK not observed")
		return plan, nil
	}
	if req.SYNACKAck != plan.ExpectedRealSeq {
		plan.State = "invalid-syn-ack"
		plan.Reasons = append(plan.Reasons, "SYN-ACK acknowledgement does not match client ISN+1")
		return plan, nil
	}

	plan.ExpectedThirdACK = req.ServerSeq + 1
	plan.State = "awaiting-third-ack"
	if !req.ThirdACKSeen {
		plan.Reasons = append(plan.Reasons, "client third ACK not observed")
		return plan, nil
	}
	if req.ThirdACKSeq != plan.ExpectedRealSeq {
		plan.State = "invalid-third-ack"
		plan.Reasons = append(plan.Reasons, "third ACK sequence does not match client ISN+1")
		return plan, nil
	}
	if req.ThirdACKAck != plan.ExpectedThirdACK {
		plan.State = "invalid-third-ack"
		plan.Reasons = append(plan.Reasons, "third ACK acknowledgement does not match server ISN+1")
		return plan, nil
	}

	plan.ReadyToInject = !req.FakeInjected
	if !req.FakeInjected {
		plan.State = "ready-to-inject"
		plan.Reasons = append(plan.Reasons, "coherent three-way handshake observed")
		return plan, nil
	}

	plan.State = "awaiting-server-confirmation"
	if !req.ServerACKSeen {
		plan.Reasons = append(plan.Reasons, "decoy injection reported but server acknowledgement not observed")
		return plan, nil
	}
	if req.ServerACK != plan.ExpectedServerACK {
		plan.State = "decoy-not-confirmed"
		plan.Reasons = append(plan.Reasons, "server acknowledgement advanced or differs from client ISN+1; decoy-ignore evidence is not established")
		return plan, nil
	}

	plan.State = "fake-confirmed"
	plan.ReadyToRelay = true
	plan.Reasons = append(plan.Reasons, "server still expects client ISN+1 after decoy injection")
	return plan, nil
}
