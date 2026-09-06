package transport

import (
	"net"
	"sync"
)

type MultipathEvasionPipeline struct {
	Tunnel         *MultipathTunnelManager
	Scrambler      *PacketScrambler
	Profile        *RegionalEvasionProfile
	TotalProcessed uint64
	mu             sync.Mutex
}

func NewMultipathEvasionPipeline(
	tunnelID string,
	mode BondingMode,
	queueNum uint16,
	mark uint32,
	region CensorshipRegion,
) *MultipathEvasionPipeline {
	synth := NewCensorshipProfileSynthesizer()
	prof := synth.GetProfile(region)
	scrambler := NewPacketScrambler(queueNum, mark)

	if prof.TcpMssClamp < 1200 {
		scrambler.TTLHopLimit = 48
	} else {
		scrambler.TTLHopLimit = 64
	}

	return &MultipathEvasionPipeline{
		Tunnel:    NewMultipathTunnelManager(tunnelID, mode),
		Scrambler: scrambler,
		Profile:   prof,
	}
}

func (p *MultipathEvasionPipeline) RegisterPath(id uint32, local, remote *net.UDPAddr, weight uint32) {
	p.Tunnel.AddPath(NewPathMetrics(id, local, remote, weight))
}

func (p *MultipathEvasionPipeline) PrepareOutboundPacket(dest *net.TCPAddr, payload []byte) (uint32, []byte, error) {
	p.mu.Lock()
	p.TotalProcessed++
	p.mu.Unlock()

	// 1. Scramble/inspect
	action := p.Scrambler.ProcessIPPacket(dest, payload)
	if action == ActionAccept {
		// normal flow
	}

	// 2. Select path
	pathID, err := p.Tunnel.SelectPathForEgress()
	if err != nil {
		return 0, nil, err
	}

	// 3. Encapsulate
	frame, err := p.Tunnel.Encapsulate(pathID, payload)
	if err != nil {
		return 0, nil, err
	}

	return pathID, frame, nil
}
