package transport

import (
	"sync"
)

type SocketState int

const (
	SocketStateActive SocketState = iota
	SocketStateStandby
	SocketStateDegraded
	SocketStateDead
)

type ManagedSocket struct {
	ID                  string
	Endpoint            string
	State               SocketState
	ConsecutiveFailures int
	LastRttMs           uint64
}

type SocketPoolSupervisor struct {
	mu             sync.RWMutex
	sockets        map[string]*ManagedSocket
	activeSocketID string
}

func NewSocketPoolSupervisor() *SocketPoolSupervisor {
	return &SocketPoolSupervisor{
		sockets: make(map[string]*ManagedSocket),
	}
}

func (s *SocketPoolSupervisor) RegisterSocket(id, endpoint string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	state := SocketStateStandby
	if len(s.sockets) == 0 {
		state = SocketStateActive
		s.activeSocketID = id
	}

	s.sockets[id] = &ManagedSocket{
		ID:       id,
		Endpoint: endpoint,
		State:    state,
	}
}

func (s *SocketPoolSupervisor) RecordHeartbeat(id string, rttMs uint64, success bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	sock, ok := s.sockets[id]
	if !ok {
		return
	}

	sock.LastRttMs = rttMs
	if success {
		sock.ConsecutiveFailures = 0
		if sock.State == SocketStateDegraded {
			sock.State = SocketStateStandby
		}
	} else {
		sock.ConsecutiveFailures++
		if sock.ConsecutiveFailures >= 3 {
			sock.State = SocketStateDead
		} else {
			sock.State = SocketStateDegraded
		}
	}

	if s.activeSocketID == id && !success {
		s.electNewActiveLocked()
	}
}

func (s *SocketPoolSupervisor) electNewActiveLocked() {
	var bestID string
	var bestRtt uint64 = ^uint64(0)

	for id, sock := range s.sockets {
		if sock.State == SocketStateStandby {
			if sock.LastRttMs < bestRtt {
				bestRtt = sock.LastRttMs
				bestID = id
			}
		}
	}

	if bestID != "" {
		if cur, ok := s.sockets[s.activeSocketID]; ok && cur.State == SocketStateActive {
			cur.State = SocketStateStandby
		}
		s.sockets[bestID].State = SocketStateActive
		s.activeSocketID = bestID
	}
}

func (s *SocketPoolSupervisor) ActiveSocket() *ManagedSocket {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.activeSocketID == "" {
		return nil
	}
	if sock, ok := s.sockets[s.activeSocketID]; ok {
		cp := *sock
		return &cp
	}
	return nil
}
