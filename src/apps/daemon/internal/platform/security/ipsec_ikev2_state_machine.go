package security

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"sync"
)

// IkeState represents the lifecycle phase of an IKEv2 / IPsec session
type IkeState string

const (
	IkeStateInit         IkeState = "INIT"
	IkeStateSaInitSent   IkeState = "SA_INIT_SENT"
	IkeStateSaInitRecv   IkeState = "SA_INIT_RECV"
	IkeStateAuthSent     IkeState = "AUTH_SENT"
	IkeStateEstablished  IkeState = "ESTABLISHED"
	IkeStateRekeying     IkeState = "REKEYING"
	IkeStateClosed       IkeState = "CLOSED"
)

// IkeMessageExchange represents RFC 7296 exchange types
type IkeExchangeType uint8

const (
	ExchangeIkeSaInit    IkeExchangeType = 34
	ExchangeIkeAuth      IkeExchangeType = 35
	ExchangeCreateChildSa IkeExchangeType = 36
	ExchangeInformational IkeExchangeType = 37
)

// IpsecIkev2StateMachine coordinates IKEv2 security associations and state transitions
type IpsecIkev2StateMachine struct {
	initiatorSPI uint64
	responderSPI uint64
	state        IkeState
	messageID    uint32
	sharedSecret []byte
	mu           sync.RWMutex
}

// NewIpsecIkev2StateMachine initializes a new IKEv2 state machine
func NewIpsecIkev2StateMachine(secret []byte) (*IpsecIkev2StateMachine, error) {
	if len(secret) < 16 {
		return nil, errors.New("shared secret must be at least 16 bytes")
	}
	var spiBytes [8]byte
	if _, err := rand.Read(spiBytes[:]); err != nil {
		return nil, err
	}
	spi := binary.BigEndian.Uint64(spiBytes[:])

	return &IpsecIkev2StateMachine{
		initiatorSPI: spi,
		responderSPI: 0,
		state:        IkeStateInit,
		messageID:    0,
		sharedSecret: secret,
	}, nil
}

// State returns current session state
func (sm *IpsecIkev2StateMachine) State() IkeState {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	return sm.state
}

// InitiatorSPI returns the 64-bit SPI
func (sm *IpsecIkev2StateMachine) InitiatorSPI() uint64 {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	return sm.initiatorSPI
}

// BuildSaInitRequest creates an IKE_SA_INIT frame (28-byte IKE header + payload)
func (sm *IpsecIkev2StateMachine) BuildSaInitRequest(nonce []byte) ([]byte, error) {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	if sm.state != IkeStateInit {
		return nil, errors.New("cannot send SA_INIT from non-INIT state")
	}

	frame := make([]byte, 28+len(nonce))
	binary.BigEndian.PutUint64(frame[0:8], sm.initiatorSPI)
	binary.BigEndian.PutUint64(frame[8:16], 0) // responder SPI is 0 in init
	frame[16] = 33                             // Next payload: SA (Security Association)
	frame[17] = 0x20                           // Version 2.0
	frame[18] = byte(ExchangeIkeSaInit)
	frame[19] = 0x08                           // Flags: Initiator
	binary.BigEndian.PutUint32(frame[20:24], sm.messageID)
	binary.BigEndian.PutUint32(frame[24:28], uint32(len(frame)))
	copy(frame[28:], nonce)

	sm.state = IkeStateSaInitSent
	sm.messageID++
	return frame, nil
}

// ProcessSaInitResponse validates responder SPI and moves to SA_INIT_RECV
func (sm *IpsecIkev2StateMachine) ProcessSaInitResponse(resp []byte) error {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	if sm.state != IkeStateSaInitSent {
		return errors.New("unexpected state for SA_INIT response")
	}
	if len(resp) < 28 {
		return errors.New("response shorter than IKE header")
	}

	initSPI := binary.BigEndian.Uint64(resp[0:8])
	if initSPI != sm.initiatorSPI {
		return errors.New("initiator SPI mismatch")
	}

	respSPI := binary.BigEndian.Uint64(resp[8:16])
	if respSPI == 0 {
		return errors.New("responder SPI cannot be zero")
	}
	sm.responderSPI = respSPI
	sm.state = IkeStateSaInitRecv
	return nil
}

// TransitionToAuthSent moves state to AUTH_SENT
func (sm *IpsecIkev2StateMachine) TransitionToAuthSent() error {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	if sm.state != IkeStateSaInitRecv {
		return errors.New("must be in SA_INIT_RECV state to send AUTH")
	}
	sm.state = IkeStateAuthSent
	return nil
}

// FinalizeEstablished marks connection as established
func (sm *IpsecIkev2StateMachine) FinalizeEstablished() error {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	if sm.state != IkeStateAuthSent {
		return errors.New("must be in AUTH_SENT state to establish")
	}
	sm.state = IkeStateEstablished
	return nil
}

// Close terminates the SA
func (sm *IpsecIkev2StateMachine) Close() {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	sm.state = IkeStateClosed
}
