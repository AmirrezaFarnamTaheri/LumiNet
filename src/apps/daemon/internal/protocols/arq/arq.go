package arq

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/maybeknott/luminet/internal/protocols/reliable"
)

const (
	PACKET_STREAM_DATA      uint8 = 0x0F
	PACKET_STREAM_DATA_ACK  uint8 = 0x10
	PACKET_STREAM_DATA_NACK uint8 = 0x11
	PACKET_STREAM_SYN       uint8 = 0x01
	PACKET_STREAM_SYN_ACK   uint8 = 0x02
	PACKET_STREAM_CLOSE     uint8 = 0x03
	PACKET_STREAM_CLOSE_ACK uint8 = 0x04
	PACKET_STREAM_RST       uint8 = 0x05
	PACKET_STREAM_RST_ACK   uint8 = 0x06
)

type PacketSender interface {
	SendPacket(uint8, uint16, []byte) error
}
type Logger interface {
	Debugf(string, ...interface{})
	Infof(string, ...interface{})
	Errorf(string, ...interface{})
}
type DummyLogger struct{}

func (*DummyLogger) Debugf(string, ...interface{}) {}
func (*DummyLogger) Infof(string, ...interface{})  {}
func (*DummyLogger) Errorf(string, ...interface{}) {}

type Config struct {
	WindowSize               int
	DefaultRTO, MaxRTO       time.Duration
	MaxRetries               int
	EnableControlReliability bool
}
type adaptiveRTOState struct {
	currentBase time.Duration
	initialized bool
}
type ARQ struct {
	mu                 sync.Mutex
	sender             PacketSender
	logger             Logger
	config             Config
	core               *reliable.Stream
	isClosed           bool
	ctx                context.Context
	cancel             context.CancelFunc
	condRead, condSend *sync.Cond
	readBuf            []byte
	dataAdaptiveRTO    adaptiveRTOState
}

func NewARQ(sender PacketSender, logger Logger, cfg Config) *ARQ {
	if logger == nil {
		logger = &DummyLogger{}
	}
	if cfg.WindowSize <= 0 {
		cfg.WindowSize = 128
	}
	if cfg.DefaultRTO <= 0 {
		cfg.DefaultRTO = 300 * time.Millisecond
	}
	if cfg.MaxRTO <= 0 {
		cfg.MaxRTO = 5 * time.Second
	}
	if cfg.MaxRetries <= 0 {
		cfg.MaxRetries = 30
	}
	ctx, cancel := context.WithCancel(context.Background())
	a := &ARQ{sender: sender, logger: logger, config: cfg, ctx: ctx, cancel: cancel, core: reliable.New(reliable.DirectProfile(cfg.WindowSize, cfg.DefaultRTO, cfg.MaxRTO, cfg.MaxRetries))}
	a.condRead = sync.NewCond(&a.mu)
	a.condSend = sync.NewCond(&a.mu)
	return a
}
func (a *ARQ) Close() error {
	a.mu.Lock()
	if a.isClosed {
		a.mu.Unlock()
		return nil
	}
	a.isClosed = true
	a.core.Step(reliable.Command{Op: reliable.Stop})
	a.cancel()
	a.condRead.Broadcast()
	a.condSend.Broadcast()
	a.mu.Unlock()
	a.logger.Infof("ARQ session closed gracefully")
	return nil
}
func (a *ARQ) IsClosed() bool { a.mu.Lock(); defer a.mu.Unlock(); return a.isClosed }
func (a *ARQ) Write(p []byte) error {
	if len(p) == 0 {
		return nil
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	for {
		if a.isClosed {
			return errors.New("write to closed ARQ session")
		}
		r := a.core.Step(reliable.Command{Op: reliable.Send, Payload: p})
		if r.Status != reliable.WouldBlock {
			a.dispatch(r)
			return nil
		}
		a.condSend.Wait()
	}
}
func (a *ARQ) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	for len(a.readBuf) == 0 {
		if a.isClosed {
			return 0, fmt.Errorf("read: connection closed")
		}
		a.condRead.Wait()
	}
	n := copy(p, a.readBuf)
	a.readBuf = a.readBuf[n:]
	return n, nil
}
func (a *ARQ) HandleInboundPacket(kind uint8, seq uint16, p []byte) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.isClosed {
		return errors.New("cannot handle packet: ARQ closed")
	}
	k := reliable.Kind(0)
	switch kind {
	case PACKET_STREAM_DATA:
		k = reliable.Data
	case PACKET_STREAM_DATA_ACK:
		k = reliable.Ack
	case PACKET_STREAM_DATA_NACK:
		k = reliable.Nack
	default:
		return nil
	}
	a.dispatch(a.core.Step(reliable.Command{Op: reliable.Receive, Frame: reliable.Frame{Kind: k, Seq: seq, Payload: p}}))
	return nil
}
func (a *ARQ) CheckRetransmissions() {
	a.mu.Lock()
	defer a.mu.Unlock()
	if !a.isClosed {
		a.dispatch(a.core.Step(reliable.Command{Op: reliable.Tick}))
	}
}
func (a *ARQ) dispatch(r reliable.Result) {
	for _, d := range r.Delivered {
		a.readBuf = append(a.readBuf, d.Payload...)
	}
	if len(r.Delivered) > 0 {
		a.condRead.Broadcast()
	}
	for _, f := range r.Outbound {
		kind := PACKET_STREAM_DATA
		if f.Kind == reliable.Ack {
			kind = PACKET_STREAM_DATA_ACK
		}
		if f.Kind == reliable.Nack {
			kind = PACKET_STREAM_DATA_NACK
		}
		if err := a.sender.SendPacket(kind, f.Seq, f.Payload); err != nil {
			a.logger.Errorf("Failed to send packet seq=%d: %v", f.Seq, err)
		}
	}
	st := a.core.Stats()
	a.dataAdaptiveRTO = adaptiveRTOState{currentBase: st.RTO, initialized: st.RTOInitialized}
	if st.Closed {
		a.isClosed = true
		a.cancel()
		a.condRead.Broadcast()
	}
	a.condSend.Broadcast()
}
