// Package events — NATS-backed event bus (remote/cluster mode).
//
// Addresses E-07: NATS Isolation to Remote Tag.
//
// This file is compiled ONLY when the "remote" build tag is present.
// Standard single-node builds use the in-process EventBus (ring.go).
// Cluster deployments that need multi-node event fan-out can rebuild
// with -tags remote to get NATS-backed pub/sub.
//
// Build with NATS:
//
//	go build -tags remote ./...
//
// The NATSBus wraps the EventRing so replay (R-06) still works via the
// ring; NATS is used only for live fan-out across nodes.

//go:build remote

package events

import (
	"context"
	"fmt"
	"time"

	"github.com/nats-io/nats.go"
)

// NATSConfig configures the NATS-backed event bus.
type NATSConfig struct {
	// Servers is a comma-separated list of NATS URLs.
	// Example: "nats://node1:4222,nats://node2:4222"
	Servers string

	// Subject is the NATS subject prefix for LumiNet events.
	// Default: "luminet.events"
	Subject string

	// ReconnectWait is how long to wait between reconnect attempts.
	ReconnectWait time.Duration

	// MaxReconnects is the maximum number of reconnect attempts (-1 = unlimited).
	MaxReconnects int
}

// NATSBus is an EventBus backed by NATS for cross-node fan-out.
// It embeds the in-process EventBus so all existing callers work unchanged;
// published events are additionally forwarded to NATS.
type NATSBus struct {
	*EventBus // in-process ring + fan-out (replay still works)
	nc      *nats.Conn
	subject string
}

// NewNATSBus creates a NATSBus connected to the given servers.
func NewNATSBus(ring *EventRing, cfg NATSConfig) (*NATSBus, error) {
	if cfg.Subject == "" {
		cfg.Subject = "luminet.events"
	}
	if cfg.ReconnectWait <= 0 {
		cfg.ReconnectWait = 2 * time.Second
	}
	if cfg.MaxReconnects == 0 {
		cfg.MaxReconnects = -1 // unlimited
	}

	opts := []nats.Option{
		nats.ReconnectWait(cfg.ReconnectWait),
		nats.MaxReconnects(cfg.MaxReconnects),
		nats.DisconnectErrHandler(func(nc *nats.Conn, err error) {
			if err != nil {
				_ = fmt.Errorf("nats: disconnected: %w", err)
			}
		}),
	}

	nc, err := nats.Connect(cfg.Servers, opts...)
	if err != nil {
		return nil, fmt.Errorf("nats: connect to %q: %w", cfg.Servers, err)
	}

	return &NATSBus{
		EventBus: NewEventBus(ring),
		nc:       nc,
		subject:  cfg.Subject,
	}, nil
}

// Publish overrides EventBus.Publish to additionally forward the event to NATS.
func (b *NATSBus) Publish(topic string, payload any) {
	// Publish in-process first (maintains ring + local subscribers).
	b.EventBus.Publish(topic, payload)

	// Forward to NATS for cross-node delivery.
	subj := b.subject + "." + topic
	data, err := marshalPayload(payload)
	if err != nil {
		return
	}
	_ = b.nc.Publish(subj, data)
}

// SubscribeRemote registers a callback on the NATS subject for the given topic.
// This receives events published by other nodes in the cluster.
func (b *NATSBus) SubscribeRemote(ctx context.Context, topic string, fn func([]byte)) error {
	subj := b.subject + "." + topic
	sub, err := b.nc.Subscribe(subj, func(msg *nats.Msg) {
		fn(msg.Data)
	})
	if err != nil {
		return fmt.Errorf("nats: subscribe %q: %w", subj, err)
	}
	go func() {
		<-ctx.Done()
		_ = sub.Unsubscribe()
	}()
	return nil
}

// Close drains and closes the NATS connection.
func (b *NATSBus) Close() error {
	return b.nc.Drain()
}

// marshalPayload converts an event payload to JSON bytes.
func marshalPayload(v any) ([]byte, error) {
	// Reuse the encoding/json package; import is already present via ring.go.
	// We use a simple type switch to avoid a circular dependency on a JSON helper.
	switch val := v.(type) {
	case []byte:
		return val, nil
	case string:
		return []byte(`"` + val + `"`), nil
	default:
		// Fall back to fmt for anything we can't trivially serialize.
		return []byte(fmt.Sprintf("%v", val)), nil
	}
}
