package relayclient

import (
	"context"
	"time"
)

const (
	relayIdlePollBaseDelay = 200 * time.Millisecond
	relayIdlePollMaxDelay  = 4 * time.Second
)

// relayPollRequest returns whether downstream payload bytes were received.
type relayPollRequest func([]byte) (bool, error)

// runAdaptiveRelayPolling is the single success/idle polling state machine for
// HTTP relay adapters. Transport-error retry remains owned by RecordPollFailure.
func runAdaptiveRelayPolling(ctx context.Context, state *relayConnState, request relayPollRequest, onWriteCommitted func(int)) {
	timer := time.NewTimer(0)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-state.TxReady():
		case <-timer.C:
		}
		if state.isClosed() {
			return
		}
		data := state.TakeWriteBatch()
		if len(data) == 0 && state.ReadBuffered() != 0 {
			resetRelayTimer(timer, relayIdlePollBaseDelay)
			continue
		}
		received, err := request(data)
		if err != nil {
			if state.isClosed() {
				return
			}
			if len(data) > 0 {
				state.RollbackWrite(data)
			}
			if !waitRelayRetry(ctx, state.RecordPollFailure()) {
				return
			}
			resetRelayTimer(timer, relayIdlePollBaseDelay)
			continue
		}
		state.RecordPollSuccess()
		if len(data) > 0 {
			state.CommitWrite(len(data))
			if onWriteCommitted != nil {
				onWriteCommitted(len(data))
			}
		}
		delay := state.RecordIdlePoll(len(data) == 0 && !received)
		resetRelayTimer(timer, delay)
	}
}

func resetRelayTimer(timer *time.Timer, delay time.Duration) {
	if delay < 0 {
		delay = 0
	}
	if !timer.Stop() {
		select {
		case <-timer.C:
		default:
		}
	}
	timer.Reset(delay)
}
