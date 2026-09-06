package bridge

import "time"

const (
	defaultAsyncOperationTimeout = 3 * time.Second
	asyncCallbackGrace           = 2 * time.Second
	maxAsyncCallbackWait         = 10 * time.Minute
)

func asyncWaitDuration(timeoutMs uint32) time.Duration {
	base := time.Duration(timeoutMs) * time.Millisecond
	if base <= 0 {
		base = defaultAsyncOperationTimeout
	}
	wait := base + asyncCallbackGrace
	if wait > maxAsyncCallbackWait {
		return maxAsyncCallbackWait
	}
	return wait
}
