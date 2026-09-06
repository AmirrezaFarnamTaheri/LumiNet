package bridge

import (
	"testing"
	"time"
)

func TestAsyncWaitDurationUsesOperationTimeoutPlusGrace(t *testing.T) {
	if got := asyncWaitDuration(2500); got != 4500*time.Millisecond {
		t.Fatalf("wait=%s", got)
	}
}

func TestAsyncWaitDurationUsesBoundedDefaultAndCeiling(t *testing.T) {
	if got := asyncWaitDuration(0); got != defaultAsyncOperationTimeout+asyncCallbackGrace {
		t.Fatalf("default wait=%s", got)
	}
	if got := asyncWaitDuration(^uint32(0)); got != maxAsyncCallbackWait {
		t.Fatalf("max wait=%s", got)
	}
}
