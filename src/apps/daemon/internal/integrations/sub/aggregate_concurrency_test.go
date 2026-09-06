package sub

import (
	"context"
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	"github.com/maybeknott/luminet/internal/networking/proxyconfig"
)

func TestResolveInputsBoundedPreservesOrderAndCapsConcurrency(t *testing.T) {
	inputs := make([]string, 12)
	for i := range inputs {
		inputs[i] = fmt.Sprintf("input-%02d", i)
	}
	var active atomic.Int32
	var maximum atomic.Int32
	resolver := func(_ context.Context, input string, _ bool) []*proxyconfig.ProxyConfig {
		now := active.Add(1)
		defer active.Add(-1)
		for {
			old := maximum.Load()
			if now <= old || maximum.CompareAndSwap(old, now) {
				break
			}
		}
		time.Sleep(5 * time.Millisecond)
		return []*proxyconfig.ProxyConfig{{Name: input}}
	}

	batches := resolveInputsBounded(context.Background(), inputs, false, resolver)
	if got := maximum.Load(); got > maxConcurrentSubscriptionInputs {
		t.Fatalf("max concurrency = %d, limit = %d", got, maxConcurrentSubscriptionInputs)
	}
	if maximum.Load() < 2 {
		t.Fatalf("expected concurrent execution, max = %d", maximum.Load())
	}
	for i, batch := range batches {
		if len(batch) != 1 || batch[0].Name != inputs[i] {
			t.Fatalf("batch %d = %#v, want %q", i, batch, inputs[i])
		}
	}
}
