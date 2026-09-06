//go:build cgo && !android && !ios

package bridge

// #include <stdlib.h>
// #include "lumicore_abi.h"
// extern void goStreamCallback(uint16_t event_type, uint8_t* data,
//                              size_t data_len, void* user_data);
import "C"
import (
	"fmt"
	"sync"
	"unsafe"
)

const streamBufDepth = 256 // channel capacity before drops

type streamSink struct {
	mu     sync.Mutex
	ch     chan StreamEvent
	closed bool
}

var (
	sinkMu    sync.Mutex
	sinkTable         = map[uintptr]*streamSink{}
	sinkSeq   uintptr = 1
)

// StartStream registers a Go channel and starts a Rust streaming operation.
// Cancellation only requests Rust-side cancellation; the channel is closed by
// the terminal callback after Rust has stopped issuing stream callbacks.
// Returns: receive channel, cancel func, error.
func StartStream(op uint16, payload []byte) (<-chan StreamEvent, func(), error) {
	ch := make(chan StreamEvent, streamBufDepth)
	sink := &streamSink{ch: ch}
	sinkMu.Lock()
	id := sinkSeq
	sinkSeq++
	sinkTable[id] = sink
	sinkMu.Unlock()

	var inputPtr *C.uint8_t
	if len(payload) > 0 {
		inputPtr = (*C.uint8_t)(unsafe.Pointer(&payload[0]))
	}

	callbackContext, err := streamContext(id)
	if err != nil {
		sinkMu.Lock()
		delete(sinkTable, id)
		sinkMu.Unlock()
		close(ch)
		return nil, nil, err
	}
	handle := C.lumicore_stream_start(
		C.uint16_t(op),
		inputPtr, C.size_t(len(payload)),
		C.StreamCallback(C.goStreamCallback),
		callbackContext,
	)

	if handle.stream_id == 0 {
		C.free(callbackContext)
		sinkMu.Lock()
		delete(sinkTable, id)
		sinkMu.Unlock()
		close(ch)
		return nil, nil, fmt.Errorf("lumicore streaming runtime unavailable")
	}

	var cancelOnce sync.Once
	cancel := func() {
		cancelOnce.Do(func() {
			C.lumicore_stream_cancel(handle)
		})
	}
	return ch, cancel, nil
}

//export goStreamCallback
func goStreamCallback(eventType C.uint16_t, data *C.uint8_t, dataLen C.size_t, userData unsafe.Pointer) {
	id := uintptr(*(*C.uintptr_t)(userData))

	sinkMu.Lock()
	sink := sinkTable[id]
	sinkMu.Unlock()
	if sink == nil {
		return
	}

	terminal := eventType == C.uint16_t(C.LUMICORE_STREAM_EVT_SCAN_DONE)
	var payload []byte
	if dataLen > 0 {
		payload = C.GoBytes(unsafe.Pointer(data), C.int(dataLen))
	}

	sink.mu.Lock()
	if sink.closed {
		sink.mu.Unlock()
		return
	}
	if terminal {
		sink.closed = true
	}
	select {
	case sink.ch <- StreamEvent{Type: uint16(eventType), Data: payload}:
	default: // drop if consumer is slower than producer
	}
	if terminal {
		close(sink.ch)
	}
	sink.mu.Unlock()

	if terminal {
		sinkMu.Lock()
		if sinkTable[id] == sink {
			delete(sinkTable, id)
		}
		sinkMu.Unlock()
		C.free(userData)
	}
}

func streamContext(id uintptr) (unsafe.Pointer, error) {
	context := C.malloc(C.size_t(unsafe.Sizeof(C.uintptr_t(0))))
	if context == nil {
		return nil, fmt.Errorf("allocate stream callback context")
	}
	*(*C.uintptr_t)(context) = C.uintptr_t(id)
	return context, nil
}
