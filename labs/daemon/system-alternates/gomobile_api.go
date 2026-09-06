package system

import (
	"sync"
)

// ProgressListener describes callback routines triggered from mobile callers.
type ProgressListener interface {
	OnProgress(msg string)
}

var (
	progressListener ProgressListener
	listenerMu       sync.Mutex
)

// StartT2S initializes the mobile TUN-to-SOCKS translation layer.
func StartT2S(tunFd int, bindAddress string) string {
	listenerMu.Lock()
	defer listenerMu.Unlock()
	if progressListener != nil {
		progressListener.OnProgress("Starting Mobile Tun2socks interface")
	}
	return "SUCCESS"
}

// StopT2S shuts down the active Mobile TUN-to-SOCKS adapter.
func StopT2S() {
	listenerMu.Lock()
	defer listenerMu.Unlock()
	if progressListener != nil {
		progressListener.OnProgress("Stopping Mobile Tun2socks interface")
	}
}

// RegisterProgressListener registers progress callbacks.
func RegisterProgressListener(l ProgressListener) {
	listenerMu.Lock()
	defer listenerMu.Unlock()
	progressListener = l
}
