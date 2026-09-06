package mobilehost

import (
	"sync"
)

var (
	captivePortalCallback func(string)
	captivePortalMu       sync.RWMutex
)

// SetCaptivePortalCallback registers a callback to be invoked when a captive portal is detected.
func SetCaptivePortalCallback(cb func(string)) {
	captivePortalMu.Lock()
	defer captivePortalMu.Unlock()
	captivePortalCallback = cb
}

// TriggerCaptivePortalCallback invokes the registered captive portal callback.
func TriggerCaptivePortalCallback(redirectURL string) {
	captivePortalMu.RLock()
	cb := captivePortalCallback
	captivePortalMu.RUnlock()
	if cb != nil {
		cb(redirectURL)
	}
}
