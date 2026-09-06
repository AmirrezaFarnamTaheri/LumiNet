package proxy

import (
	"sync"
	"time"
)

type KeepAliveHeartbeat struct {
	mu       sync.Mutex
	interval time.Duration
}

func NewKeepAliveHeartbeat(interval time.Duration) *KeepAliveHeartbeat {
	return &KeepAliveHeartbeat{interval: interval}
}
