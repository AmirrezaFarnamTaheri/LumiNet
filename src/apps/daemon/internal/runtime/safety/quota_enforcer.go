package safety

import (
	"sync"
)

type QuotaAlertLevel int

const (
	QuotaNormal QuotaAlertLevel = iota
	QuotaWarning80
	QuotaExhausted
)

type UserBandwidthQuota struct {
	UserID    string `json:"user_id"`
	MaxBytes  uint64 `json:"max_bytes"`
	UsedBytes uint64 `json:"used_bytes"`
	IsActive  bool   `json:"is_active"`
}

type BandwidthQuotaEnforcer struct {
	mu     sync.Mutex
	quotas map[string]*UserBandwidthQuota
}

func NewBandwidthQuotaEnforcer() *BandwidthQuotaEnforcer {
	return &BandwidthQuotaEnforcer{
		quotas: make(map[string]*UserBandwidthQuota),
	}
}

func (e *BandwidthQuotaEnforcer) RegisterUser(userID string, maxBytes uint64) {
	e.mu.Lock()
	defer e.mu.Unlock()

	e.quotas[userID] = &UserBandwidthQuota{
		UserID:    userID,
		MaxBytes:  maxBytes,
		UsedBytes: 0,
		IsActive:  true,
	}
}

func (e *BandwidthQuotaEnforcer) RecordTraffic(userID string, bytes uint64) QuotaAlertLevel {
	e.mu.Lock()
	defer e.mu.Unlock()

	quota, exists := e.quotas[userID]
	if !exists {
		return QuotaExhausted
	}

	quota.UsedBytes += bytes
	if quota.UsedBytes >= quota.MaxBytes {
		quota.IsActive = false
		return QuotaExhausted
	}
	if quota.UsedBytes >= (quota.MaxBytes*8)/10 {
		return QuotaWarning80
	}
	return QuotaNormal
}

func (e *BandwidthQuotaEnforcer) IsUserAllowed(userID string) bool {
	e.mu.Lock()
	defer e.mu.Unlock()

	quota, exists := e.quotas[userID]
	return exists && quota.IsActive
}
