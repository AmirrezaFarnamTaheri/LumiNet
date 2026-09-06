package security

import (
	"sync"
)

type AccountStatus string

const (
	AccountStatusReady       AccountStatus = "Ready"
	AccountStatusInUse       AccountStatus = "InUse"
	AccountStatusCoolingDown AccountStatus = "CoolingDown"
	AccountStatusLocked      AccountStatus = "Locked"
)

type ManagedAccount struct {
	AccountID         string
	Token             string
	UsesCount         uint32
	MaxUses           uint32
	Status            AccountStatus
	CooldownUntilSec  uint64
}

type SessionRotationPool struct {
	mu                 sync.RWMutex
	accounts           map[string]*ManagedAccount
	rotationOrder      []string
	cursor             int
	defaultCooldownSec uint64
}

func NewSessionRotationPool(defaultCooldownSec uint64) *SessionRotationPool {
	return &SessionRotationPool{
		accounts:           make(map[string]*ManagedAccount),
		rotationOrder:      make([]string, 0),
		cursor:             0,
		defaultCooldownSec: defaultCooldownSec,
	}
}

func (p *SessionRotationPool) AddAccount(accountID, token string, maxUses uint32) {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.accounts[accountID] = &ManagedAccount{
		AccountID:        accountID,
		Token:            token,
		UsesCount:        0,
		MaxUses:          maxUses,
		Status:           AccountStatusReady,
		CooldownUntilSec: 0,
	}
	p.rotationOrder = append(p.rotationOrder, accountID)
}

func (p *SessionRotationPool) AcquireAccount(nowSec uint64) (string, string, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()

	n := len(p.rotationOrder)
	if n == 0 {
		return "", "", false
	}

	for _, acc := range p.accounts {
		if acc.Status == AccountStatusCoolingDown && nowSec >= acc.CooldownUntilSec {
			acc.Status = AccountStatusReady
			acc.UsesCount = 0
		}
	}

	for i := 0; i < n; i++ {
		id := p.rotationOrder[p.cursor%n]
		p.cursor++

		if acc, ok := p.accounts[id]; ok {
			if acc.Status == AccountStatusReady {
				acc.UsesCount++
				if acc.UsesCount >= acc.MaxUses {
					acc.Status = AccountStatusCoolingDown
					acc.CooldownUntilSec = nowSec + p.defaultCooldownSec
				}
				return acc.AccountID, acc.Token, true
			}
		}
	}

	return "", "", false
}

func (p *SessionRotationPool) MarkLocked(accountID string) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if acc, ok := p.accounts[accountID]; ok {
		acc.Status = AccountStatusLocked
	}
}

func (p *SessionRotationPool) AvailableCount(nowSec uint64) int {
	p.mu.RLock()
	defer p.mu.RUnlock()

	count := 0
	for _, acc := range p.accounts {
		if acc.Status == AccountStatusReady || (acc.Status == AccountStatusCoolingDown && nowSec >= acc.CooldownUntilSec) {
			count++
		}
	}
	return count
}
