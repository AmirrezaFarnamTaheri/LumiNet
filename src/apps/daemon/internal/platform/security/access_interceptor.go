package security

import (
	"strings"
	"sync"
	"time"
)

type AccessRole int

const (
	RoleGuest AccessRole = iota
	RoleAuditor
	RoleOperator
	RoleAdmin
)

type AuditEntry struct {
	Timestamp time.Time
	UserID    string
	Path      string
	Allowed   bool
	Reason    string
}

type AccessInterceptor struct {
	mu         sync.Mutex
	routeRoles map[string]AccessRole
	auditTrail []AuditEntry
}

func NewAccessInterceptor() *AccessInterceptor {
	return &AccessInterceptor{
		routeRoles: make(map[string]AccessRole),
		auditTrail: make([]AuditEntry, 0),
	}
}

func (a *AccessInterceptor) ProtectRoute(prefix string, minRole AccessRole) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.routeRoles[prefix] = minRole
}

func (a *AccessInterceptor) Authorize(userID string, role AccessRole, path string) (bool, string) {
	a.mu.Lock()
	defer a.mu.Unlock()

	allowed := true
	reason := "authorized"

	for prefix, minRole := range a.routeRoles {
		if strings.HasPrefix(path, prefix) {
			if role < minRole {
				allowed = false
				reason = "insufficient permissions"
				break
			}
		}
	}

	a.auditTrail = append(a.auditTrail, AuditEntry{
		Timestamp: time.Now(),
		UserID:    userID,
		Path:      path,
		Allowed:   allowed,
		Reason:    reason,
	})

	return allowed, reason
}

func (a *AccessInterceptor) AuditCount() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return len(a.auditTrail)
}
