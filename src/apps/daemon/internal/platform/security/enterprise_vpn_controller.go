package security

import (
	"errors"
	"net"
	"sync"
	"time"
)

// UserRole represents an enterprise access level
type UserRole string

const (
	VpnRoleStandardUser UserRole = "STANDARD_USER"
	VpnRoleAdmin        UserRole = "ADMIN"
	VpnRoleAuditor      UserRole = "AUDITOR"
)

// TenantOrganization holds enterprise tenant configuration
type TenantOrganization struct {
	OrgID             string
	Name              string
	VirtualSubnet     string
	MaxUsers          int
	EnableSplitTunnel bool
}

// EnterpriseUser holds identity and authorization state for a user
type EnterpriseUser struct {
	Username          string
	OrgID             string
	Role              UserRole
	AuthToken         string
	AssignedVirtualIP string
	AllowedRoutes     []string
	CreatedAt         time.Time
	IsActive          bool
}

// EnterpriseVpnController orchestrates enterprise multi-tenant RBAC and routing
type EnterpriseVpnController struct {
	orgs      map[string]TenantOrganization
	users     map[string]*EnterpriseUser // keyed by AuthToken
	ipToToken map[string]string
	mu        sync.RWMutex
}

// NewEnterpriseVpnController creates a new enterprise controller
func NewEnterpriseVpnController() *EnterpriseVpnController {
	return &EnterpriseVpnController{
		orgs:      make(map[string]TenantOrganization),
		users:     make(map[string]*EnterpriseUser),
		ipToToken: make(map[string]string),
	}
}

// RegisterOrganization adds a new tenant org
func (c *EnterpriseVpnController) RegisterOrganization(org TenantOrganization) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.orgs[org.OrgID] = org
}

// RegisterUser enrolls a user under an organization
func (c *EnterpriseVpnController) RegisterUser(user EnterpriseUser) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	org, exists := c.orgs[user.OrgID]
	if !exists {
		return errors.New("organization not registered")
	}

	// Count users in this org
	count := 0
	for _, u := range c.users {
		if u.OrgID == user.OrgID && u.IsActive {
			count++
		}
	}
	if count >= org.MaxUsers {
		return errors.New("organization user limit exceeded")
	}

	user.CreatedAt = time.Now()
	user.IsActive = true

	c.users[user.AuthToken] = &user
	c.ipToToken[user.AssignedVirtualIP] = user.AuthToken
	return nil
}

// AuthenticateToken verifies the auth token and returns user details
func (c *EnterpriseVpnController) AuthenticateToken(token string) (*EnterpriseUser, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	user, exists := c.users[token]
	if !exists || !user.IsActive {
		return nil, false
	}
	return user, true
}

// CanAccessRoute verifies whether a token is permitted to reach destination IP
func (c *EnterpriseVpnController) CanAccessRoute(token string, destIP string) bool {
	c.mu.RLock()
	defer c.mu.RUnlock()

	user, exists := c.users[token]
	if !exists || !user.IsActive {
		return false
	}

	if user.Role == VpnRoleAdmin {
		return true
	}

	parsedDest := net.ParseIP(destIP)
	if parsedDest == nil {
		return false
	}

	for _, route := range user.AllowedRoutes {
		if route == "0.0.0.0/0" {
			return true
		}
		_, ipNet, err := net.ParseCIDR(route)
		if err == nil && ipNet.Contains(parsedDest) {
			return true
		}
		if route == destIP {
			return true
		}
	}

	return false
}

// RevokeUser deactivates a user session
func (c *EnterpriseVpnController) RevokeUser(token string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()

	user, exists := c.users[token]
	if !exists {
		return false
	}
	user.IsActive = false
	delete(c.ipToToken, user.AssignedVirtualIP)
	return true
}

// TotalActiveUsers returns active user count
func (c *EnterpriseVpnController) TotalActiveUsers() int {
	c.mu.RLock()
	defer c.mu.RUnlock()

	count := 0
	for _, u := range c.users {
		if u.IsActive {
			count++
		}
	}
	return count
}
