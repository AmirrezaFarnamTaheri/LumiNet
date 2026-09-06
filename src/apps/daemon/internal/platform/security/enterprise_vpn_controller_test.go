package security

import (
	"testing"
)

func TestEnterpriseVpnController(t *testing.T) {
	ctrl := NewEnterpriseVpnController()

	org := TenantOrganization{
		OrgID:             "org-cyber",
		Name:              "CyberCorp",
		VirtualSubnet:     "10.200.0.0/16",
		MaxUsers:          10,
		EnableSplitTunnel: true,
	}
	ctrl.RegisterOrganization(org)

	userAlice := EnterpriseUser{
		Username:          "alice",
		OrgID:             "org-cyber",
		Role:              VpnRoleStandardUser,
		AuthToken:         "token-alice",
		AssignedVirtualIP: "10.200.1.5",
		AllowedRoutes:     []string{"10.200.10.0/24"},
	}
	if err := ctrl.RegisterUser(userAlice); err != nil {
		t.Fatalf("failed to register user: %v", err)
	}

	userBob := EnterpriseUser{
		Username:          "bob",
		OrgID:             "org-cyber",
		Role:              VpnRoleAdmin,
		AuthToken:         "token-bob",
		AssignedVirtualIP: "10.200.1.1",
		AllowedRoutes:     []string{},
	}
	if err := ctrl.RegisterUser(userBob); err != nil {
		t.Fatalf("failed to register admin: %v", err)
	}

	// Test auth
	if u, ok := ctrl.AuthenticateToken("token-alice"); !ok || u.Username != "alice" {
		t.Fatalf("auth token alice failed")
	}
	if _, ok := ctrl.AuthenticateToken("bad-token"); ok {
		t.Fatalf("expected bad token to fail")
	}

	// Test route access
	if !ctrl.CanAccessRoute("token-alice", "10.200.10.55") {
		t.Fatalf("expected alice to access route 10.200.10.55")
	}
	if ctrl.CanAccessRoute("token-alice", "10.200.99.1") {
		t.Fatalf("expected alice to NOT access route 10.200.99.1")
	}

	// Admin access to any route
	if !ctrl.CanAccessRoute("token-bob", "10.200.99.1") {
		t.Fatalf("expected admin to access any route")
	}

	// Revoke
	if !ctrl.RevokeUser("token-alice") {
		t.Fatalf("expected revoke to succeed")
	}
	if _, ok := ctrl.AuthenticateToken("token-alice"); ok {
		t.Fatalf("expected revoked alice to fail auth")
	}
	if ctrl.TotalActiveUsers() != 1 {
		t.Fatalf("expected 1 active user, got %d", ctrl.TotalActiveUsers())
	}
}
