package security

import "testing"

func TestAccessInterceptor(t *testing.T) {
	interceptor := NewAccessInterceptor()
	interceptor.ProtectRoute("/api/admin", RoleAdmin)

	ok, _ := interceptor.Authorize("user_guest", RoleGuest, "/api/admin/system")
	if ok {
		t.Errorf("guest should not be allowed into /api/admin")
	}

	ok, _ = interceptor.Authorize("user_admin", RoleAdmin, "/api/admin/system")
	if !ok {
		t.Errorf("admin should be allowed into /api/admin")
	}

	if interceptor.AuditCount() != 2 {
		t.Errorf("expected 2 audit records")
	}
}
