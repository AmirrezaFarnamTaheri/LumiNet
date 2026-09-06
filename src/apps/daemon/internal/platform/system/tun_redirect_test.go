package system

import (
	"context"
	"testing"
)

func TestWindowsTUNRedirect(t *testing.T) {
	ctx := context.Background()
	_ = ConfigureWindowsTUNRedirect(ctx, "tun0", "192.168.1.1", "8.8.8.8", "1.1.1.1")
	_ = ClearWindowsTUNRedirect(ctx, "tun0", "8.8.8.8")
}
