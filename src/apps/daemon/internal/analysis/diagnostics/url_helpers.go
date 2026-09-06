package diagnostics

import (
	"net"
	"strings"
)

func containsPort(addr string) bool {
	_, _, err := net.SplitHostPort(addr)
	return err == nil
}

func ensureScheme(value string) string {
	lower := strings.ToLower(value)
	if strings.HasPrefix(lower, "http://") || strings.HasPrefix(lower, "https://") {
		return value
	}
	return "http://" + value
}
