package nat

import (
	"net"
	"net/netip"
	"testing"
)

func TestTranslatedConnAddressesAndUnwrap(t *testing.T) {
	raw, peer := net.Pipe()
	defer raw.Close()
	defer peer.Close()

	from := netip.MustParseAddrPort("192.0.2.10:54321")
	to := netip.MustParseAddrPort("198.51.100.20:443")
	conn := &TranslatedConn{
		Conn: raw,
		tuple: tuple{
			from: from,
			to:   to,
		},
	}

	if got := conn.LocalAddr().String(); got != from.String() {
		t.Fatalf("LocalAddr() = %q, want %q", got, from)
	}
	if got := conn.RemoteAddr().String(); got != to.String() {
		t.Fatalf("RemoteAddr() = %q, want %q", got, to)
	}

	if got, ok := conn.RawConn(); !ok || got != raw {
		t.Fatalf("RawConn() = (%v, %v), want underlying connection", got, ok)
	}
	if got, ok := conn.Unwrap(); !ok || got != raw {
		t.Fatalf("Unwrap() = (%v, %v), want underlying connection", got, ok)
	}
}
