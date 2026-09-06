package mitm

import (
	"context"
	"net"
	"testing"
)

func TestMitmFrontingHostResolverCompatibilityAliases(t *testing.T) {
	resolver := MitmFrontingHostResolverHelper{ResolverActiveStatus: "active"}
	if resolver.ResolverActiveStatus != "active" {
		t.Fatal("helper alias did not preserve canonical fields")
	}

	var diagnostics MitmFrontingHostDiagnosticsTuningHelper
	var _ func(context.Context, string) (net.Conn, error) = diagnostics.DialDiagnostics
}
