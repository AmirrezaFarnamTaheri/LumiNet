package proxy

import (
	"context"
	"fmt"
	"net"
	"strings"

	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/maybeknott/luminet/internal/log"
	ens "github.com/wealdtech/go-ens/v3"
)

// List of free public keyless Ethereum RPC endpoints to query
var publicEthereumRPCs = []string{
	"https://ethereum-rpc.publicnode.com",
	"https://rpc.flashbots.net",
	"https://eth.drpc.org",
	"https://1rpc.io/eth",
}

// ResolveENS resolves a .eth domain name to a deterministic virtual IP and fetches its Contenthash.
func ResolveENS(host string) ([]string, error) {
	if !strings.HasSuffix(host, ".eth") {
		return nil, fmt.Errorf("not an ENS domain")
	}

	var client *ethclient.Client
	var err error

	// Try each public RPC node sequentially
	for _, rpc := range publicEthereumRPCs {
		client, err = ethclient.Dial(rpc)
		if err == nil {
			break
		}
	}

	if err != nil || client == nil {
		return nil, fmt.Errorf("failed to dial any public Ethereum RPC gateway: %w", err)
	}
	defer client.Close()

	// 1. Resolve ENS name to Ethereum address
	address, err := ens.Resolve(client, host)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve ENS address: %w", err)
	}

	// 2. Fetch Contenthash if configured
	var contentHashStr string
	resolver, err := ens.NewResolver(client, host)
	if err == nil {
		hash, err := resolver.Contenthash()
		if err == nil {
			contentHashStr = fmt.Sprintf("0x%x", hash)
		}
	}

	// Log resolution event to structured logging system
	logger := log.NewLogger("info")
	logger.Info(context.Background(), fmt.Sprintf("Blockchain DNS: Resolved ENS '%s' to Address '%s' (Contenthash: '%s')", host, address.Hex(), contentHashStr))

	// 3. Generate deterministic virtual IP (Fake-IP range 198.18.0.0/15)
	// Map the last 2 bytes of the Ethereum address to create a deterministic mapping
	ip := net.IPv4(198, 18, address[18], address[19]).String()

	return []string{ip}, nil
}
