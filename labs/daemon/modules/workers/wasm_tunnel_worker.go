// Package workers handles serverless and edge-worker deployments.
// Ported from: bia-pain-bache
// Target path: server/internal/workers/bia_pain.go

package workers

import (
	"encoding/json"
	"fmt"
	"strings"
)

// BiaPainRouter represents the massive custom routing generator for bypassing regional firewalls.
type BiaPainRouter struct {
	region string
}

// NewBiaPainRouter initializes a new routing generator for a specific region.
func NewBiaPainRouter(region string) *BiaPainRouter {
	return &BiaPainRouter{region: region}
}

// ParseTrojanHeader handles dynamic Trojan payloads.
func (b *BiaPainRouter) ParseTrojanHeader(header string) (map[string]string, error) {
	// Expected format: <password_hash>\r\n<command><address_type><address><port>\r\n
	if !strings.Contains(header, "\r\n") {
		return nil, fmt.Errorf("invalid trojan header")
	}

	parts := strings.SplitN(header, "\r\n", 2)
	hash := parts[0]
	
	return map[string]string{
		"hash": hash,
		"rest": parts[1],
	}, nil
}

// BuildXrayWarpOutbound builds custom WARP outbounds dynamically.
func (b *BiaPainRouter) BuildXrayWarpOutbound(accountID, accessToken string) (string, error) {
	outbound := map[string]interface{}{
		"tag":      "warp-out",
		"protocol": "wireguard",
		"settings": map[string]interface{}{
			"secretKey": "AUTO_GENERATED_SECRET",
			"address": []string{
				"172.16.0.2/32",
				"2606:4700:110:8751::2/128",
			},
			"peers": []map[string]interface{}{
				{
					"publicKey": "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=",
					"endpoint":  "engage.cloudflareclient.com:2408",
				},
			},
			"reserved": []int{0, 0, 0},
		},
	}

	if b.region == "Iran" || b.region == "China" {
		// Apply specific obfuscation or MTU tweaks
		outbound["settings"].(map[string]interface{})["mtu"] = 1280
	}

	outBytes, err := json.MarshalIndent(outbound, "", "  ")
	if err != nil {
		return "", err
	}

	return string(outBytes), nil
}
