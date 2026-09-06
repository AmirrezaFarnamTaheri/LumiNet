// Package xray provides a gRPC API client for managing Xray proxy core.
// Ported from 3ax-ui-main/xray/api.go.
//
// Build requirement: github.com/xtls/xray-core must be added to go.mod.
// Add with: go get github.com/xtls/xray-core@latest
//
// All peer-logics transplanted verbatim (PL-003):
//   - getRequiredUserString / getOptionalUserString typed field helpers
//   - AddUser protocol switch: vmess, vless (Testseed/Testpre), trojan, shadowsocks,
//     shadowsocks_2022, hysteria/hysteria2
//   - RemoveUser: 5s context timeout
//   - GetTraffic: dual regex + skip "api" tag + mapToSlice generic
//   - processTraffic / processClientTraffic accumulators
//
//go:build xray
// +build xray

package xray

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"regexp"
	"time"

	"github.com/xtls/xray-core/app/proxyman/command"
	statsService "github.com/xtls/xray-core/app/stats/command"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/infra/conf"
	hysteriaAccount "github.com/xtls/xray-core/proxy/hysteria/account"
	"github.com/xtls/xray-core/proxy/shadowsocks"
	"github.com/xtls/xray-core/proxy/shadowsocks_2022"
	"github.com/xtls/xray-core/proxy/trojan"
	"github.com/xtls/xray-core/proxy/vless"
	"github.com/xtls/xray-core/proxy/vmess"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// XrayAPI is a gRPC client for managing Xray core configuration and statistics.
// Ported verbatim from 3ax-ui-main/xray/api.go with import paths remapped to xtls/xray-core.
type XrayAPI struct {
	HandlerServiceClient *command.HandlerServiceClient
	StatsServiceClient   *statsService.StatsServiceClient
	grpcClient           *grpc.ClientConn
	isConnected          bool
}

// getRequiredUserString extracts a required string field from a user map.
// Mirrors getRequiredUserString() from 3ax-ui/xray/api.go verbatim (PL-003 safe extraction).
func getRequiredUserString(user map[string]any, key string) (string, error) {
	value, ok := user[key]
	if !ok || value == nil {
		return "", fmt.Errorf("missing required user field %q", key)
	}
	strValue, ok := value.(string)
	if !ok {
		return "", fmt.Errorf("invalid type for user field %q: %T", key, value)
	}
	return strValue, nil
}

// getOptionalUserString extracts an optional string field from a user map.
// Returns ("", nil) when the key is absent or nil.
// Mirrors getOptionalUserString() from 3ax-ui/xray/api.go verbatim.
func getOptionalUserString(user map[string]any, key string) (string, error) {
	value, ok := user[key]
	if !ok || value == nil {
		return "", nil
	}
	strValue, ok := value.(string)
	if !ok {
		return "", fmt.Errorf("invalid type for user field %q: %T", key, value)
	}
	return strValue, nil
}

// Init connects to the Xray gRPC API at 127.0.0.1:{apiPort}.
// Mirrors Init() from 3ax-ui/xray/api.go verbatim.
func (x *XrayAPI) Init(apiPort int) error {
	if apiPort <= 0 || apiPort > math.MaxUint16 {
		return fmt.Errorf("invalid Xray API port: %d", apiPort)
	}
	addr := fmt.Sprintf("127.0.0.1:%d", apiPort)
	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return fmt.Errorf("failed to connect to Xray API at %s: %w", addr, err)
	}
	x.grpcClient = conn
	x.isConnected = true

	hsClient := command.NewHandlerServiceClient(conn)
	ssClient := statsService.NewStatsServiceClient(conn)
	x.HandlerServiceClient = &hsClient
	x.StatsServiceClient = &ssClient
	return nil
}

// Close closes the gRPC connection and resets the client state.
// Mirrors Close() from 3ax-ui/xray/api.go verbatim.
func (x *XrayAPI) Close() {
	if x.grpcClient != nil {
		x.grpcClient.Close()
	}
	x.HandlerServiceClient = nil
	x.StatsServiceClient = nil
	x.isConnected = false
}

// IsConnected reports whether the gRPC connection is established.
func (x *XrayAPI) IsConnected() bool { return x.isConnected }

// AddInbound adds a new inbound configuration to the running Xray core via gRPC.
// Mirrors AddInbound() from 3ax-ui/xray/api.go verbatim.
func (x *XrayAPI) AddInbound(inbound []byte) error {
	client := *x.HandlerServiceClient
	cfg := new(conf.InboundDetourConfig)
	if err := json.Unmarshal(inbound, cfg); err != nil {
		return fmt.Errorf("failed to unmarshal inbound config: %w", err)
	}
	built, err := cfg.Build()
	if err != nil {
		return fmt.Errorf("failed to build inbound config: %w", err)
	}
	_, err = client.AddInbound(context.Background(), &command.AddInboundRequest{Inbound: built})
	return err
}

// DelInbound removes an inbound from the running Xray core by tag.
// Mirrors DelInbound() from 3ax-ui/xray/api.go verbatim.
func (x *XrayAPI) DelInbound(tag string) error {
	client := *x.HandlerServiceClient
	_, err := client.RemoveInbound(context.Background(), &command.RemoveInboundRequest{Tag: tag})
	return err
}

// AddUser adds a user to an inbound in the running Xray core.
// Ported verbatim from 3ax-ui/xray/api.go AddUser() including all protocol cases.
//
// Supported protocols: vmess, vless, trojan, shadowsocks, shadowsocks_2022,
// hysteria, hysteria2.
//
// vless: optional "testseed" ([]uint32 or []float64) and "testpre" (uint32/float64) fields.
// shadowsocks: auto-selects classic vs. 2022 based on cipher type.
func (x *XrayAPI) AddUser(protocol_name string, inboundTag string, user map[string]any) error {
	userEmail, err := getRequiredUserString(user, "email")
	if err != nil {
		return err
	}

	var account *serial.TypedMessage
	switch protocol_name {
	case "vmess":
		userID, err := getRequiredUserString(user, "id")
		if err != nil {
			return err
		}
		account = serial.ToTypedMessage(&vmess.Account{Id: userID})

	case "vless":
		userID, err := getRequiredUserString(user, "id")
		if err != nil {
			return err
		}
		userFlow, err := getOptionalUserString(user, "flow")
		if err != nil {
			return err
		}
		vlessAccount := &vless.Account{Id: userID, Flow: userFlow}

		// testseed: []any (JSON float64) or []uint32 — mirrors 3ax-ui verbatim.
		if testseedVal, ok := user["testseed"]; ok {
			if tsArr, ok := testseedVal.([]any); ok && len(tsArr) >= 4 {
				ts := make([]uint32, len(tsArr))
				for i, v := range tsArr {
					if num, ok := v.(float64); ok {
						ts[i] = uint32(num)
					}
				}
				vlessAccount.Testseed = ts
			} else if tsArr, ok := testseedVal.([]uint32); ok && len(tsArr) >= 4 {
				vlessAccount.Testseed = tsArr
			}
		}
		// testpre: float64 (JSON) or uint32 — mirrors 3ax-ui verbatim.
		if testpreVal, ok := user["testpre"]; ok {
			if v, ok := testpreVal.(float64); ok && v > 0 {
				vlessAccount.Testpre = uint32(v)
			} else if v, ok := testpreVal.(uint32); ok && v > 0 {
				vlessAccount.Testpre = v
			}
		}
		account = serial.ToTypedMessage(vlessAccount)

	case "trojan":
		password, err := getRequiredUserString(user, "password")
		if err != nil {
			return err
		}
		account = serial.ToTypedMessage(&trojan.Account{Password: password})

	case "shadowsocks":
		// Cipher-based dispatch: known poly1305 ciphers → classic; anything else → ss2022.
		// Mirrors the 3ax-ui cipher switch verbatim.
		cipher, err := getOptionalUserString(user, "cipher")
		if err != nil {
			return err
		}
		password, err := getRequiredUserString(user, "password")
		if err != nil {
			return err
		}
		var cipherType shadowsocks.CipherType
		switch cipher {
		case "chacha20-poly1305", "chacha20-ietf-poly1305":
			cipherType = shadowsocks.CipherType_CHACHA20_POLY1305
		case "xchacha20-poly1305", "xchacha20-ietf-poly1305":
			cipherType = shadowsocks.CipherType_XCHACHA20_POLY1305
		default:
			cipherType = shadowsocks.CipherType_NONE
		}
		if cipherType != shadowsocks.CipherType_NONE {
			account = serial.ToTypedMessage(&shadowsocks.Account{
				Password:   password,
				CipherType: cipherType,
			})
		} else {
			account = serial.ToTypedMessage(&shadowsocks_2022.ServerConfig{
				Key:   password,
				Email: userEmail,
			})
		}

	case "hysteria", "hysteria2":
		auth, err := getRequiredUserString(user, "auth")
		if err != nil {
			return err
		}
		account = serial.ToTypedMessage(&hysteriaAccount.Account{Auth: auth})

	default:
		// Unknown protocol — no-op, mirrors 3ax-ui behaviour.
		return nil
	}

	client := *x.HandlerServiceClient
	_, err = client.AlterInbound(context.Background(), &command.AlterInboundRequest{
		Tag: inboundTag,
		Operation: serial.ToTypedMessage(&command.AddUserOperation{
			User: &protocol.User{
				Email:   userEmail,
				Account: account,
			},
		}),
	})
	return err
}

// RemoveUser removes a user from an inbound by email with a 5-second timeout.
// Mirrors RemoveUser() from 3ax-ui/xray/api.go verbatim.
func (x *XrayAPI) RemoveUser(inboundTag, email string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	op := &command.RemoveUserOperation{Email: email}
	req := &command.AlterInboundRequest{
		Tag:       inboundTag,
		Operation: serial.ToTypedMessage(op),
	}
	_, err := (*x.HandlerServiceClient).AlterInbound(ctx, req)
	if err != nil {
		return fmt.Errorf("failed to remove user %q from %q: %w", email, inboundTag, err)
	}
	return nil
}

// GetTraffic queries Xray traffic statistics via gRPC QueryStats.
// Mirrors GetTraffic() from 3ax-ui/xray/api.go verbatim (PL-003).
//
// Returns:
//   - []*Traffic: per-inbound/outbound-tag traffic (skips tag "api")
//   - []*ClientTraffic: per-user-email traffic
func (x *XrayAPI) GetTraffic(reset bool) ([]*Traffic, []*ClientTraffic, error) {
	if x.grpcClient == nil {
		return nil, nil, fmt.Errorf("xray API is not initialised")
	}
	if x.StatsServiceClient == nil {
		return nil, nil, fmt.Errorf("xray StatsServiceClient is not initialised")
	}

	// Regex patterns ported verbatim from 3ax-ui/xray/api.go (PL-003).
	trafficRegex := regexp.MustCompile(`(inbound|outbound)>>>([^>]+)>>>traffic>>>(downlink|uplink)`)
	clientTrafficRegex := regexp.MustCompile(`user>>>([^>]+)>>>traffic>>>(downlink|uplink)`)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	resp, err := (*x.StatsServiceClient).QueryStats(ctx, &statsService.QueryStatsRequest{Reset_: reset})
	if err != nil {
		return nil, nil, fmt.Errorf("QueryStats failed: %w", err)
	}

	tagTrafficMap := make(map[string]*Traffic)
	emailTrafficMap := make(map[string]*ClientTraffic)

	for _, stat := range resp.GetStat() {
		if matches := trafficRegex.FindStringSubmatch(stat.Name); len(matches) == 4 {
			processTraffic(matches, stat.Value, tagTrafficMap)
		} else if matches := clientTrafficRegex.FindStringSubmatch(stat.Name); len(matches) == 3 {
			processClientTraffic(matches, stat.Value, emailTrafficMap)
		}
	}
	return mapToSlice(tagTrafficMap), mapToSlice(emailTrafficMap), nil
}

// processTraffic aggregates a tag stat entry into trafficMap.
// Mirrors processTraffic() from 3ax-ui/xray/api.go verbatim; skips tag == "api".
func processTraffic(matches []string, value int64, trafficMap map[string]*Traffic) {
	isInbound := matches[1] == "inbound"
	tag := matches[2]
	isDown := matches[3] == "downlink"

	if tag == "api" {
		return // skip internal management tag
	}

	t, ok := trafficMap[tag]
	if !ok {
		t = &Traffic{IsInbound: isInbound, IsOutbound: !isInbound, Tag: tag}
		trafficMap[tag] = t
	}
	if isDown {
		t.Down = value
	} else {
		t.Up = value
	}
}

// processClientTraffic aggregates a user-email stat entry into clientTrafficMap.
// Mirrors processClientTraffic() from 3ax-ui/xray/api.go verbatim.
func processClientTraffic(matches []string, value int64, clientTrafficMap map[string]*ClientTraffic) {
	email := matches[1]
	isDown := matches[2] == "downlink"

	t, ok := clientTrafficMap[email]
	if !ok {
		t = &ClientTraffic{Email: email}
		clientTrafficMap[email] = t
	}
	if isDown {
		t.Down = value
	} else {
		t.Up = value
	}
}

// mapToSlice converts a map of pointer values to a slice.
// Mirrors mapToSlice[T]() from 3ax-ui/xray/api.go verbatim (Go 1.18+ generics).
func mapToSlice[T any](m map[string]*T) []*T {
	result := make([]*T, 0, len(m))
	for _, v := range m {
		result = append(result, v)
	}
	return result
}
