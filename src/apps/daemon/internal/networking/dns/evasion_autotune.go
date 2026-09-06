package dns

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

type AutoTunePresetStability string

const (
	StabilityStable     AutoTunePresetStability = "Stable"
	StabilityAggressive AutoTunePresetStability = "Aggressive"
)

type AutoTunePreset struct {
	ID                  string                  `json:"id"`
	Label               string                  `json:"label"`
	MinUploadMtu        uint16                  `json:"min_upload_mtu"`
	MaxUploadMtu        uint16                  `json:"max_upload_mtu"`
	MinDownloadMtu      uint16                  `json:"min_download_mtu"`
	MaxDownloadMtu      uint16                  `json:"max_download_mtu"`
	ResolverTimeoutMs   uint32                  `json:"resolver_timeout_ms"`
	DnsFragCapacity     uint32                  `json:"dns_frag_capacity"`
	UploadDuplication   uint8                   `json:"upload_duplication"`
	DownloadDuplication uint8                   `json:"download_duplication"`
	UploadCompression   uint8                   `json:"upload_compression"`
	DownloadCompression uint8                   `json:"download_compression"`
	Stability           AutoTunePresetStability `json:"stability"`
}

var AutoTunePresets = []AutoTunePreset{
	{
		ID:                  "iran-average",
		Label:               "Iran Default",
		MinUploadMtu:        40,
		MaxUploadMtu:        140,
		MinDownloadMtu:      300,
		MaxDownloadMtu:      3000,
		ResolverTimeoutMs:   2500,
		DnsFragCapacity:     256,
		UploadDuplication:   3,
		DownloadDuplication: 7,
		UploadCompression:   2,
		DownloadCompression: 2,
		Stability:           StabilityStable,
	},
	{
		ID:                  "iran-low-mtu-scan",
		Label:               "Iran Low MTU Scan",
		MinUploadMtu:        20,
		MaxUploadMtu:        120,
		MinDownloadMtu:      160,
		MaxDownloadMtu:      768,
		ResolverTimeoutMs:   2500,
		DnsFragCapacity:     256,
		UploadDuplication:   3,
		DownloadDuplication: 7,
		UploadCompression:   2,
		DownloadCompression: 2,
		Stability:           StabilityStable,
	},
	{
		ID:                  "iran-fast-low-mtu",
		Label:               "Iran Fast Low MTU",
		MinUploadMtu:        20,
		MaxUploadMtu:        325,
		MinDownloadMtu:      100,
		MaxDownloadMtu:      1270,
		ResolverTimeoutMs:   2500,
		DnsFragCapacity:     100,
		UploadDuplication:   5,
		DownloadDuplication: 10,
		UploadCompression:   2,
		DownloadCompression: 2,
		Stability:           StabilityStable,
	},
	{
		ID:                  "iran-compact-fixed",
		Label:               "Iran Compact Fixed",
		MinUploadMtu:        62,
		MaxUploadMtu:        62,
		MinDownloadMtu:      414,
		MaxDownloadMtu:      414,
		ResolverTimeoutMs:   2500,
		DnsFragCapacity:     384,
		UploadDuplication:   6,
		DownloadDuplication: 8,
		UploadCompression:   2,
		DownloadCompression: 2,
		Stability:           StabilityStable,
	},
	{
		ID:                  "iran-fixed-64-balanced",
		Label:               "Iran Fixed 64 Balanced",
		MinUploadMtu:        64,
		MaxUploadMtu:        64,
		MinDownloadMtu:      756,
		MaxDownloadMtu:      756,
		ResolverTimeoutMs:   2500,
		DnsFragCapacity:     256,
		UploadDuplication:   8,
		DownloadDuplication: 8,
		UploadCompression:   2,
		DownloadCompression: 2,
		Stability:           StabilityStable,
	},
	{
		ID:                  "iran-mid-reliable",
		Label:               "Iran Mid Reliable",
		MinUploadMtu:        120,
		MaxUploadMtu:        160,
		MinDownloadMtu:      652,
		MaxDownloadMtu:      1110,
		ResolverTimeoutMs:   2500,
		DnsFragCapacity:     256,
		UploadDuplication:   5,
		DownloadDuplication: 11,
		UploadCompression:   2,
		DownloadCompression: 2,
		Stability:           StabilityStable,
	},
	{
		ID:                  "iran-download-heavy",
		Label:               "Iran Download Heavy",
		MinUploadMtu:        104,
		MaxUploadMtu:        139,
		MinDownloadMtu:      394,
		MaxDownloadMtu:      1000,
		ResolverTimeoutMs:   2500,
		DnsFragCapacity:     256,
		UploadDuplication:   8,
		DownloadDuplication: 30,
		UploadCompression:   2,
		DownloadCompression: 2,
		Stability:           StabilityStable,
	},
	{
		ID:                  "iran-fixed-64-aggressive",
		Label:               "Iran Fixed 64 Wide",
		MinUploadMtu:        64,
		MaxUploadMtu:        64,
		MinDownloadMtu:      756,
		MaxDownloadMtu:      1317,
		ResolverTimeoutMs:   2500,
		DnsFragCapacity:     230,
		UploadDuplication:   14,
		DownloadDuplication: 30,
		UploadCompression:   2,
		DownloadCompression: 2,
		Stability:           StabilityAggressive,
	},
	{
		ID:                  "iran-large-download-aggressive",
		Label:               "Iran No Compression Max",
		MinUploadMtu:        100,
		MaxUploadMtu:        600,
		MinDownloadMtu:      800,
		MaxDownloadMtu:      6500,
		ResolverTimeoutMs:   2500,
		DnsFragCapacity:     640,
		UploadDuplication:   23,
		DownloadDuplication: 30,
		UploadCompression:   0,
		DownloadCompression: 0,
		Stability:           StabilityAggressive,
	},
	{
		ID:                  "iran-wide-range-aggressive",
		Label:               "Iran Wide Range Max",
		MinUploadMtu:        100,
		MaxUploadMtu:        1000,
		MinDownloadMtu:      200,
		MaxDownloadMtu:      2667,
		ResolverTimeoutMs:   2500,
		DnsFragCapacity:     256,
		UploadDuplication:   15,
		DownloadDuplication: 30,
		UploadCompression:   2,
		DownloadCompression: 2,
		Stability:           StabilityAggressive,
	},
}

func GetPresetByID(id string) *AutoTunePreset {
	for i := range AutoTunePresets {
		if AutoTunePresets[i].ID == id {
			return &AutoTunePresets[i]
		}
	}
	return nil
}

func ChunkResolversRoundRobin(resolvers []string, requestedWorkers int) [][]string {
	var clean []string
	for _, r := range resolvers {
		trimmed := strings.TrimSpace(r)
		if trimmed != "" {
			clean = append(clean, trimmed)
		}
	}
	if len(clean) == 0 {
		return nil
	}

	workerCount := requestedWorkers
	if workerCount < 1 {
		workerCount = 1
	}
	if workerCount > len(clean) {
		workerCount = len(clean)
	}

	chunks := make([][]string, workerCount)
	for i, r := range clean {
		chunks[i%workerCount] = append(chunks[i%workerCount], r)
	}
	return chunks
}

type DnsProfileRecord struct {
	Name             string `json:"name"`
	Domain           string `json:"domain"`
	EncryptionKey    string `json:"encryption_key"`
	EncryptionMethod uint8  `json:"encryption_method"`
	Engine           string `json:"engine"`
}

type profileWireRoot struct {
	Schema  string             `json:"schema"`
	Version int                `json:"version"`
	Profile profileWireProfile `json:"profile"`
}

type profileWireProfile struct {
	Name   string            `json:"name"`
	Server profileWireServer `json:"server"`
}

type profileWireServer struct {
	Domain           string `json:"domain"`
	EncryptionKey    string `json:"encryption_key"`
	EncryptionMethod uint8  `json:"encryption_method"`
}

func EncodeDnsProfileLink(record DnsProfileRecord) (string, error) {
	if strings.TrimSpace(record.Domain) == "" || strings.TrimSpace(record.EncryptionKey) == "" {
		return "", errors.New("domain and encryption key are required")
	}

	name := record.Name
	if strings.TrimSpace(name) == "" {
		name = record.Domain
	}

	wire := profileWireRoot{
		Schema:  "whitedns.profile",
		Version: 1,
		Profile: profileWireProfile{
			Name: name,
			Server: profileWireServer{
				Domain:           strings.TrimSuffix(strings.TrimSpace(record.Domain), "."),
				EncryptionKey:    strings.TrimSpace(record.EncryptionKey),
				EncryptionMethod: record.EncryptionMethod,
			},
		},
	}

	jsonBytes, err := json.Marshal(wire)
	if err != nil {
		return "", err
	}

	b64 := base64.RawURLEncoding.EncodeToString(jsonBytes)
	engine := strings.ToLower(strings.TrimSpace(record.Engine))
	if engine == "" {
		engine = "stormdns"
	}
	return fmt.Sprintf("%s://%s", engine, b64), nil
}

func DecodeDnsProfileLink(link string) (DnsProfileRecord, error) {
	parts := strings.Split(link, "://")
	if len(parts) != 2 {
		return DnsProfileRecord{}, errors.New("invalid profile URI format")
	}
	engine := strings.ToLower(parts[0])
	payload := parts[1]
	if idx := strings.IndexAny(payload, "#?"); idx != -1 {
		payload = payload[:idx]
	}
	payload = strings.TrimSpace(payload)
	if payload == "" {
		return DnsProfileRecord{}, errors.New("empty profile payload")
	}

	decodedBytes, err := base64.RawURLEncoding.DecodeString(payload)
	if err != nil {
		decodedBytes, err = base64.StdEncoding.DecodeString(payload)
		if err != nil {
			return DnsProfileRecord{}, fmt.Errorf("invalid base64 payload: %w", err)
		}
	}

	var wire profileWireRoot
	if err := json.Unmarshal(decodedBytes, &wire); err != nil {
		return DnsProfileRecord{}, fmt.Errorf("invalid profile JSON structure: %w", err)
	}

	if wire.Schema != "whitedns.profile" {
		return DnsProfileRecord{}, fmt.Errorf("unsupported profile schema: %s", wire.Schema)
	}

	return DnsProfileRecord{
		Name:             wire.Profile.Name,
		Domain:           wire.Profile.Server.Domain,
		EncryptionKey:    wire.Profile.Server.EncryptionKey,
		EncryptionMethod: wire.Profile.Server.EncryptionMethod,
		Engine:           engine,
	}, nil
}
