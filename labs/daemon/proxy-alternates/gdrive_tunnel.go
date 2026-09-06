package proxy

import (
	"context"
	"encoding/base64"
	"fmt"
	"math/rand"
	"sync"
	"time"
)

type GDriveTunnelConfig struct {
	Enabled bool
}

// GDriveTunnelRelay routes chunks through Cloud-backed covert Relays.
type GDriveTunnelRelay struct {
	mu           sync.Mutex
	cfg          GDriveTunnelConfig
	bytesRelayed int64
}

func NewGDriveTunnelRelay(cfg GDriveTunnelConfig) *GDriveTunnelRelay {
	return &GDriveTunnelRelay{cfg: cfg}
}

func (r *GDriveTunnelRelay) EncapsulateChunk(ctx context.Context, chunk []byte) (string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if !r.cfg.Enabled {
		return "", fmt.Errorf("GDrive tunnel relay is disabled")
	}

	r.bytesRelayed += int64(len(chunk))
	encoded := base64.StdEncoding.EncodeToString(chunk)
	return encoded, nil
}

func (r *GDriveTunnelRelay) GetStats() map[string]interface{} {
	r.mu.Lock()
	defer r.mu.Unlock()
	return map[string]interface{}{
		"bytes_relayed": r.bytesRelayed,
		"enabled":       r.cfg.Enabled,
	}
}

// GenerateCovertFilename creates randomized documents to look like normal files.
func GenerateCovertFilename() string {
	formats := []string{"report", "invoice", "data", "schedule", "notes"}
	extensions := []string{"docx", "xlsx", "pdf", "txt"}

	rand.Seed(time.Now().UnixNano())
	fmtName := formats[rand.Intn(len(formats))]
	extName := extensions[rand.Intn(len(extensions))]

	return fmt.Sprintf("covert_%s_%d.%s", fmtName, time.Now().Unix(), extName)
}
