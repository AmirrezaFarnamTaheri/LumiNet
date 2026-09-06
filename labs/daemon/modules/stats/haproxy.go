// Package stats provides telemetry, traffic statistics, and L7 metric analysis for LumiNet.
// Ported from: haproxy (sFlow HTTP Instrumentation)
// Target path: server/internal/stats/haproxy.go
package stats

import (
	"encoding/binary"
	"fmt"
	"net"
)

// HAProxyTelemetryExporter exports real-time HTTP metrics over UDP to an sFlow receiver.
type HAProxyTelemetryExporter struct {
	targetAddress string
}

// NewHAProxyTelemetryExporter creates a new exporter.
func NewHAProxyTelemetryExporter(targetAddress string) *HAProxyTelemetryExporter {
	return &HAProxyTelemetryExporter{
		targetAddress: targetAddress,
	}
}

// ExportHTTPMetric sends L7 metric values formatted in sFlow standard struct definitions.
func (e *HAProxyTelemetryExporter) ExportHTTPMetric(method, url string, statusCode int, durationMs int64) error {
	conn, err := net.Dial("udp", e.targetAddress)
	if err != nil {
		return fmt.Errorf("failed to dial sFlow receiver: %w", err)
	}
	defer conn.Close()

	// Format sFlow transaction structure:
	// - sFlow version (4 bytes): 5
	// - IP version (4 bytes): 1 (IPv4)
	// - HTTP method (4 bytes): GET=1, POST=2, PUT=3, DELETE=4
	// - HTTP status (4 bytes)
	// - transaction duration (8 bytes)
	payload := make([]byte, 24)

	binary.BigEndian.PutUint32(payload[0:4], 5) // version 5
	binary.BigEndian.PutUint32(payload[4:8], 1) // ipv4

	var methodVal uint32 = 0
	switch method {
	case "GET":
		methodVal = 1
	case "POST":
		methodVal = 2
	case "PUT":
		methodVal = 3
	case "DELETE":
		methodVal = 4
	}
	binary.BigEndian.PutUint32(payload[8:12], methodVal)
	binary.BigEndian.PutUint32(payload[12:16], uint32(statusCode))
	binary.BigEndian.PutUint64(payload[16:24], uint64(durationMs))

	_, err = conn.Write(payload)
	return err
}
