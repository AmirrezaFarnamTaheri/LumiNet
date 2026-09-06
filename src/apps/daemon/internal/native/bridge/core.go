//go:build cgo && !android && !ios

// Package bridge provides the CGO bridge to the Rust liblumicore shared library.
// It wraps all FFI calls with safe Go types and proper memory management.
//
// NOTE: This file requires CGO and the compiled Rust library at build time.
// Build with: CGO_ENABLED=1 go build
package bridge

/*
#include <stdlib.h>
#include "lumicore_abi.h"

// Go callback exported below; Rust calls it through CoreAsyncCallback.
extern void FfiCallbackHandler(uint64_t req_id, char* result_json);
*/
import "C"
import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"
)

var (
	callbackMap sync.Map
	nextReqId   uint64
)

//export FfiCallbackHandler
func FfiCallbackHandler(reqId C.uint64_t, resultJson *C.char) {
	payload := `{"error":"native callback returned null"}`
	if resultJson != nil {
		payload = C.GoString(resultJson)
	}
	if ch, ok := callbackMap.Load(uint64(reqId)); ok {
		select {
		case ch.(chan string) <- payload:
		default:
		}
	}
}

func dispatchAsync(endpoint string, input interface{}, timeoutMs uint32) (string, error) {
	reqId := atomic.AddUint64(&nextReqId, 1)
	ch := make(chan string, 1)
	callbackMap.Store(reqId, ch)
	defer callbackMap.Delete(reqId)

	payload, err := json.Marshal(input)
	if err != nil {
		return "", err
	}

	cEndpoint := C.CString(endpoint)
	defer C.free(unsafe.Pointer(cEndpoint))

	cInput := C.CString(string(payload))
	defer C.free(unsafe.Pointer(cInput))

	C.call_core_async_ffi(cEndpoint, cInput, C.uint64_t(reqId),
		C.CoreAsyncCallback(C.FfiCallbackHandler))

	timer := time.NewTimer(asyncWaitDuration(timeoutMs))
	defer timer.Stop()

	var res string
	select {
	case res = <-ch:
	case <-timer.C:
		return "", fmt.Errorf("native async callback timed out after %s", asyncWaitDuration(timeoutMs))
	}
	if strings.HasPrefix(res, `{"error":`) {
		var errEnv map[string]string
		if json.Unmarshal([]byte(res), &errEnv) == nil && errEnv["error"] != "" {
			return "", fmt.Errorf("Rust Core Async: %s", errEnv["error"])
		}
	}
	return res, nil
}

// NativeCoreLinked reports whether this build is backed by the linked LumiCore native implementation.
const NativeCoreLinked = true

// Helper to free a C-allocated char pointer returned from Rust
func freeCString(cStr *C.char) {
	if cStr != nil {
		C.free_string(cStr)
	}
}

// IcmpScan performs an ICMP ping sweep against the specified targets using the Rust core.
// It expands CIDR/range targets and sends concurrent probes with the given configuration.
func IcmpScan(targets []string, config ScanConfig) ([]ProbeResult, error) {
	input := map[string]interface{}{
		"targets": targets,
		"config":  config,
	}

	payload, err := json.Marshal(input)
	if err != nil {
		return nil, err
	}

	cInput := C.CString(string(payload))
	defer C.free(unsafe.Pointer(cInput))

	// Catch panics or missing CGO library during local test runs safely
	cResult := C.scan_icmp_ffi(cInput)
	if cResult == nil {
		return nil, fmt.Errorf("scan_icmp_ffi returned null")
	}
	defer freeCString(cResult)

	resJSON := C.GoString(cResult)

	var results []ProbeResult
	if err := json.Unmarshal([]byte(resJSON), &results); err != nil {
		// Handle potential FFI-level error envelope
		var errEnv map[string]string
		if json.Unmarshal([]byte(resJSON), &errEnv) == nil && errEnv["error"] != "" {
			return nil, fmt.Errorf("Rust Core: %s", errEnv["error"])
		}
		return nil, fmt.Errorf("failed to unmarshal results: %w", err)
	}

	return results, nil
}

// TcpConnect tests TCP connectivity to a specific host:port using the Rust core.
func TcpConnect(target string, port uint16, timeout uint32) (*ProbeResult, error) {
	input := map[string]interface{}{
		"target":     target,
		"port":       port,
		"timeout_ms": timeout,
	}

	resJSON, err := dispatchAsync("probe_tcp", input, timeout)
	if err != nil {
		return nil, err
	}

	var result ProbeResult
	if err := json.Unmarshal([]byte(resJSON), &result); err != nil {
		return nil, fmt.Errorf("failed to unmarshal result: %w", err)
	}

	return &result, nil
}

// PortScan performs a port scan against a single target across multiple ports.
func PortScan(target string, ports []uint16, config ScanConfig) ([]PortResult, error) {
	input := map[string]interface{}{
		"target": target,
		"ports":  ports,
		"config": config,
	}

	payload, err := json.Marshal(input)
	if err != nil {
		return nil, err
	}

	cInput := C.CString(string(payload))
	defer C.free(unsafe.Pointer(cInput))

	cResult := C.scan_ports_ffi(cInput)
	if cResult == nil {
		return nil, fmt.Errorf("scan_ports_ffi returned null")
	}
	defer freeCString(cResult)

	resJSON := C.GoString(cResult)

	var results []PortResult
	if err := json.Unmarshal([]byte(resJSON), &results); err != nil {
		var errEnv map[string]string
		if json.Unmarshal([]byte(resJSON), &errEnv) == nil && errEnv["error"] != "" {
			return nil, fmt.Errorf("Rust Core: %s", errEnv["error"])
		}
		return nil, fmt.Errorf("failed to unmarshal results: %w", err)
	}

	return results, nil
}

// DnsResolve queries a DNS server with the historical 3-second timeout.
func DnsResolve(server, domain string, recordType string) (*DnsServerResult, error) {
	return DnsResolveWithTimeout(server, domain, recordType, 3000)
}

// DnsResolveWithTimeout queries a DNS server using the caller-owned timeout.
func DnsResolveWithTimeout(server, domain string, recordType string, timeoutMs uint32) (*DnsServerResult, error) {
	if timeoutMs == 0 {
		timeoutMs = 3000
	}
	protocol := "udp"
	if len(server) >= 8 && (server[:8] == "https://" || server[:7] == "http://") {
		protocol = "doh"
	} else if len(server) > 4 && server[len(server)-4:] == ":853" {
		protocol = "dot"
	}

	input := map[string]interface{}{
		"server":      server,
		"domain":      domain,
		"record_type": recordType,
		"protocol":    protocol,
		"timeout_ms":  timeoutMs,
	}

	resJSON, err := dispatchAsync("scan_dns", input, timeoutMs)
	if err != nil {
		return nil, err
	}

	var result DnsServerResult
	if err := json.Unmarshal([]byte(resJSON), &result); err != nil {
		return nil, fmt.Errorf("failed to unmarshal result: %w", err)
	}

	return &result, nil
}

// TlsHandshake performs a TLS handshake and returns certificate/protocol details.
func TlsHandshake(host string, port uint16, timeout uint32) (*TlsInfo, error) {
	return TlsHandshakeWithSni(host, port, host, timeout)
}

// TlsHandshakeWithSni performs a TLS handshake with a custom SNI and returns certificate/protocol details.
func TlsHandshakeWithSni(host string, port uint16, sni string, timeout uint32) (*TlsInfo, error) {
	input := map[string]interface{}{
		"target":     host,
		"port":       port,
		"timeout_ms": timeout,
		"sni":        sni,
	}

	payload, err := json.Marshal(input)
	if err != nil {
		return nil, err
	}

	cInput := C.CString(string(payload))
	defer C.free(unsafe.Pointer(cInput))

	cResult := C.probe_tls_ffi(cInput)
	if cResult == nil {
		return nil, fmt.Errorf("probe_tls_ffi returned null")
	}
	defer freeCString(cResult)

	resJSON := C.GoString(cResult)

	var result TlsInfo
	if err := json.Unmarshal([]byte(resJSON), &result); err != nil {
		var errEnv map[string]string
		if json.Unmarshal([]byte(resJSON), &errEnv) == nil && errEnv["error"] != "" {
			return nil, fmt.Errorf("Rust Core: %s", errEnv["error"])
		}
		return nil, fmt.Errorf("failed to unmarshal result: %w", err)
	}

	return &result, nil
}

// SniDetect tests multiple domains for SNI-based filtering/blocking.
func SniDetect(domain string, timeout uint32) (*SniResult, error) {
	input := map[string]interface{}{
		"domain":     domain,
		"timeout_ms": timeout,
	}

	payload, err := json.Marshal(input)
	if err != nil {
		return nil, err
	}

	cInput := C.CString(string(payload))
	defer C.free(unsafe.Pointer(cInput))

	cResult := C.detect_sni_ffi(cInput)
	if cResult == nil {
		return nil, fmt.Errorf("detect_sni_ffi returned null")
	}
	defer freeCString(cResult)

	resJSON := C.GoString(cResult)

	var result SniResult
	if err := json.Unmarshal([]byte(resJSON), &result); err != nil {
		var errEnv map[string]string
		if json.Unmarshal([]byte(resJSON), &errEnv) == nil && errEnv["error"] != "" {
			return nil, fmt.Errorf("Rust Core: %s", errEnv["error"])
		}
		return nil, fmt.Errorf("failed to unmarshal result: %w", err)
	}

	return &result, nil
}

// SpeedTest measures download speed from a URL for the specified duration.
func SpeedTest(url string, timeoutMs uint32) (*SpeedResult, error) {
	input := map[string]interface{}{
		"server_url": url,
		"timeout_ms": timeoutMs,
	}

	payload, err := json.Marshal(input)
	if err != nil {
		return nil, err
	}

	cInput := C.CString(string(payload))
	defer C.free(unsafe.Pointer(cInput))

	cResult := C.test_speed_ffi(cInput)
	if cResult == nil {
		return nil, fmt.Errorf("test_speed_ffi returned null")
	}
	defer freeCString(cResult)

	resJSON := C.GoString(cResult)

	var result SpeedResult
	if err := json.Unmarshal([]byte(resJSON), &result); err != nil {
		var errEnv map[string]string
		if json.Unmarshal([]byte(resJSON), &errEnv) == nil && errEnv["error"] != "" {
			return nil, fmt.Errorf("Rust Core: %s", errEnv["error"])
		}
		return nil, fmt.Errorf("failed to unmarshal result: %w", err)
	}

	return &result, nil
}

// WgProbe sends a WireGuard handshake initiation packet to test endpoint reachability.
func WgProbe(ip string, port uint16, timeoutMs uint32, paddingLen uint32) (*ProbeResult, error) {
	input := map[string]interface{}{
		"ip":          ip,
		"port":        port,
		"timeout_ms":  timeoutMs,
		"padding_len": paddingLen,
	}

	payload, err := json.Marshal(input)
	if err != nil {
		return nil, err
	}

	cInput := C.CString(string(payload))
	defer C.free(unsafe.Pointer(cInput))

	cResult := C.probe_wg_ffi(cInput)
	if cResult == nil {
		return nil, fmt.Errorf("probe_wg_ffi returned null")
	}
	defer freeCString(cResult)

	resJSON := C.GoString(cResult)

	var result ProbeResult
	if err := json.Unmarshal([]byte(resJSON), &result); err != nil {
		var errEnv map[string]string
		if json.Unmarshal([]byte(resJSON), &errEnv) == nil && errEnv["error"] != "" {
			return nil, fmt.Errorf("Rust Core: %s", errEnv["error"])
		}
		return nil, fmt.Errorf("failed to unmarshal result: %w", err)
	}

	return &result, nil
}

// FreeString frees a Rust-allocated C string.
// Must be called for every string returned by the Rust FFI layer.
func FreeString(ptr *C.char) {
	if ptr != nil {
		C.free_string(ptr)
	}
}

// InjectFakePacket sends a custom raw TCP packet with a specific TTL using the Rust core.
func InjectFakePacket(targetIp string, port uint16, ttl uint32, flags *uint8, seq *uint32, ack *uint32, payloadHex string) error {
	input := map[string]interface{}{
		"target_ip":   targetIp,
		"port":        port,
		"ttl":         ttl,
		"flags":       flags,
		"seq":         seq,
		"ack":         ack,
		"payload_hex": payloadHex,
	}

	payload, err := json.Marshal(input)
	if err != nil {
		return err
	}

	cInput := C.CString(string(payload))
	defer C.free(unsafe.Pointer(cInput))

	cResult := C.inject_fake_packet_ffi(cInput)
	if cResult == nil {
		return fmt.Errorf("inject_fake_packet_ffi returned null")
	}
	defer freeCString(cResult)

	resJSON := C.GoString(cResult)

	var result struct {
		Success bool   `json:"success"`
		Error   string `json:"error"`
	}
	if err := json.Unmarshal([]byte(resJSON), &result); err != nil {
		var errEnv map[string]string
		if json.Unmarshal([]byte(resJSON), &errEnv) == nil && errEnv["error"] != "" {
			return fmt.Errorf("Rust Core: %s", errEnv["error"])
		}
		return fmt.Errorf("failed to unmarshal result: %w", err)
	}

	if !result.Success {
		return fmt.Errorf("Rust Core: %s", result.Error)
	}

	return nil
}

// DisassemblePayload runs Capstone disassembly via Rust core to check for exploit shellcode
func DisassemblePayload(payload []byte, arch string) (string, error) {
	input := map[string]interface{}{
		"payload_hex": hex.EncodeToString(payload),
		"arch":        arch,
	}

	payloadJSON, err := json.Marshal(input)
	if err != nil {
		return "", err
	}

	cInput := C.CString(string(payloadJSON))
	defer C.free(unsafe.Pointer(cInput))

	cResult := C.disassemble_shellcode_ffi(cInput)
	if cResult == nil {
		return "", fmt.Errorf("disassemble_shellcode_ffi returned null")
	}
	defer freeCString(cResult)

	resJSON := C.GoString(cResult)

	var result struct {
		Success     bool   `json:"success"`
		Disassembly string `json:"disassembly"`
		Error       string `json:"error"`
	}
	if err := json.Unmarshal([]byte(resJSON), &result); err != nil {
		var errEnv map[string]string
		if json.Unmarshal([]byte(resJSON), &errEnv) == nil && errEnv["error"] != "" {
			return "", fmt.Errorf("Rust Core: %s", errEnv["error"])
		}
		return "", fmt.Errorf("failed to unmarshal result: %w", err)
	}

	if !result.Success {
		return "", fmt.Errorf("Rust Core: %s", result.Error)
	}

	return result.Disassembly, nil
}
