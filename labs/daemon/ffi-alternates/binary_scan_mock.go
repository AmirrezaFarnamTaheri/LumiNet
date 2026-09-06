//go:build cgo && !android && !ios

package bridge

/*
#include "lumicore_abi.h"
*/
import "C"

import (
	"context"
	"errors"
	"net/netip"
)

const RequiredAbi = 3

type ScanResult struct {
	IP         netip.Addr
	IsAlive    bool
	ReasonCode uint16
	LatencyUs  uint64
}

func ExecScan(ctx context.Context, config ScanConfig, targets []netip.Addr) ([]ScanResult, error) {
	if len(targets) == 0 {
		return nil, nil
	}

	cTargets := make([]C.PackedTarget, len(targets))
	for i, ip := range targets {
		bytes := ip.As16()
		for j := 0; j < 16; j++ {
			cTargets[i].ip_bytes[j] = C.uint8_t(bytes[j])
		}
		if ip.Is6() {
			cTargets[i].is_ipv6 = 1
		} else {
			cTargets[i].is_ipv6 = 0
		}
	}

	cResults := make([]C.PackedResult, len(targets))

	env := C.FfiEnvelope{
		abi_version: C.uint16_t(RequiredAbi),
		op_code:     C.uint16_t(1),
		input_len:   C.size_t(len(targets)),
		output_cap:  C.size_t(len(targets)),
	}

	cfg := C.PackedScanConfig{
		timeout_ms:     C.uint32_t(config.Timeout),
		max_concurrent: C.uint32_t(config.Concurrency),
		rate_limit_pps: C.uint32_t(config.RateLimitPPS),
	}

	status := C.lumicore_scan_execution(
		&env,
		&cfg,
		&cTargets[0],
		C.size_t(len(targets)),
		&cResults[0],
	)

	if status.code != 0 {
		return nil, errors.New("FFI scan failed with code")
	}

	results := make([]ScanResult, status.output_len)
	for i := 0; i < int(status.output_len); i++ {
		var ipBytes [16]byte
		for j := 0; j < 16; j++ {
			ipBytes[j] = byte(cResults[i].ip_bytes[j])
		}

		var addr netip.Addr
		if cResults[i].is_ipv6 == 1 {
			addr = netip.AddrFrom16(ipBytes)
		} else {
			addr = netip.AddrFrom4([4]byte{ipBytes[12], ipBytes[13], ipBytes[14], ipBytes[15]})
		}

		results[i] = ScanResult{
			IP:         addr,
			IsAlive:    cResults[i].is_alive == 1,
			ReasonCode: uint16(cResults[i].reason_code),
			LatencyUs:  uint64(cResults[i].latency_us),
		}
	}
	return results, nil
}
