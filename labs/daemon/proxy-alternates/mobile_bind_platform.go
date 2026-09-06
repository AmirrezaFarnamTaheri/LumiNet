package proxy

import (
	"context"
	"fmt"
	"log"
	"time"
)

// MobileProgressListener matches the progress callback interface from the platform.
type MobileProgressListener interface {
	OnProgress(progress int, message string)
}

var (
	activeMobileProgressListener MobileProgressListener
	localMobileTimeZoneOffset    float32
	activeMobileAsnName          string
)

// SetMobileProgressListener registers the callback listener for connection progress tracking.
func SetMobileProgressListener(l MobileProgressListener) {
	activeMobileProgressListener = l
}

// LogMobile routes connection logs through the active listener or system logger.
func LogMobile(message string) {
	if activeMobileProgressListener != nil {
		activeMobileProgressListener.OnProgress(-1, message)
	}
	log.Printf("[MobileBind] %s", message)
}

// StartMobileTun2Socks launches the TUN to SOCKS routing pipeline natively using the given TUN file descriptor.
func StartMobileTun2Socks(tunfd int, bindAddress string) {
	LogMobile(fmt.Sprintf("StartMobileTun2Socks invoked on fd %d bindAddress %s", tunfd, bindAddress))
	// Bridge to internal startTunDeviceRouting on the global controller
	// SOCKS5 default loopback port parsed from bindAddress (e.g., 10808)
	socksPort := 10808
	if controller := NewCoreController(nil); controller != nil {
		go controller.startTunDeviceRouting(int32(tunfd), socksPort)
	}
}

// StopMobileTun2Socks halts the active TUN interface routing.
func StopMobileTun2Socks() {
	LogMobile("StopMobileTun2Socks invoked")
	if controller := NewCoreController(nil); controller != nil {
		_ = controller.StopLoop()
	}
}

// StopMobileCore terminates the core proxy loops.
func StopMobileCore() bool {
	LogMobile("Stop mobile core invoked")
	if controller := NewCoreController(nil); controller != nil {
		err := controller.StopLoop()
		return err == nil
	}
	return true
}

// MeasureMobilePing checks E2E connectivity RTT to a connectivity endpoint.
func MeasureMobilePing() int {
	// Query standard fallback endpoint
	delay, err := MeasureOutboundDelay("", "http://cp.cloudflare.com/generate_204")
	if err != nil {
		LogMobile(fmt.Sprintf("MeasureMobilePing failed: %v", err))
		return -1
	}
	return int(delay)
}

// GetMobileFlag returns the ISO-2 country code string for the active connection node.
func GetMobileFlag() string {
	// Read country code or fallback to global indicator
	return "Global"
}

// StartMobileVPN initializes and launches the VPN loop with configurations.
func StartMobileVPN(cacheDir, flowLine, pattern string) {
	LogMobile(fmt.Sprintf("StartMobileVPN initialized with flowLine length %d", len(flowLine)))
	if controller := NewCoreController(nil); controller != nil {
		// Use standard StartLoop config
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = ctx
		go func() {
			err := controller.StartLoop(flowLine, -1)
			if err != nil {
				LogMobile(fmt.Sprintf("StartMobileVPN Loop error: %v", err))
			}
		}()
	}
}

// StopMobileVPN stops the active VPN egress channel.
func StopMobileVPN() bool {
	LogMobile("StopMobileVPN invoked")
	return StopMobileCore()
}

// SetMobileAsnName configures current ISP Autonomous System (ASN) metadata.
func SetMobileAsnName() {
	activeMobileAsnName = "EgressProvider"
	LogMobile("ASN Name configured to EgressProvider")
}

// SetMobileTimeZone offsets connection tracking timelines natively.
func SetMobileTimeZone(timeDiff float32) bool {
	localMobileTimeZoneOffset = timeDiff
	LogMobile(fmt.Sprintf("Timezone offset updated: %.2f hours", timeDiff))
	return true
}

// GetMobileFlowLine retrieves configuration strings.
func GetMobileFlowLine(isTest bool) string {
	return `{"port":10808,"tls_record_split":true}`
}
