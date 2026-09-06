package mobilehost

import (
	"testing"
	"time"
)

func TestAutonomousGlobalProxySupervisor(t *testing.T) {
	sup := NewAutonomousGlobalProxySupervisor(true)

	sup.RegisterSubsystem("mesh_wireguard_coordinator", "routing")
	sup.RegisterSubsystem("on_device_dpi_evader", "evasion")
	sup.RegisterSubsystem("multiprotocol_traffic_inspector", "transport")

	sup.UpdateHealth("mesh_wireguard_coordinator", true, 10, "")
	sup.UpdateHealth("on_device_dpi_evader", true, 20, "")
	sup.UpdateHealth("multiprotocol_traffic_inspector", false, 0, "port conflict")

	report := sup.GenerateReport()
	if report.TotalSubsystems != 3 || report.HealthySubsystems != 2 || report.TotalActiveConnections != 30 {
		t.Fatalf("unexpected report values: %+v", report)
	}

	// Test killswitch
	sup.SetKillswitch(true)
	reportKilled := sup.GenerateReport()
	if !reportKilled.KillswitchEngaged || reportKilled.TotalActiveConnections != 0 {
		t.Fatalf("expected killswitch engaged and 0 active connections")
	}

	// Test auto-remediation detection
	targets := sup.IdentifyRemediationTargets(time.Now(), 5*time.Second)
	if len(targets) != 1 || targets[0] != "multiprotocol_traffic_inspector" {
		t.Fatalf("expected multiprotocol_traffic_inspector in remediation targets, got %v", targets)
	}
}
