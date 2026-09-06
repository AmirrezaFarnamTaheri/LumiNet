package proxy

import "github.com/maybeknott/luminet/internal/presets"

// Compatibility aliases preserve the historical proxy preset API while the
// general preset catalog is owned by internal/presets.
type LabeledRange = presets.LabeledRange
type CDNPreset = presets.CDNPreset
type DoHPreset = presets.DoHPreset
type DNSPreset = presets.DNSPreset
type ScanPreset = presets.ScanPreset
type EvasionISPPreset = presets.EvasionISPPreset
type ServerlessRoutingPreset = presets.ServerlessRoutingPreset

func GetCDNPresets() []CDNPreset               { return presets.GetCDNPresets() }
func GetWarpPorts() []int                      { return presets.GetWarpPorts() }
func GetDoHPresets() []DoHPreset               { return presets.GetDoHPresets() }
func GetDNSPresets() []DNSPreset               { return presets.GetDNSPresets() }
func GetScanPresets() []ScanPreset             { return presets.GetScanPresets() }
func GetEvasionISPPresets() []EvasionISPPreset { return presets.GetEvasionISPPresets() }
func GetServerlessRoutingPresets() []ServerlessRoutingPreset {
	return presets.GetServerlessRoutingPresets()
}
