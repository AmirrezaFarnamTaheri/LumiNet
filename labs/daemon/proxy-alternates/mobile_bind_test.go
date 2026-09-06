package proxy

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestMobileBindQueryStats(t *testing.T) {
	// Reset stats first
	ResetEvasionTrafficStats()

	controller := &CoreController{}

	// Verify initial stats are 0
	up := controller.QueryStats("test", "upload")
	down := controller.QueryStats("test", "download")
	total := controller.QueryStats("test", "total")
	if up != 0 || down != 0 || total != 0 {
		t.Errorf("expected initial stats to be 0, got up=%d down=%d total=%d", up, down, total)
	}

	// Add test traffic bytes
	AddUploadBytes(500)
	AddDownloadBytes(1500)

	// Verify updated stats
	up = controller.QueryStats("test", "upload")
	down = controller.QueryStats("test", "download")
	total = controller.QueryStats("test", "total")
	if up != 500 {
		t.Errorf("expected upload stats to be 500, got %d", up)
	}
	if down != 1500 {
		t.Errorf("expected download stats to be 1500, got %d", down)
	}
	if total != 2000 {
		t.Errorf("expected total stats to be 2000, got %d", total)
	}

	// Verify json query output
	allStatsStr := controller.QueryAllOutboundTrafficStats()
	var allStats map[string]uint64
	if err := json.Unmarshal([]byte(allStatsStr), &allStats); err != nil {
		t.Fatalf("failed to parse QueryAllOutboundTrafficStats response JSON: %v", err)
	}
	if allStats["upload"] != 500 || allStats["download"] != 1500 || allStats["total"] != 2000 {
		t.Errorf("unexpected JSON stats: %+v", allStats)
	}
}

type testMobileProgressListener struct {
	t        *testing.T
	progress int
	msg      string
}

func (l *testMobileProgressListener) OnProgress(progress int, msg string) {
	l.progress = progress
	l.msg = msg
}

func TestMobileBindPlatform(t *testing.T) {
	listener := &testMobileProgressListener{t: t}
	SetMobileProgressListener(listener)

	LogMobile("Checking initialization")
	if listener.msg == "" || !strings.Contains(listener.msg, "Checking initialization") {
		t.Errorf("expected MobileProgressListener to receive log, got: %q", listener.msg)
	}

	SetMobileAsnName()
	if activeMobileAsnName != "EgressProvider" {
		t.Errorf("expected activeMobileAsnName to be EgressProvider, got %q", activeMobileAsnName)
	}

	if !SetMobileTimeZone(3.5) {
		t.Error("SetMobileTimeZone returned false")
	}
	if localMobileTimeZoneOffset != 3.5 {
		t.Errorf("expected localMobileTimeZoneOffset to be 3.5, got %f", localMobileTimeZoneOffset)
	}

	if flag := GetMobileFlag(); flag != "Global" {
		t.Errorf("expected GetMobileFlag to be Global, got %q", flag)
	}

	flowLine := GetMobileFlowLine(false)
	if flowLine == "" {
		t.Error("expected non-empty configuration flow line")
	}

	// Verify Stop runs without crashing
	if !StopMobileCore() {
		t.Error("Stop platform core loop failed")
	}
}

func TestGetLocationSpoofConfig(t *testing.T) {
	controller := &CoreController{}
	controller.lastConfig = MobileConfig{
		FakeLocationEnabled:   true,
		FakeLocationLatitude:  35.6895,
		FakeLocationLongitude: 139.6917,
		FakeLocationAltitude:  15.0,
		FakeLocationAccuracy:  3.0,
		FakeLocationSpeed:     0.5,
		FakeCellTowerSpoof:    true,
		FakeWifiSpoof:         false,
	}

	configStr := controller.GetLocationSpoofConfig()
	var config map[string]interface{}
	if err := json.Unmarshal([]byte(configStr), &config); err != nil {
		t.Fatalf("failed to unmarshal location spoof JSON: %v", err)
	}

	if config["fake_location_enabled"] != true {
		t.Errorf("expected fake_location_enabled to be true, got %v", config["fake_location_enabled"])
	}
	if config["fake_location_latitude"] != 35.6895 {
		t.Errorf("expected latitude 35.6895, got %v", config["fake_location_latitude"])
	}
	if config["fake_location_longitude"] != 139.6917 {
		t.Errorf("expected longitude 139.6917, got %v", config["fake_location_longitude"])
	}
	if config["fake_location_altitude"] != 15.0 {
		t.Errorf("expected altitude 15.0, got %v", config["fake_location_altitude"])
	}
	if config["fake_location_accuracy"] != float64(3.0) {
		t.Errorf("expected accuracy 3.0, got %v", config["fake_location_accuracy"])
	}
	if config["fake_location_speed"] != float64(0.5) {
		t.Errorf("expected speed 0.5, got %v", config["fake_location_speed"])
	}
	if config["fake_cell_tower_spoof"] != true {
		t.Errorf("expected cell tower spoof to be true, got %v", config["fake_cell_tower_spoof"])
	}
	if config["fake_wifi_spoof"] != false {
		t.Errorf("expected wifi spoof to be false, got %v", config["fake_wifi_spoof"])
	}
}
