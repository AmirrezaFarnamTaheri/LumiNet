package diagnostics

import (
	"net/netip"
	"strings"
	"testing"
)

func TestSplitIperfAddress(t *testing.T) {
	t.Parallel()
	cases := []struct {
		input string
		host  string
		port  int
	}{
		{"example.com", "example.com", 5201},
		{"example.com:5300", "example.com", 5300},
		{"[2606:4700::1111]:5202", "2606:4700::1111", 5202},
		{"2606:4700::1111", "2606:4700::1111", 5201},
	}
	for _, tc := range cases {
		host, port, err := splitIperfAddress(tc.input)
		if err != nil || host != tc.host || port != tc.port {
			t.Fatalf("splitIperfAddress(%q)=(%q,%d,%v), want (%q,%d,nil)", tc.input, host, port, err, tc.host, tc.port)
		}
	}
}

func TestParseIperf3TCPJSON(t *testing.T) {
	t.Parallel()
	raw := `{
		"start":{"version":"iperf 3.18"},
		"end":{
			"sum_sent":{"seconds":5.0,"bytes":62500000,"bits_per_second":100000000,"retransmits":7},
			"sum_received":{"seconds":5.0,"bytes":61875000,"bits_per_second":99000000},
			"cpu_utilization_percent":{"host_total":12.5,"remote_total":8.25}
		}}
	`
	got, err := parseIperf3JSON([]byte(raw), "tcp", false, false)
	if err != nil {
		t.Fatal(err)
	}
	if got.BytesTransferred != 61875000 || got.BandwidthMbps != 99 || len(got.Directions) != 1 || got.Directions[0].Retransmits != 7 {
		t.Fatalf("unexpected result: %+v", got)
	}
	if got.IperfVersion != "iperf 3.18" || got.CPUHostPercent != 12.5 || got.CPURemotePercent != 8.25 {
		t.Fatalf("metadata mismatch: %+v", got)
	}
}

func TestParseIperf3UDPJSONPreservesLossAndJitter(t *testing.T) {
	t.Parallel()
	raw := `{"start":{"version":"iperf 3.18"},"end":{"sum":{"seconds":4,"bytes":5000000,"bits_per_second":10000000,"jitter_ms":1.25,"lost_packets":3,"packets":5000,"lost_percent":0.06}}}`
	got, err := parseIperf3JSON([]byte(raw), "udp", false, false)
	if err != nil {
		t.Fatal(err)
	}
	d := got.Directions[0]
	if d.JitterMs != 1.25 || d.LostPackets != 3 || d.Packets != 5000 || d.LostPercent != 0.06 || d.BandwidthMbps != 10 {
		t.Fatalf("unexpected UDP result: %+v", d)
	}
}

func TestParseIperf3BidirectionalJSON(t *testing.T) {
	t.Parallel()
	raw := `{"start":{"version":"iperf 3.18"},"end":{"sum_sent":{"seconds":3,"bytes":3000,"bits_per_second":8000,"retransmits":1},"sum_received":{"seconds":3,"bytes":2900,"bits_per_second":7733.3},"sum_sent_bidir_reverse":{"seconds":3,"bytes":6000,"bits_per_second":16000,"retransmits":2},"sum_received_bidir_reverse":{"seconds":3,"bytes":5900,"bits_per_second":15733.3}}}`
	got, err := parseIperf3JSON([]byte(raw), "tcp", false, true)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Directions) != 2 || got.Directions[0].Direction != "forward" || got.Directions[1].Direction != "reverse" || got.Directions[1].Retransmits != 2 {
		t.Fatalf("unexpected bidirectional result: %+v", got.Directions)
	}
}

func TestLimitedBufferBoundsOutput(t *testing.T) {
	t.Parallel()
	b := limitedBuffer{limit: 4}
	if n, err := b.Write([]byte("abcdef")); err != nil || n != 6 {
		t.Fatalf("write=(%d,%v)", n, err)
	}
	if b.String() != "abcd" || !b.overflow {
		t.Fatalf("buffer=%q overflow=%v", b.String(), b.overflow)
	}
}

func TestParseIperf3Error(t *testing.T) {
	t.Parallel()
	_, err := parseIperf3JSON([]byte(`{"error":"server is busy"}`), "tcp", false, false)
	if err == nil || !strings.Contains(err.Error(), "server is busy") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestSelectPublicIperfAddressPinsValidatedNumericTarget(t *testing.T) {
	t.Parallel()
	addresses := []netip.Addr{
		netip.MustParseAddr("2606:4700:4700::1111"),
		netip.MustParseAddr("1.1.1.1"),
	}
	got, err := selectPublicIperfAddress("iperf.example", addresses)
	if err != nil {
		t.Fatal(err)
	}
	if got != "2606:4700:4700::1111" {
		t.Fatalf("pinned target=%q", got)
	}
}

func TestSelectPublicIperfAddressRejectsMixedPublicPrivateAnswers(t *testing.T) {
	t.Parallel()
	_, err := selectPublicIperfAddress("rebinding.example", []netip.Addr{
		netip.MustParseAddr("1.1.1.1"),
		netip.MustParseAddr("127.0.0.1"),
	})
	if err == nil || !strings.Contains(err.Error(), "non-public DNS answer refused") {
		t.Fatalf("unexpected error: %v", err)
	}
}
