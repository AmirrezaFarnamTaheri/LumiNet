package vpngate

import (
	"strings"
	"testing"
)

func TestParseFiltersAndRanksServers(t *testing.T) {
	body := "*vpn_servers\nHostName,IP,Score,Ping,Speed,CountryLong,CountryShort,NumVpnSessions,Uptime,TotalUsers,TotalTraffic,LogType,Operator,Message,OpenVPN_ConfigData_Base64\n" +
		"a,1.1.1.1,100,50,1000,Japan,JP,3,100,10,1000,2,op,msg,x\n" +
		"b,2.2.2.2,200,80,5000,Japan,JP,4,200,20,2000,2,op2,msg2,y\n" +
		"c,3.3.3.3,300,20,9000,Korea Republic of,KR,5,300,30,3000,2,op3,msg3,z\n*\n"
	got, err := Parse(strings.NewReader(body), Filter{Country: "JP", Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].HostName != "b" || got[1].HostName != "a" {
		t.Fatalf("unexpected ranking: %+v", got)
	}
	if got[0].SSTPServer != "b.opengw.net" || got[0].SSTPUsername != "vpn" {
		t.Fatalf("missing SSTP handoff: %+v", got[0])
	}
}

func TestParseBoundsAndFilters(t *testing.T) {
	body := "HostName,IP,Score,Ping,Speed,CountryLong,CountryShort,NumVpnSessions,Uptime,TotalUsers,TotalTraffic,Operator,Message\n" +
		"a,1.1.1.1,100,500,1000,Japan,JP,3,100,10,1000,op,msg\n"
	got, err := Parse(strings.NewReader(body), Filter{MaxPingMS: 100})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Fatalf("expected filtered result, got %+v", got)
	}
}
