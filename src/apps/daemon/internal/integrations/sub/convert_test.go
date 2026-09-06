package sub

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/maybeknott/luminet/internal/networking/proxyconfig"
)

func sampleVMess(name string) *proxyconfig.ProxyConfig {
	return &proxyconfig.ProxyConfig{
		Protocol: proxyconfig.ProtocolVMess, Name: name, Address: "203.0.113.10", Port: 443,
		UUID: "11111111-1111-1111-1111-111111111111", Security: "auto", TLS: true,
		SNI: "edge.example", Transport: "ws", Path: "/ws", Host: "cdn.example",
	}
}

func TestConvertURIAndBase64PreserveNodeCountAndUniqueNames(t *testing.T) {
	configs := []*proxyconfig.ProxyConfig{sampleVMess("edge"), sampleVMess("edge")}
	plain, err := ConvertConfigs(configs, ConversionURIList, true)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Fields(plain.Content)
	if plain.Report.EmittedNodes != 2 || plain.Report.Unsupported != 0 || len(lines) != 2 {
		t.Fatalf("plain=%+v content=%q", plain.Report, plain.Content)
	}
	first, err := proxyconfig.ParseProxyURI(lines[0])
	if err != nil {
		t.Fatal(err)
	}
	second, err := proxyconfig.ParseProxyURI(lines[1])
	if err != nil {
		t.Fatal(err)
	}
	if first.Name != "edge" || second.Name != "edge (2)" {
		t.Fatalf("names=%q,%q", first.Name, second.Name)
	}
	encoded, err := ConvertConfigs(configs, ConversionBase64, true)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := base64.StdEncoding.DecodeString(encoded.Content)
	if err != nil {
		t.Fatal(err)
	}
	if string(decoded) != plain.Content {
		t.Fatalf("decoded=%q plain=%q", decoded, plain.Content)
	}
}

func TestConvertClashReportsUnsupportedInsteadOfDroppingSilently(t *testing.T) {
	good := sampleVMess("good")
	bad := sampleVMess("xhttp")
	bad.Transport = "xhttp"
	bad.XHTTPMode = "packet-up"
	result, err := ConvertConfigs([]*proxyconfig.ProxyConfig{good, bad}, ConversionClashMeta, false)
	if err != nil {
		t.Fatal(err)
	}
	if result.Report.EmittedNodes != 1 || result.Report.Unsupported == 0 || !strings.Contains(result.Content, `"name":"good"`) || strings.Contains(result.Content, `"name":"xhttp"`) {
		t.Fatalf("report=%+v content=%s", result.Report, result.Content)
	}
	strict, err := ConvertConfigs([]*proxyconfig.ProxyConfig{good, bad}, ConversionClashMeta, true)
	if !errors.Is(err, ErrStrictConversion) || strict.Report.Unsupported == 0 {
		t.Fatalf("strict report=%+v err=%v", strict.Report, err)
	}
}

func TestConvertSingBoxPreservesAdvancedWireGuardAndTransport(t *testing.T) {
	vmess := sampleVMess("vmess")
	awg := &proxyconfig.ProxyConfig{
		Protocol: proxyconfig.ProtocolAmneziaWG, Name: "awg", Address: "198.51.100.7", Port: 51820,
		PrivateKey: "private", PublicKey: "public", LocalAddress: []string{"10.0.0.2/32"},
		Jc: 4, Jmin: 40, Jmax: 80, S1: 15, H1: "12345", I1: "abc",
	}
	result, err := ConvertConfigs([]*proxyconfig.ProxyConfig{vmess, awg}, ConversionSingBox, true)
	if err != nil {
		t.Fatal(err)
	}
	var config map[string]any
	if err := json.Unmarshal([]byte(result.Content), &config); err != nil {
		t.Fatal(err)
	}
	outbounds, ok := config["outbounds"].([]any)
	if !ok || len(outbounds) != 4 {
		t.Fatalf("outbounds=%#v", config["outbounds"])
	}
	vm := outbounds[0].(map[string]any)
	if vm["type"] != "vmess" || vm["transport"].(map[string]any)["type"] != "ws" || vm["tls"].(map[string]any)["server_name"] != "edge.example" {
		t.Fatalf("vmess=%#v", vm)
	}
	wg := outbounds[1].(map[string]any)
	if wg["type"] != "wireguard" || wg["awg_jc"] != float64(4) || wg["awg_i1"] != "abc" {
		t.Fatalf("wireguard=%#v", wg)
	}
}

func TestConvertLumiNetJSONIsVersionedCanonicalBundle(t *testing.T) {
	result, err := ConvertConfigs([]*proxyconfig.ProxyConfig{sampleVMess("native")}, ConversionLumiNetJSON, true)
	if err != nil {
		t.Fatal(err)
	}
	if result.Report.EmittedNodes != 1 || !strings.Contains(result.Content, `"schema": "luminet.proxy-bundle.v1"`) || !strings.Contains(result.Content, `"protocol": "vmess"`) {
		t.Fatalf("result=%+v content=%s", result.Report, result.Content)
	}
}

func TestConvertRejectsUnboundedNodeSetAndInvalidTarget(t *testing.T) {
	tooMany := make([]*proxyconfig.ProxyConfig, maxConversionNodes+1)
	if _, err := ConvertConfigs(tooMany, ConversionURIList, false); err == nil {
		t.Fatal("accepted unbounded conversion input")
	}
	if _, err := ConvertConfigs([]*proxyconfig.ProxyConfig{sampleVMess("x")}, ConversionTarget("mystery"), false); err == nil {
		t.Fatal("accepted unknown conversion target")
	}
}

func TestConvertSingBoxPreservesTopLevelDetourGraph(t *testing.T) {
	exit := sampleVMess("exit")
	front := sampleVMess("front")
	front.Detour = exit
	front.DialerProxy = "exit"
	result, err := ConvertConfigs([]*proxyconfig.ProxyConfig{front, exit}, ConversionSingBox, true)
	if err != nil {
		t.Fatal(err)
	}
	if result.Report.Unsupported != 0 || result.Report.EmittedNodes != 2 {
		t.Fatalf("report=%+v", result.Report)
	}
	var config map[string]any
	if err := json.Unmarshal([]byte(result.Content), &config); err != nil {
		t.Fatal(err)
	}
	outbounds := config["outbounds"].([]any)
	first := outbounds[0].(map[string]any)
	if first["tag"] != "front" || first["dialer_proxy"] != "exit" {
		t.Fatalf("front=%#v", first)
	}
}

func TestConvertSingBoxRejectsCyclicAndAmbiguousDetours(t *testing.T) {
	a := sampleVMess("a")
	b := sampleVMess("b")
	a.Detour, a.DialerProxy = b, "b"
	b.Detour, b.DialerProxy = a, "a"
	result, err := ConvertConfigs([]*proxyconfig.ProxyConfig{a, b}, ConversionSingBox, true)
	if !errors.Is(err, ErrStrictConversion) || result.Report.Unsupported < 2 {
		t.Fatalf("cycle report=%+v err=%v", result.Report, err)
	}

	dup1 := sampleVMess("dup")
	dup2 := sampleVMess("dup")
	front := sampleVMess("front")
	front.DialerProxy = "dup"
	result, err = ConvertConfigs([]*proxyconfig.ProxyConfig{front, dup1, dup2}, ConversionSingBox, true)
	if !errors.Is(err, ErrStrictConversion) || result.Report.Unsupported == 0 {
		t.Fatalf("ambiguous report=%+v err=%v", result.Report, err)
	}
	found := false
	for _, issue := range result.Report.Issues {
		if issue.Code == "ambiguous_detour" && issue.Index == 1 {
			found = true
		}
	}
	if !found {
		t.Fatalf("missing ambiguous_detour issue: %+v", result.Report.Issues)
	}
}
