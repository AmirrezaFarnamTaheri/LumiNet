package jobs

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/maybeknott/luminet/internal/integrations/provision"
	"github.com/maybeknott/luminet/internal/networking/proxyconfig"
)

const redactedSecret = "[REDACTED]"
const redactedUnreadableConfig = `{"redacted":true}`

// JobIntent is the sealed execution contract accepted by JobManager.
// Only concrete intent types in this package can satisfy it, preventing callers
// from pairing an arbitrary job type with an undocumented JSON payload.
type JobIntent interface{ jobType() JobType }

type IcmpScanIntent struct {
	Targets     []string `json:"targets"`
	TimeoutMs   int      `json:"timeout_ms"`
	Concurrency int      `json:"concurrency"`
	IPv6        bool     `json:"ipv6"`
}

func (IcmpScanIntent) jobType() JobType { return JobTypeIcmpScan }

type PortScanIntent struct {
	Target      string   `json:"target"`
	Ports       []uint16 `json:"ports"`
	TimeoutMs   int      `json:"timeout_ms"`
	Concurrency int      `json:"concurrency"`
}

func (PortScanIntent) jobType() JobType { return JobTypePortScan }

type DnsScanIntent struct {
	Server     string `json:"server"`
	Domain     string `json:"domain"`
	RecordType string `json:"record_type"`
	TimeoutMs  uint32 `json:"timeout_ms"`
}

func (DnsScanIntent) jobType() JobType { return JobTypeDnsScan }

type TlsScanIntent struct {
	Target    string `json:"target"`
	Port      uint16 `json:"port"`
	TimeoutMs uint32 `json:"timeout_ms"`
	SNI       string `json:"sni"`
}

func (TlsScanIntent) jobType() JobType { return JobTypeTlsScan }

type SniScanIntent struct {
	Domain    string `json:"domain"`
	TimeoutMs uint32 `json:"timeout_ms"`
}

func (SniScanIntent) jobType() JobType { return JobTypeSniScan }

type ProxyTestIntent struct {
	Proxies   []string `json:"proxies,omitempty"`
	ProxyURI  string   `json:"proxy_uri,omitempty"`
	ProxyAddr string   `json:"proxy_addr,omitempty"`
	// ProxyPreview is history/display metadata only; execution always uses the
	// full URI/address fields above.
	ProxyPreview string   `json:"proxy_preview,omitempty"`
	URLs         []string `json:"urls,omitempty"`
	Target       string   `json:"target,omitempty"`
	Timeout      int      `json:"timeout,omitempty"`
	TimeoutMs    uint32   `json:"timeout_ms,omitempty"`
	Concurrency  int      `json:"concurrency,omitempty"`
	SpeedTest    bool     `json:"speed_test,omitempty"`
	GeoIP        bool     `json:"geoip,omitempty"`
	CoreType     string   `json:"core_type,omitempty"`
	DNSResolver  string   `json:"dns_resolver,omitempty"`
}

func (ProxyTestIntent) jobType() JobType { return JobTypeProxyTest }

type DiagnosticIntent struct {
	Type    string            `json:"type,omitempty"`
	Target  string            `json:"target,omitempty"`
	Timeout int               `json:"timeout,omitempty"`
	Options map[string]string `json:"options,omitempty"`
}

func (DiagnosticIntent) jobType() JobType { return JobTypeDiagnostic }

type SpeedTestIntent struct {
	URL       string `json:"url"`
	TimeoutMs uint32 `json:"timeout_ms"`
}

func (SpeedTestIntent) jobType() JobType { return JobTypeSpeedTest }

type WgScanIntent struct {
	IP         string `json:"ip"`
	Port       uint16 `json:"port"`
	TimeoutMs  uint32 `json:"timeout_ms"`
	PaddingLen uint32 `json:"padding_len"`
}

func (WgScanIntent) jobType() JobType { return JobTypeWgScan }

type CdnScanIntent struct {
	Targets     []string `json:"targets"`
	CDNHost     string   `json:"cdn_host"`
	SampleRate  int      `json:"sample_rate"`
	TimeoutMs   uint32   `json:"timeout_ms"`
	Concurrency int      `json:"concurrency"`
}

func (CdnScanIntent) jobType() JobType { return JobTypeCdnScan }

type IpDiscoveryIntent struct {
	Blocks    []string `json:"blocks"`
	TimeoutMs uint32   `json:"timeout_ms"`
	Workers   int      `json:"workers"`
	Duration  int      `json:"duration"`
}

func (IpDiscoveryIntent) jobType() JobType { return JobTypeIpDiscovery }

type VpsProvisionIntent struct {
	Config provision.VpsConfig `json:"-"`
}

func (VpsProvisionIntent) jobType() JobType { return JobTypeVpsProvision }

type StreamScanIntent struct {
	Target    string   `json:"target"`
	Ports     []uint16 `json:"ports"`
	TimeoutMs int      `json:"timeout_ms"`
}

func (StreamScanIntent) jobType() JobType { return JobTypeStreamScan }

type EdgeDeployIntent struct {
	Config provision.EdgeConfig `json:"-"`
}

func (EdgeDeployIntent) jobType() JobType { return JobTypeEdgeDeploy }

func normalizeIntent(intent JobIntent) (JobIntent, error) {
	if intent == nil {
		return nil, fmt.Errorf("job intent is required")
	}
	switch v := intent.(type) {
	case StreamScanIntent:
		if v.Target == "" {
			v.Target = "127.0.0.1"
		}
		if len(v.Ports) == 0 {
			v.Ports = []uint16{80, 443, 8080}
		}
		if v.TimeoutMs <= 0 {
			v.TimeoutMs = 3000
		}
		return v, nil
	case IcmpScanIntent:
		if v.TimeoutMs <= 0 {
			v.TimeoutMs = 1000
		}
		if v.Concurrency <= 0 {
			v.Concurrency = 100
		}
		return v, nil
	case PortScanIntent:
		if v.TimeoutMs <= 0 {
			v.TimeoutMs = 1000
		}
		if v.Concurrency <= 0 {
			v.Concurrency = 100
		}
		return v, nil
	case DnsScanIntent:
		if v.Server == "" {
			v.Server = "8.8.8.8"
		}
		if v.RecordType == "" {
			v.RecordType = "A"
		}
		if v.TimeoutMs == 0 {
			v.TimeoutMs = 3000
		}
		return v, nil
	case TlsScanIntent:
		if v.Port == 0 {
			v.Port = 443
		}
		if v.TimeoutMs == 0 {
			v.TimeoutMs = 5000
		}
		return v, nil
	case SniScanIntent:
		if v.TimeoutMs == 0 {
			v.TimeoutMs = 5000
		}
		return v, nil
	case ProxyTestIntent:
		if len(v.URLs) == 0 && v.Target == "" {
			v.URLs = []string{"http://cp.cloudflare.com/"}
		}
		if v.Timeout <= 0 && v.TimeoutMs == 0 {
			v.Timeout = 10
		}
		if v.Concurrency <= 0 {
			v.Concurrency = 8
		}
		return v, nil
	case DiagnosticIntent:
		if v.Target == "" {
			v.Target = "8.8.8.8:53"
		}
		if v.Type == "" {
			v.Type = "ping"
		}
		if v.Timeout <= 0 {
			v.Timeout = 15
		}
		return v, nil
	case SpeedTestIntent, WgScanIntent, VpsProvisionIntent:
		return v, nil
	case CdnScanIntent:
		if v.CDNHost == "" {
			v.CDNHost = "speed.cloudflare.com"
		}
		if v.TimeoutMs == 0 {
			v.TimeoutMs = 1500
		}
		if v.Concurrency <= 0 {
			v.Concurrency = 50
		}
		return v, nil
	case IpDiscoveryIntent:
		if v.TimeoutMs == 0 {
			v.TimeoutMs = 1500
		}
		if v.Workers <= 0 {
			v.Workers = 50
		}
		if v.Duration <= 0 {
			v.Duration = 60
		}
		return v, nil
	case EdgeDeployIntent:
		if v.Config.Type == "" {
			v.Config.Type = "relay"
		}
		return v, nil
	default:
		return nil, fmt.Errorf("unsupported job intent %T", intent)
	}
}

func persistedConfig(intent JobIntent) (string, error) {
	var value any = intent
	switch v := intent.(type) {
	case VpsProvisionIntent:
		cfg := v.Config
		cfg.SSHPassword = redactSecret(cfg.SSHPassword)
		cfg.SSHKey = redactSecret(cfg.SSHKey)
		cfg.CFToken = redactSecret(cfg.CFToken)
		value = cfg
	case EdgeDeployIntent:
		cfg := v.Config
		cfg.CFToken = redactSecret(cfg.CFToken)
		value = cfg
	case ProxyTestIntent:
		value = redactProxyTestIntent(v)
	}
	encoded, err := json.Marshal(value)
	if err != nil {
		return "", fmt.Errorf("encode persisted job config: %w", err)
	}
	return string(encoded), nil
}

func redactProxyTestIntent(v ProxyTestIntent) ProxyTestIntent {
	redacted := v
	preview := func(raw string) string {
		if strings.TrimSpace(raw) == "" {
			return ""
		}
		return proxyconfig.URITransportPreview(raw, 110)
	}
	if len(v.Proxies) > 0 {
		redacted.Proxies = make([]string, len(v.Proxies))
		for i, raw := range v.Proxies {
			redacted.Proxies[i] = preview(raw)
		}
	}
	redacted.ProxyURI = preview(v.ProxyURI)
	redacted.ProxyAddr = preview(v.ProxyAddr)
	if strings.TrimSpace(redacted.ProxyPreview) == "" {
		if redacted.ProxyURI != "" {
			redacted.ProxyPreview = redacted.ProxyURI
		} else if redacted.ProxyAddr != "" {
			redacted.ProxyPreview = redacted.ProxyAddr
		}
	}
	return redacted
}
func redactSecret(v string) string {
	if v == "" {
		return ""
	}
	return redactedSecret
}

func scrubLegacyConfig(jobType JobType, raw string) (string, bool) {
	if raw == "" {
		return raw, false
	}
	switch jobType {
	case JobTypeProxyTest:
		var cfg ProxyTestIntent
		if json.Unmarshal([]byte(raw), &cfg) != nil {
			return redactedUnreadableConfig, raw != redactedUnreadableConfig
		}
		encoded, err := json.Marshal(redactProxyTestIntent(cfg))
		if err != nil {
			return redactedUnreadableConfig, raw != redactedUnreadableConfig
		}
		sanitized := string(encoded)
		return sanitized, sanitized != raw
	case JobTypeVpsProvision:
		var cfg provision.VpsConfig
		if json.Unmarshal([]byte(raw), &cfg) != nil {
			return redactedUnreadableConfig, raw != redactedUnreadableConfig
		}
		cfg.SSHPassword = redactSecret(cfg.SSHPassword)
		cfg.SSHKey = redactSecret(cfg.SSHKey)
		cfg.CFToken = redactSecret(cfg.CFToken)
		b, err := json.Marshal(cfg)
		if err != nil {
			return raw, false
		}
		return string(b), string(b) != raw
	case JobTypeEdgeDeploy:
		var cfg provision.EdgeConfig
		if json.Unmarshal([]byte(raw), &cfg) != nil {
			return redactedUnreadableConfig, raw != redactedUnreadableConfig
		}
		cfg.CFToken = redactSecret(cfg.CFToken)
		b, err := json.Marshal(cfg)
		if err != nil {
			return raw, false
		}
		return string(b), string(b) != raw
	default:
		return raw, false
	}
}

func intentAs[T JobIntent](job *Job) (T, error) {
	var zero T
	v, ok := job.intent.(T)
	if !ok {
		return zero, fmt.Errorf("job %s execution intent is %T, want %T", job.ID, job.intent, zero)
	}
	return v, nil
}
func vpsProvisionConfig(job *Job) (provision.VpsConfig, error) {
	v, err := intentAs[VpsProvisionIntent](job)
	if err != nil {
		return provision.VpsConfig{}, err
	}
	return v.Config, nil
}
func edgeDeployConfig(job *Job) (provision.EdgeConfig, error) {
	v, err := intentAs[EdgeDeployIntent](job)
	if err != nil {
		return provision.EdgeConfig{}, err
	}
	return v.Config, nil
}
