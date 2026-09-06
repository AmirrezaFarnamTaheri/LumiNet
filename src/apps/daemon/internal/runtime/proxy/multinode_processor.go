// Package proxy implements outbound protocols and obfuscation mechanisms.

package proxy

import (
	"bytes"
	"compress/gzip"
	"encoding/gob"
	"fmt"
	"runtime"
	"strings"
	"sync"
)

// NetflowPacket defines a single incoming telemetry record.
type NetflowPacket struct {
	IP        string
	Country   string
	ISP       string
	ASN       string
	Direction string
	Protocol  string
	Bytes     float64
}

// AggregatedFlow contains aggregated protocol statistics.
type AggregatedFlow struct {
	IP        string
	Country   string
	ISP       string
	ASN       string
	Direction string

	TCPPacket  int64
	TCPBytes   float64
	UDPPacket  int64
	UDPBytes   float64
	ICMPPacket int64
	ICMPBytes  float64
}

// MultinodeProcessor aggregates netflow packets concurrently.
type MultinodeProcessor struct {
	mu           sync.RWMutex
	active       bool
	version      int
	logLevel     string
	maxWorkers   int
	allowedIPs   []string
	blockedASNs  []string
	totalPackets uint64
	totalBytes   float64
}

// NewMultinodeProcessor initializes a new MultinodeProcessor.
func NewMultinodeProcessor() *MultinodeProcessor {
	return &MultinodeProcessor{
		active:       true,
		version:      1,
		logLevel:     "info",
		maxWorkers:   runtime.NumCPU(),
		allowedIPs:   make([]string, 0),
		blockedASNs:  make([]string, 0),
		totalPackets: 0,
		totalBytes:   0.0,
	}
}

// Process processes Netflow packets concurrently in chunks.
func (p *MultinodeProcessor) Process(bucket []NetflowPacket) ([]AggregatedFlow, error) {
	threads := runtime.GOMAXPROCS(0)
	n := len(bucket)
	if n == 0 {
		return nil, fmt.Errorf("empty bucket")
	}

	chunkSize := (n + threads - 1) / threads
	var chunks [][]NetflowPacket
	for i := 0; i < n; i += chunkSize {
		j := i + chunkSize
		if j > n {
			j = n
		}
		chunks = append(chunks, bucket[i:j])
	}

	var wg sync.WaitGroup
	wg.Add(len(chunks))

	var mutex sync.Mutex
	aggregatedMap := make(map[string]*AggregatedFlow)

	for _, chunk := range chunks {
		go func(c []NetflowPacket) {
			defer wg.Done()
			localMap := make(map[string]*AggregatedFlow)

			for _, packet := range c {
				key := fmt.Sprintf("%s|%s|%s|%s|%s", packet.IP, packet.Country, packet.ISP, packet.ASN, packet.Direction)
				flow, exists := localMap[key]
				if !exists {
					flow = &AggregatedFlow{
						IP:        packet.IP,
						Country:   packet.Country,
						ISP:       packet.ISP,
						ASN:       packet.ASN,
						Direction: packet.Direction,
					}
					localMap[key] = flow
				}

				switch stringsToUpper(packet.Protocol) {
				case "TCP":
					flow.TCPPacket++
					flow.TCPBytes += packet.Bytes
				case "UDP":
					flow.UDPPacket++
					flow.UDPBytes += packet.Bytes
				case "ICMP":
					flow.ICMPPacket++
					flow.ICMPBytes += packet.Bytes
				}
			}

			mutex.Lock()
			for key, flow := range localMap {
				aggFlow, exists := aggregatedMap[key]
				if !exists {
					aggregatedMap[key] = flow
				} else {
					aggFlow.TCPPacket += flow.TCPPacket
					aggFlow.TCPBytes += flow.TCPBytes
					aggFlow.UDPPacket += flow.UDPPacket
					aggFlow.UDPBytes += flow.UDPBytes
					aggFlow.ICMPPacket += flow.ICMPPacket
					aggFlow.ICMPBytes += flow.ICMPBytes
				}
			}
			mutex.Unlock()
		}(chunk)
	}

	wg.Wait()

	result := make([]AggregatedFlow, 0, len(aggregatedMap))
	for _, flow := range aggregatedMap {
		result = append(result, *flow)
	}

	return result, nil
}

func stringsToUpper(s string) string {
	var builder strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'a' && c <= 'z' {
			c -= 32
		}
		builder.WriteByte(c)
	}
	return builder.String()
}

// MarshalNetflowBatch serializes and compresses a batch of netflow packets.
func (p *MultinodeProcessor) MarshalNetflowBatch(batch []NetflowPacket) ([]byte, error) {
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	enc := gob.NewEncoder(gz)
	if err := enc.Encode(batch); err != nil {
		return nil, err
	}
	if err := gz.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// MarshalNetflowPacket serializes and compresses a single netflow packet.
func (p *MultinodeProcessor) MarshalNetflowPacket(packet NetflowPacket) ([]byte, error) {
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	enc := gob.NewEncoder(gz)
	if err := enc.Encode(packet); err != nil {
		return nil, err
	}
	if err := gz.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// UnmarshalNetflowBatch decompresses and deserializes netflow packets.
func (p *MultinodeProcessor) UnmarshalNetflowBatch(data [][]byte) ([]NetflowPacket, error) {
	var batch []NetflowPacket
	for _, compressed := range data {
		buf := bytes.NewBuffer(compressed)
		gz, err := gzip.NewReader(buf)
		if err != nil {
			return nil, err
		}
		dec := gob.NewDecoder(gz)
		var packet NetflowPacket
		if err := dec.Decode(&packet); err != nil {
			return nil, err
		}
		batch = append(batch, packet)
		if err := gz.Close(); err != nil {
			return nil, err
		}
	}
	return batch, nil
}

// SetActive overrides telemetry processor active flag.
func (p *MultinodeProcessor) SetActive(active bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.active = active
}

// GetActive retrieves telemetry processor active flag.
func (p *MultinodeProcessor) GetActive() bool {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.active
}

// SetVersion overrides configuration schema version.
func (p *MultinodeProcessor) SetVersion(v int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.version = v
}

// GetVersion retrieves configuration schema version.
func (p *MultinodeProcessor) GetVersion() int {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.version
}

// SetLogLevel overrides diagnostics log severity level.
func (p *MultinodeProcessor) SetLogLevel(level string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.logLevel = level
}

// GetLogLevel retrieves diagnostics log severity level.
func (p *MultinodeProcessor) GetLogLevel() string {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.logLevel
}

// SetMaxWorkers overrides concurrent processing thread bounds.
func (p *MultinodeProcessor) SetMaxWorkers(workers int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.maxWorkers = workers
}

// GetMaxWorkers retrieves concurrent processing thread bounds.
func (p *MultinodeProcessor) GetMaxWorkers() int {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.maxWorkers
}

// SetTotalPackets overrides total processed packet counter.
func (p *MultinodeProcessor) SetTotalPackets(val uint64) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.totalPackets = val
}

// GetTotalPackets retrieves total processed packet counter.
func (p *MultinodeProcessor) GetTotalPackets() uint64 {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.totalPackets
}

// SetTotalBytes overrides total processed bytes counter.
func (p *MultinodeProcessor) SetTotalBytes(val float64) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.totalBytes = val
}

// GetTotalBytes retrieves total processed bytes counter.
func (p *MultinodeProcessor) GetTotalBytes() float64 {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.totalBytes
}

// SetAllowedIPs overrides whitelist of monitored client IPs.
func (p *MultinodeProcessor) SetAllowedIPs(ips []string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	copied := make([]string, len(ips))
	copy(copied, ips)
	p.allowedIPs = copied
}

// GetAllowedIPs retrieves whitelist of monitored client IPs.
func (p *MultinodeProcessor) GetAllowedIPs() []string {
	p.mu.RLock()
	defer p.mu.RUnlock()
	copied := make([]string, len(p.allowedIPs))
	copy(copied, p.allowedIPs)
	return copied
}

// AddAllowedIP registers allowed client IP.
func (p *MultinodeProcessor) AddAllowedIP(ip string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.allowedIPs = append(p.allowedIPs, ip)
}

// RemoveAllowedIP deletes whitelisted client IP.
func (p *MultinodeProcessor) RemoveAllowedIP(ip string) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	idx := -1
	for i, v := range p.allowedIPs {
		if v == ip {
			idx = i
			break
		}
	}
	if idx != -1 {
		p.allowedIPs = append(p.allowedIPs[:idx], p.allowedIPs[idx+1:]...)
		return true
	}
	return false
}

// ClearAllowedIPs flushes whitelisted client IPs.
func (p *MultinodeProcessor) ClearAllowedIPs() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.allowedIPs = make([]string, 0)
}

// GetAllowedIPsCount retrieves count of whitelisted client IPs.
func (p *MultinodeProcessor) GetAllowedIPsCount() int {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return len(p.allowedIPs)
}

// SetBlockedASNs overrides blacklist of excluded network ASNs.
func (p *MultinodeProcessor) SetBlockedASNs(asns []string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	copied := make([]string, len(asns))
	copy(copied, asns)
	p.blockedASNs = copied
}

// GetBlockedASNs retrieves blacklist of excluded network ASNs.
func (p *MultinodeProcessor) GetBlockedASNs() []string {
	p.mu.RLock()
	defer p.mu.RUnlock()
	copied := make([]string, len(p.blockedASNs))
	copy(copied, p.blockedASNs)
	return copied
}

// AddBlockedASN registers excluded network ASN.
func (p *MultinodeProcessor) AddBlockedASN(asn string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.blockedASNs = append(p.blockedASNs, asn)
}

// RemoveBlockedASN deletes blacklisted network ASN.
func (p *MultinodeProcessor) RemoveBlockedASN(asn string) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	idx := -1
	for i, v := range p.blockedASNs {
		if v == asn {
			idx = i
			break
		}
	}
	if idx != -1 {
		p.blockedASNs = append(p.blockedASNs[:idx], p.blockedASNs[idx+1:]...)
		return true
	}
	return false
}

// ClearBlockedASNs flushes blacklisted network ASNs.
func (p *MultinodeProcessor) ClearBlockedASNs() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.blockedASNs = make([]string, 0)
}

// GetBlockedASNsCount retrieves count of blacklisted network ASNs.
func (p *MultinodeProcessor) GetBlockedASNsCount() int {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return len(p.blockedASNs)
}

// SetIP overrides NetflowPacket target IP.
func (np *NetflowPacket) SetIP(ip string) {
	np.IP = ip
}

// GetIP retrieves NetflowPacket target IP.
func (np *NetflowPacket) GetIP() string {
	return np.IP
}

// SetCountry overrides NetflowPacket target region.
func (np *NetflowPacket) SetCountry(c string) {
	np.Country = c
}

// GetCountry retrieves NetflowPacket target region.
func (np *NetflowPacket) GetCountry() string {
	return np.Country
}

// SetISP overrides NetflowPacket target internet provider.
func (np *NetflowPacket) SetISP(isp string) {
	np.ISP = isp
}

// GetISP retrieves NetflowPacket target internet provider.
func (np *NetflowPacket) GetISP() string {
	return np.ISP
}

// SetASN overrides NetflowPacket network system asn.
func (np *NetflowPacket) SetASN(asn string) {
	np.ASN = asn
}

// GetASN retrieves NetflowPacket network system asn.
func (np *NetflowPacket) GetASN() string {
	return np.ASN
}

// SetDirection overrides NetflowPacket telemetry flow direction.
func (np *NetflowPacket) SetDirection(d string) {
	np.Direction = d
}

// GetDirection retrieves NetflowPacket telemetry flow direction.
func (np *NetflowPacket) GetDirection() string {
	return np.Direction
}

// SetProtocol overrides NetflowPacket protocol target.
func (np *NetflowPacket) SetProtocol(p string) {
	np.Protocol = p
}

// GetProtocol retrieves NetflowPacket protocol target.
func (np *NetflowPacket) GetProtocol() string {
	return np.Protocol
}

// SetBytes overrides NetflowPacket byte weight.
func (np *NetflowPacket) SetBytes(b float64) {
	np.Bytes = b
}

// GetBytes retrieves NetflowPacket byte weight.
func (np *NetflowPacket) GetBytes() float64 {
	return np.Bytes
}
