package system

import (
	"net"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	// DefaultIPStaleDuration is the cutoff after which inactive client IPs are pruned (30m).
	DefaultIPStaleDuration = 30 * time.Minute
	// DefaultClusterSyncWindow is the window in which cluster-observed IPs are deemed live (2m).
	DefaultClusterSyncWindow = 2 * time.Minute
)

// ClientIPRecord records an observed client IP address and its last seen unix timestamp.
type ClientIPRecord struct {
	IP        string `json:"ip"`
	Timestamp int64  `json:"timestamp"`
}

// MergeClientIPs merges historical and current observed IPs, pruning entries older than staleCutoff.
// If newAlwaysLive is true, newly observed IPs bypass the staleCutoff filter.
func MergeClientIPs(oldIPs, newIPs []ClientIPRecord, staleCutoff int64, newAlwaysLive bool) map[string]int64 {
	ipMap := make(map[string]int64, len(oldIPs)+len(newIPs))

	for _, rec := range oldIPs {
		if rec.Timestamp < staleCutoff {
			continue
		}
		ipMap[rec.IP] = rec.Timestamp
	}

	for _, rec := range newIPs {
		if !newAlwaysLive && rec.Timestamp < staleCutoff {
			continue
		}
		if existing, ok := ipMap[rec.IP]; !ok || rec.Timestamp > existing {
			ipMap[rec.IP] = rec.Timestamp
		}
	}

	return ipMap
}

// PartitionLiveIPs splits the merged IP map into live and historical slices sorted oldest-first.
func PartitionLiveIPs(ipMap map[string]int64, observedThisScan map[string]bool, now int64, clusterRecentWindowSec int64) (live, historical []ClientIPRecord) {
	live = make([]ClientIPRecord, 0, len(observedThisScan))
	historical = make([]ClientIPRecord, 0, len(ipMap))

	if clusterRecentWindowSec <= 0 {
		clusterRecentWindowSec = int64(DefaultClusterSyncWindow.Seconds())
	}

	for ip, ts := range ipMap {
		rec := ClientIPRecord{IP: ip, Timestamp: ts}
		if (observedThisScan != nil && observedThisScan[ip]) || (now-ts >= 0 && now-ts < clusterRecentWindowSec) {
			live = append(live, rec)
		} else {
			historical = append(historical, rec)
		}
	}

	sort.Slice(live, func(i, j int) bool { return live[i].Timestamp < live[j].Timestamp })
	sort.Slice(historical, func(i, j int) bool { return historical[i].Timestamp < historical[j].Timestamp })

	return live, historical
}

// SelectIPsToBan selects the newest `limit` IPs to keep, and marks older excess IPs for banning/disconnection.
func SelectIPsToBan(live []ClientIPRecord, limit int) (kept, banned []ClientIPRecord) {
	if limit <= 0 || len(live) <= limit {
		return live, nil
	}
	cutoff := len(live) - limit
	return live[cutoff:], live[:cutoff]
}

// IPLimitAllowlist holds allowed IP literals and CIDRs that are exempt from concurrency limits.
type IPLimitAllowlist struct {
	exactIPs map[string]struct{}
	cidrs    []*net.IPNet
}

// NewIPLimitAllowlist parses newline- or comma-separated IPs/CIDRs into an allowlist.
func NewIPLimitAllowlist(raw string) *IPLimitAllowlist {
	al := &IPLimitAllowlist{
		exactIPs: make(map[string]struct{}),
		cidrs:    make([]*net.IPNet, 0),
	}

	tokens := strings.FieldsFunc(raw, func(r rune) bool {
		return r == '\n' || r == '\r' || r == ',' || r == ';'
	})

	for _, token := range tokens {
		token = strings.TrimSpace(token)
		if token == "" || strings.HasPrefix(token, "#") {
			continue
		}

		if strings.Contains(token, "/") {
			_, ipnet, err := net.ParseCIDR(token)
			if err == nil && ipnet != nil {
				al.cidrs = append(al.cidrs, ipnet)
				continue
			}
		}

		parsed := net.ParseIP(token)
		if parsed != nil {
			al.exactIPs[parsed.String()] = struct{}{}
		}
	}

	return al
}

// Contains checks if an IP matches the allowlist.
func (al *IPLimitAllowlist) Contains(ipStr string) bool {
	if al == nil {
		return false
	}
	ip := net.ParseIP(strings.TrimSpace(ipStr))
	if ip == nil {
		return false
	}

	if _, exists := al.exactIPs[ip.String()]; exists {
		return true
	}

	for _, cidr := range al.cidrs {
		if cidr.Contains(ip) {
			return true
		}
	}

	return false
}

// Split divides live IPs into limited IPs (subject to quota) and allowed IPs (exempt from quota).
func (al *IPLimitAllowlist) Split(live []ClientIPRecord) (limited, allowed []ClientIPRecord) {
	if al == nil || (len(al.exactIPs) == 0 && len(al.cidrs) == 0) {
		return live, nil
	}

	limited = make([]ClientIPRecord, 0, len(live))
	allowed = make([]ClientIPRecord, 0)

	for _, rec := range live {
		if al.Contains(rec.IP) {
			allowed = append(allowed, rec)
		} else {
			limited = append(limited, rec)
		}
	}

	return limited, allowed
}

// BanDeduplicator filters out redundant bans for frozen/dead connections where lastSeen has not advanced.
type BanDeduplicator struct {
	mu         sync.Mutex
	bannedSeen map[string]int64
}

// NewBanDeduplicator initializes a BanDeduplicator.
func NewBanDeduplicator() *BanDeduplicator {
	return &BanDeduplicator{
		bannedSeen: make(map[string]int64),
	}
}

// FilterAdvancedSinceLastBan returns only banned items whose timestamp is strictly greater than the last recorded ban.
func (d *BanDeduplicator) FilterAdvancedSinceLastBan(clientKey string, banned []ClientIPRecord) []ClientIPRecord {
	d.mu.Lock()
	defer d.mu.Unlock()

	current := make(map[string]struct{}, len(banned))
	actionable := make([]ClientIPRecord, 0, len(banned))

	for _, rec := range banned {
		key := clientKey + "|" + rec.IP
		current[key] = struct{}{}
		if lastTs, ok := d.bannedSeen[key]; ok && rec.Timestamp <= lastTs {
			continue
		}
		d.bannedSeen[key] = rec.Timestamp
		actionable = append(actionable, rec)
	}

	// Evict entries for keys no longer present
	prefix := clientKey + "|"
	for k := range d.bannedSeen {
		if strings.HasPrefix(k, prefix) {
			if _, exists := current[k]; !exists {
				delete(d.bannedSeen, k)
			}
		}
	}

	return actionable
}
