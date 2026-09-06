// Copyright 2024 LumiNet. Use of this source code is governed by the MIT license.
// WhiteDNS-style poison verifier. Detects forged or hijacked DNS responses by
// comparing them against a set of trusted anchors. Anchors can be IP-based,
// range-based (CIDR), or response-pin-based. Triggers an Anomaly when a
// response deviates from what the trusted anchors permit.

package dns

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"
)

// Anomaly classifies why a response was flagged as poisoned.
type Anomaly int

const (
	AnomalyNone         Anomaly = iota
	AnomalyUnknownServer         // response from a server not in the trusted set
	AnomalyIPMismatch            // resolved IP is not in the trusted set for the domain
	AnomalyIPRangeMismatch       // resolved IP falls outside a trusted CIDR range
	AnomalyTransactionMismatch   // transaction ID does not match the request
	AnomalyQuestionMismatch      // question section does not match the request
	AnomalyUnexpectedRCode       // rcode is not in the trusted set (e.g. refused/filtered)
	AnomalyTTLDrift              // TTL is implausibly low or zero (typical of forged responses)
)

// String returns a human-readable label for the anomaly.
func (a Anomaly) String() string {
	switch a {
	case AnomalyNone:
		return "none"
	case AnomalyUnknownServer:
		return "unknown_server"
	case AnomalyIPMismatch:
		return "ip_mismatch"
	case AnomalyIPRangeMismatch:
		return "ip_range_mismatch"
	case AnomalyTransactionMismatch:
		return "transaction_id_mismatch"
	case AnomalyQuestionMismatch:
		return "question_mismatch"
	case AnomalyUnexpectedRCode:
		return "unexpected_rcode"
	case AnomalyTTLDrift:
		return "ttl_drift"
	default:
		return fmt.Sprintf("anomaly(%d)", int(a))
	}
}

// VerificationResult is the outcome of VerifyResponse.
type VerificationResult struct {
	Trusted bool
	Anomaly Anomaly
	Reason  string
}

// Anchor is a trusted source for a particular domain pattern. DomainPatterns
// support simple wildcard matching with leading "*." (e.g. "*.example.com").
type Anchor struct {
	DomainPatterns []string
	AllowedIPs     []string  // exact IPs
	AllowedCIDRs   []string  // CIDR ranges
	AllowedRCodes  []int     // e.g. 0 (NOERROR), 3 (NXDOMAIN); empty accepts all
	MinTTL         uint32    // minimum acceptable TTL; 0 disables the check
	UpstreamIDs    []string  // IDs of trusted upstreams for this anchor
}

// PoisonVerifier compares DNS responses against a set of trusted anchors and
// classifies them as trusted or anomalous.
type PoisonVerifier struct {
	mu      sync.RWMutex
	anchors []Anchor
	// Default trusted upstream IDs; used for the AnomalyUnknownServer check
	// when an Anchor has no UpstreamIDs.
	defaultUpstreamIDs map[string]struct{}
}

// NewPoisonVerifier constructs an empty verifier.
func NewPoisonVerifier() *PoisonVerifier {
	return &PoisonVerifier{
		defaultUpstreamIDs: make(map[string]struct{}),
	}
}

// SetAnchors replaces the current anchor set.
func (v *PoisonVerifier) SetAnchors(anchors []Anchor) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.anchors = append([]Anchor(nil), anchors...)
}

// AddAnchor appends a single anchor.
func (v *PoisonVerifier) AddAnchor(anchor Anchor) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.anchors = append(v.anchors, anchor)
}

// SetDefaultUpstreamIDs configures the set of trusted upstream IDs used when
// an anchor does not specify its own.
func (v *PoisonVerifier) SetDefaultUpstreamIDs(ids []string) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.defaultUpstreamIDs = make(map[string]struct{}, len(ids))
	for _, id := range ids {
		v.defaultUpstreamIDs[id] = struct{}{}
	}
}

// VerifyResponse checks the given DNS response for signs of poisoning. The
// query is the wire-format request that produced the response, and upstreamID
// is the identifier of the upstream that returned the response. The result
// always reports a non-nil Reason when Trusted is false.
func (v *PoisonVerifier) VerifyResponse(query, response []byte, upstreamID string) VerificationResult {
	if len(query) < 12 || len(response) < 12 {
		return VerificationResult{Anomaly: AnomalyTransactionMismatch, Reason: "query or response too short to validate"}
	}
	// Transaction ID check.
	if !bytes.Equal(query[:2], response[:2]) {
		return VerificationResult{Anomaly: AnomalyTransactionMismatch, Reason: "transaction ID does not match query"}
	}
	// Question section check.
	qName, qType, qClass, err := parseDNSQuestion(query)
	if err != nil {
		return VerificationResult{Anomaly: AnomalyQuestionMismatch, Reason: "query question could not be parsed"}
	}
	rName, rType, rClass, err := parseDNSQuestion(response)
	if err != nil {
		return VerificationResult{Anomaly: AnomalyQuestionMismatch, Reason: "response question could not be parsed"}
	}
	if !strings.EqualFold(qName, rName) || qType != rType || qClass != rClass {
		return VerificationResult{Anomaly: AnomalyQuestionMismatch, Reason: "response question does not match query question"}
	}
	// Upstream check (against anchor set or defaults).
	if !v.upstreamAllowed(upstreamID, rName) {
		return VerificationResult{Anomaly: AnomalyUnknownServer, Reason: fmt.Sprintf("upstream %q is not trusted for %s", upstreamID, rName)}
	}
	// RCODE check.
	rcode := int(response[3] & 0x0F)
	if allowed := v.allowedRCodes(rName); len(allowed) > 0 {
		ok := false
		for _, a := range allowed {
			if a == rcode {
				ok = true
				break
			}
		}
		if !ok {
			return VerificationResult{Anomaly: AnomalyUnexpectedRCode, Reason: fmt.Sprintf("rcode %d not in trusted set for %s", rcode, rName)}
		}
	}
	// For NOERROR responses, verify the IPs in the answer.
	if rcode == 0 {
		minTTL := v.minTTL(rName)
		ips, ttls := extractARecordsWithTTL(response)
		if minTTL > 0 {
			for _, ttl := range ttls {
				if ttl < minTTL {
					return VerificationResult{Anomaly: AnomalyTTLDrift, Reason: fmt.Sprintf("TTL %d below minimum %d for %s", ttl, minTTL, rName)}
				}
			}
		}
		if allowedIPs, allowedCIDRs, hasAllowance := v.allowedAddresses(rName); hasAllowance {
			for _, ip := range ips {
				if !ipAllowed(ip, allowedIPs, allowedCIDRs) {
					return VerificationResult{Anomaly: AnomalyIPMismatch, Reason: fmt.Sprintf("IP %s not in trusted set for %s", ip, rName)}
				}
			}
		}
	}
	return VerificationResult{Trusted: true}
}

// VerifyRecord is a convenience wrapper that takes a domain, list of resolved
// IPs, and upstream ID and returns the verification outcome. It is intended
// for non-DNS-wire callers (e.g. cache validation).
func (v *PoisonVerifier) VerifyRecord(domain string, ips []string, upstreamID string) VerificationResult {
	v.mu.RLock()
	defer v.mu.RUnlock()
	anchor := v.findAnchorLocked(domain)
	if anchor == nil {
		// Without anchors we only check the upstream.
		if _, ok := v.defaultUpstreamIDs[upstreamID]; !ok && len(v.defaultUpstreamIDs) > 0 {
			return VerificationResult{Anomaly: AnomalyUnknownServer, Reason: fmt.Sprintf("upstream %q is not in default trusted set", upstreamID)}
		}
		return VerificationResult{Trusted: true}
	}
	// Upstream check.
	if !upstreamAllowedInAnchor(upstreamID, anchor, v.defaultUpstreamIDs) {
		return VerificationResult{Anomaly: AnomalyUnknownServer, Reason: fmt.Sprintf("upstream %q is not trusted for %s", upstreamID, domain)}
	}
	// IP check.
	allowedIPs := anchor.AllowedIPs
	allowedCIDRs := anchor.AllowedCIDRs
	if len(allowedIPs) == 0 && len(allowedCIDRs) == 0 {
		return VerificationResult{Trusted: true}
	}
	for _, ip := range ips {
		if !ipAllowed(ip, allowedIPs, allowedCIDRs) {
			return VerificationResult{Anomaly: AnomalyIPMismatch, Reason: fmt.Sprintf("IP %s not in trusted set for %s", ip, domain)}
		}
	}
	return VerificationResult{Trusted: true}
}

// findAnchorLocked returns the most specific anchor matching the given domain,
// or nil. Caller must hold v.mu.
func (v *PoisonVerifier) findAnchorLocked(domain string) *Anchor {
	domain = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(domain)), ".")
	// Prefer exact matches, then wildcard suffix matches.
	var wildcard *Anchor
	for i := range v.anchors {
		for _, pattern := range v.anchors[i].DomainPatterns {
			p := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(pattern), "."))
			if p == domain {
				return &v.anchors[i]
			}
			if strings.HasPrefix(p, "*.") {
				suffix := p[1:] // include leading dot
				if strings.HasSuffix(domain, suffix) && domain != strings.TrimPrefix(suffix, ".") {
					wildcard = &v.anchors[i]
				}
			}
		}
	}
	return wildcard
}

func (v *PoisonVerifier) upstreamAllowed(id, domain string) bool {
	v.mu.RLock()
	defer v.mu.RUnlock()
	if anchor := v.findAnchorLocked(domain); anchor != nil {
		return upstreamAllowedInAnchor(id, anchor, v.defaultUpstreamIDs)
	}
	if len(v.defaultUpstreamIDs) == 0 {
		return true // no restrictions
	}
	_, ok := v.defaultUpstreamIDs[id]
	return ok
}

func (v *PoisonVerifier) allowedRCodes(domain string) []int {
	v.mu.RLock()
	defer v.mu.RUnlock()
	if anchor := v.findAnchorLocked(domain); anchor != nil {
		return anchor.AllowedRCodes
	}
	return nil
}

func (v *PoisonVerifier) minTTL(domain string) uint32 {
	v.mu.RLock()
	defer v.mu.RUnlock()
	if anchor := v.findAnchorLocked(domain); anchor != nil {
		return anchor.MinTTL
	}
	return 0
}

func (v *PoisonVerifier) allowedAddresses(domain string) (ips []string, cidrs []string, hasAllowance bool) {
	v.mu.RLock()
	defer v.mu.RUnlock()
	if anchor := v.findAnchorLocked(domain); anchor != nil {
		return anchor.AllowedIPs, anchor.AllowedCIDRs, len(anchor.AllowedIPs) > 0 || len(anchor.AllowedCIDRs) > 0
	}
	return nil, nil, false
}

func upstreamAllowedInAnchor(id string, anchor *Anchor, defaults map[string]struct{}) bool {
	if len(anchor.UpstreamIDs) == 0 {
		// Fall back to defaults.
		if len(defaults) == 0 {
			return true
		}
		_, ok := defaults[id]
		return ok
	}
	for _, a := range anchor.UpstreamIDs {
		if a == id {
			return true
		}
	}
	return false
}

// ipAllowed checks an IP against a list of allowed IPs and CIDR ranges.
func ipAllowed(ip string, allowedIPs, allowedCIDRs []string) bool {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false
	}
	for _, a := range allowedIPs {
		if a == ip {
			return true
		}
	}
	for _, c := range allowedCIDRs {
		_, ipnet, err := net.ParseCIDR(c)
		if err != nil {
			continue
		}
		if ipnet.Contains(parsed) {
			return true
		}
	}
	return false
}

// extractARecordsWithTTL parses a wire-format DNS response and returns its
// A-record IPs and corresponding TTLs.
func extractARecordsWithTTL(resp []byte) (ips []string, ttls []uint32) {
	if len(resp) < 12 {
		return
	}
	anCount := int(binary.BigEndian.Uint16(resp[6:8]))
	offset := 12
	// Skip question section.
	qdCount := int(binary.BigEndian.Uint16(resp[4:6]))
	for i := 0; i < qdCount; i++ {
		for offset < len(resp) {
			if resp[offset] == 0 {
				offset++
				break
			}
			if resp[offset]&0xC0 == 0xC0 {
				offset += 2
				break
			}
			offset += int(resp[offset]) + 1
		}
		offset += 4
	}
	for i := 0; i < anCount && offset+10 <= len(resp); i++ {
		if resp[offset]&0xC0 == 0xC0 {
			offset += 2
		} else {
			for offset < len(resp) {
				if resp[offset] == 0 {
					offset++
					break
				}
				offset += int(resp[offset]) + 1
			}
		}
		if offset+10 > len(resp) {
			break
		}
		rtype := binary.BigEndian.Uint16(resp[offset : offset+2])
		_ = rtype
		ttl := binary.BigEndian.Uint32(resp[offset+4 : offset+8])
		rdlength := int(binary.BigEndian.Uint16(resp[offset+8 : offset+10]))
		offset += 10
		if rtype == 1 && rdlength == 4 && offset+4 <= len(resp) {
			ip := fmt.Sprintf("%d.%d.%d.%d", resp[offset], resp[offset+1], resp[offset+2], resp[offset+3])
			ips = append(ips, ip)
			ttls = append(ttls, ttl)
		}
		offset += rdlength
	}
	// Sort for deterministic test output.
	sort.Strings(ips)
	return
}
