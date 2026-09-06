package routing

import (
	"encoding/binary"
	"strings"
	"sync"
)

type PolicyVerdict string

const (
	PolicyVerdictDirect PolicyVerdict = "DIRECT"
	PolicyVerdictProxy  PolicyVerdict = "PROXY"
	PolicyVerdictReject PolicyVerdict = "REJECT"
)

type CidrRule struct {
	NetAddr uint32
	Mask    uint32
	Verdict PolicyVerdict
}

type KeywordRule struct {
	Keyword string
	Verdict PolicyVerdict
}

type PolicyRulesetRouter struct {
	mu            sync.RWMutex
	exactDomains  map[string]PolicyVerdict
	suffixDomains map[string]PolicyVerdict
	keywordRules  []KeywordRule
	cidrRules     []CidrRule
	cache         map[string]PolicyVerdict
	defaultPolicy PolicyVerdict
}

func NewPolicyRulesetRouter(defaultPolicy PolicyVerdict) *PolicyRulesetRouter {
	return &PolicyRulesetRouter{
		exactDomains:  make(map[string]PolicyVerdict),
		suffixDomains: make(map[string]PolicyVerdict),
		keywordRules:  make([]KeywordRule, 0),
		cidrRules:     make([]CidrRule, 0),
		cache:         make(map[string]PolicyVerdict),
		defaultPolicy: defaultPolicy,
	}
}

func (r *PolicyRulesetRouter) AddExactDomain(domain string, verdict PolicyVerdict) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.exactDomains[strings.ToLower(strings.TrimSpace(domain))] = verdict
}

func (r *PolicyRulesetRouter) AddSuffixDomain(suffix string, verdict PolicyVerdict) {
	r.mu.Lock()
	defer r.mu.Unlock()
	clean := strings.ToLower(strings.TrimSpace(suffix))
	clean = strings.TrimPrefix(clean, ".")
	r.suffixDomains[clean] = verdict
}

func (r *PolicyRulesetRouter) AddKeyword(keyword string, verdict PolicyVerdict) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.keywordRules = append(r.keywordRules, KeywordRule{
		Keyword: strings.ToLower(strings.TrimSpace(keyword)),
		Verdict: verdict,
	})
}

func (r *PolicyRulesetRouter) AddCidr(octets [4]byte, maskBits uint8, verdict PolicyVerdict) {
	r.mu.Lock()
	defer r.mu.Unlock()

	ipU32 := binary.BigEndian.Uint32(octets[:])
	var mask uint32
	if maskBits == 0 {
		mask = 0
	} else {
		mask = ^uint32(0) << (32 - maskBits)
	}

	r.cidrRules = append(r.cidrRules, CidrRule{
		NetAddr: ipU32 & mask,
		Mask:    mask,
		Verdict: verdict,
	})
}

func (r *PolicyRulesetRouter) ResolveDomain(domain string) PolicyVerdict {
	r.mu.Lock()
	defer r.mu.Unlock()

	clean := strings.ToLower(strings.TrimSpace(domain))
	if v, cached := r.cache[clean]; cached {
		return v
	}

	// 1. Exact match
	if v, exists := r.exactDomains[clean]; exists {
		r.cache[clean] = v
		return v
	}

	// 2. Suffix match
	for suffix, v := range r.suffixDomains {
		if clean == suffix || strings.HasSuffix(clean, "."+suffix) {
			r.cache[clean] = v
			return v
		}
	}

	// 3. Keyword match
	for _, kw := range r.keywordRules {
		if strings.Contains(clean, kw.Keyword) {
			r.cache[clean] = kw.Verdict
			return kw.Verdict
		}
	}

	r.cache[clean] = r.defaultPolicy
	return r.defaultPolicy
}

func (r *PolicyRulesetRouter) ResolveIP(octets [4]byte) PolicyVerdict {
	r.mu.RLock()
	defer r.mu.RUnlock()

	ipU32 := binary.BigEndian.Uint32(octets[:])
	for _, c := range r.cidrRules {
		if (ipU32 & c.Mask) == c.NetAddr {
			return c.Verdict
		}
	}
	return r.defaultPolicy
}

func (r *PolicyRulesetRouter) ClearCache() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.cache = make(map[string]PolicyVerdict)
}
