package transport

import (
	"fmt"
	"strings"
	"sync"
)

type SniRewriteRule struct {
	OriginalDomain string
	AlteredSNI     string
	ValidSANs      []string
	SkipCertVerify bool
}

type SniHostnameRewriter struct {
	rules          map[string]*SniRewriteRule
	httpRedirects  map[string]string
	totalRewrites  uint64
	mu             sync.RWMutex
}

func NewSniHostnameRewriter() *SniHostnameRewriter {
	return &SniHostnameRewriter{
		rules:         make(map[string]*SniRewriteRule),
		httpRedirects: make(map[string]string),
	}
}

func (r *SniHostnameRewriter) AddSniRule(original, altered string, sans []string, skipVerify bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	key := strings.Trim(strings.ToLower(original), ".")
	var cleanSans []string
	for _, s := range sans {
		cleanSans = append(cleanSans, strings.ToLower(s))
	}
	r.rules[key] = &SniRewriteRule{
		OriginalDomain: key,
		AlteredSNI:     strings.Trim(strings.ToLower(altered), "."),
		ValidSANs:      cleanSans,
		SkipCertVerify: skipVerify,
	}
}

func (r *SniHostnameRewriter) AddHttpRedirect(prefix, targetURL string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.httpRedirects[prefix] = targetURL
}

func (r *SniHostnameRewriter) ResolveSNI(domain string) (string, *SniRewriteRule) {
	r.mu.Lock()
	defer r.mu.Unlock()

	key := strings.Trim(strings.ToLower(domain), ".")
	if rule, ok := r.rules[key]; ok {
		r.totalRewrites++
		return rule.AlteredSNI, rule
	}
	return domain, nil
}

func (r *SniHostnameRewriter) CheckSanValidity(rule *SniRewriteRule, presentedSANs []string) bool {
	if rule.SkipCertVerify {
		return true
	}
	for _, valid := range rule.ValidSANs {
		for _, pres := range presentedSANs {
			presLower := strings.ToLower(pres)
			if strings.HasPrefix(valid, "*.") {
				suffix := strings.TrimPrefix(valid, "*.")
				if strings.HasSuffix(presLower, suffix) {
					return true
				}
			} else if presLower == valid {
				return true
			}
		}
	}
	return false
}

func (r *SniHostnameRewriter) CheckHttpRedirect(url string) string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	for prefix, target := range r.httpRedirects {
		if strings.HasPrefix(url, prefix) {
			return fmt.Sprintf("https://%s", target)
		}
	}
	return ""
}
