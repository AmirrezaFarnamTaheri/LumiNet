package safety

import (
	"strings"
	"sync"
)

type IdentitySession struct {
	Email  string   `json:"email"`
	Domain string   `json:"domain"`
	Groups []string `json:"groups"`
}

type RoutePolicy struct {
	PathPrefix     string   `json:"path_prefix"`
	AllowedDomains []string `json:"allowed_domains"`
	RequiredGroups []string `json:"required_groups"`
}

type IdentityPolicyEvaluator struct {
	mu       sync.RWMutex
	policies []RoutePolicy
}

func NewIdentityPolicyEvaluator() *IdentityPolicyEvaluator {
	return &IdentityPolicyEvaluator{
		policies: make([]RoutePolicy, 0),
	}
}

func (e *IdentityPolicyEvaluator) AddPolicy(p RoutePolicy) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.policies = append(e.policies, p)
}

func (e *IdentityPolicyEvaluator) IsAuthorized(path string, sess *IdentitySession) bool {
	e.mu.RLock()
	defer e.mu.RUnlock()

	if sess == nil {
		return false
	}

	for _, policy := range e.policies {
		if strings.HasPrefix(path, policy.PathPrefix) {
			// Check domain
			if len(policy.AllowedDomains) > 0 {
				matchedDomain := false
				for _, d := range policy.AllowedDomains {
					if d == sess.Domain {
						matchedDomain = true
						break
					}
				}
				if !matchedDomain {
					return false
				}
			}

			// Check groups
			if len(policy.RequiredGroups) > 0 {
				hasGroup := false
				for _, reqG := range policy.RequiredGroups {
					for _, userG := range sess.Groups {
						if reqG == userG {
							hasGroup = true
							break
						}
					}
					if hasGroup {
						break
					}
				}
				if !hasGroup {
					return false
				}
			}

			return true
		}
	}
	return false
}
