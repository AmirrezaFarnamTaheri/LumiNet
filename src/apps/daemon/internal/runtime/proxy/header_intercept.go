package proxy

import (
	"strings"
	"sync"
)

type InterceptRule struct {
	HeaderName         string `json:"header_name"`
	HeaderValueExact   string `json:"header_value_exact"`
	TargetLocalAddress string `json:"target_local_address"`
}

type HeaderInterceptRouter struct {
	mu    sync.RWMutex
	rules []InterceptRule
}

func NewHeaderInterceptRouter() *HeaderInterceptRouter {
	return &HeaderInterceptRouter{
		rules: make([]InterceptRule, 0),
	}
}

func (r *HeaderInterceptRouter) AddRule(name, val, target string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.rules = append(r.rules, InterceptRule{
		HeaderName:         strings.ToLower(name),
		HeaderValueExact:   val,
		TargetLocalAddress: target,
	})
}

func (r *HeaderInterceptRouter) EvaluateHeaders(headers map[string]string) (string, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	for _, rule := range r.rules {
		for k, v := range headers {
			if strings.ToLower(k) == rule.HeaderName && v == rule.HeaderValueExact {
				return rule.TargetLocalAddress, true
			}
		}
	}
	return "", false
}
