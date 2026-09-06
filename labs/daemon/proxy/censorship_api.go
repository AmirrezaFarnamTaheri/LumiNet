package proxy

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
)

// CensorshipAPI manages the list of censored domains and serves PAC files for browser extensions.
type CensorshipAPI struct {
	mu             sync.RWMutex
	blockedDomains map[string]bool
	socks5Addr     string
}

// NewCensorshipAPI creates a new CensorshipAPI instance.
func NewCensorshipAPI(socks5Addr string) *CensorshipAPI {
	api := &CensorshipAPI{
		blockedDomains: make(map[string]bool),
		socks5Addr:     socks5Addr,
	}

	// Seed with some default domains from censortracker/GFW lists
	api.blockedDomains["youtube.com"] = true
	api.blockedDomains["facebook.com"] = true
	api.blockedDomains["twitter.com"] = true
	api.blockedDomains["instagram.com"] = true
	api.blockedDomains["telegram.org"] = true

	return api
}

// GetCensoredDomainsHandler returns the list of censored domains.
func (a *CensorshipAPI) GetCensoredDomainsHandler(w http.ResponseWriter, r *http.Request) {
	a.mu.RLock()
	defer a.mu.RUnlock()

	domains := make([]string, 0, len(a.blockedDomains))
	for d := range a.blockedDomains {
		domains = append(domains, d)
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(domains)
}

// ReportBlockHandler allows browser extensions to report a newly blocked domain.
func (a *CensorshipAPI) ReportBlockHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Domain string `json:"domain"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	if req.Domain == "" {
		http.Error(w, "Domain cannot be empty", http.StatusBadRequest)
		return
	}

	a.mu.Lock()
	a.blockedDomains[req.Domain] = true
	a.mu.Unlock()

	w.WriteHeader(http.StatusCreated)
	_, _ = w.Write([]byte(`{"status":"success"}`))
}

// GetPacFileHandler serves a Proxy Auto-Config (PAC) file telling the browser when to use the proxy.
func (a *CensorshipAPI) GetPacFileHandler(w http.ResponseWriter, r *http.Request) {
	a.mu.RLock()
	defer a.mu.RUnlock()

	// Generate PAC script
	var domainRules []string
	for d := range a.blockedDomains {
		domainRules = append(domainRules, fmt.Sprintf("dnsDomainIs(host, '%s')", d))
		domainRules = append(domainRules, fmt.Sprintf("shExpMatch(host, '*.%s')", d))
	}

	var pacScript string
	if len(domainRules) > 0 {
		pacScript = fmt.Sprintf(`function FindProxyForURL(url, host) {
    if (%s) {
        return "SOCKS5 %s; DIRECT";
    }
    return "DIRECT";
}`, stringsJoin(domainRules, " || "), a.socks5Addr)
	} else {
		pacScript = `function FindProxyForURL(url, host) {
    return "DIRECT";
}`
	}

	w.Header().Set("Content-Type", "application/x-ns-proxy-autoconfig")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(pacScript))
}

func stringsJoin(slice []string, sep string) string {
	if len(slice) == 0 {
		return ""
	}
	res := slice[0]
	for _, s := range slice[1:] {
		res += sep + s
	}
	return res
}
