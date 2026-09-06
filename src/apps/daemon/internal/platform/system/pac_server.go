//
// PAC (Proxy Auto-Configuration) file generator and HTTP server.
// Generates JavaScript PAC functions from route rules and serves them via HTTP.

package system

import (
	"fmt"
	"net/http"
	"strings"
	"sync"
	"text/template"
)

// PACRule defines a single proxy routing rule.
type PACRule struct {
	// Pattern is a domain or subnet to match (e.g. "*.google.com", "192.168.0.0/16").
	Pattern string
	// Proxy is the proxy to use (e.g. "SOCKS5 127.0.0.1:1080", "DIRECT").
	Proxy string
}

// PACServer generates and serves a PAC file via HTTP.
type PACServer struct {
	mu     sync.RWMutex
	rules  []PACRule
	def    string
	mux    *http.ServeMux
	cached string
	dirty  bool
}

// NewPACServer creates a PAC server with the given default proxy string.
// defaultProxy examples: "DIRECT", "SOCKS5 127.0.0.1:1080".
func NewPACServer(defaultProxy string) *PACServer {
	s := &PACServer{
		def:   defaultProxy,
		mux:   http.NewServeMux(),
		dirty: true,
	}
	s.mux.HandleFunc("/proxy.pac", s.handlePAC)
	s.mux.HandleFunc("/", s.handlePAC)
	return s
}

// AddRule appends a routing rule.
func (s *PACServer) AddRule(pattern, proxy string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.rules = append(s.rules, PACRule{Pattern: pattern, Proxy: proxy})
	s.dirty = true
}

// SetDefault updates the fallback proxy.
func (s *PACServer) SetDefault(proxy string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.def = proxy
	s.dirty = true
}

// Generate renders the current PAC JavaScript content.
func (s *PACServer) Generate() (string, error) {
	s.mu.RLock()
	if !s.dirty {
		cached := s.cached
		s.mu.RUnlock()
		return cached, nil
	}
	rules := make([]PACRule, len(s.rules))
	copy(rules, s.rules)
	def := s.def
	s.mu.RUnlock()

	funcMap := template.FuncMap{
		"patternToJS": patternToJS,
	}
	tmpl := template.Must(template.New("pac").Funcs(funcMap).Parse(`
function FindProxyForURL(url, host) {
{{- range .Rules}}
  if ({{patternToJS .Pattern}}) { return "{{.Proxy}}"; }
{{- end}}
  return "{{.Default}}";
}
`))

	var sb strings.Builder
	data := struct {
		Rules   []PACRule
		Default string
	}{rules, def}
	if err := tmpl.Execute(&sb, data); err != nil {
		return "", fmt.Errorf("pac_server: render template: %w", err)
	}
	content := sb.String()

	s.mu.Lock()
	s.cached = content
	s.dirty = false
	s.mu.Unlock()

	return content, nil
}

// ServeHTTP implements http.Handler.
func (s *PACServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mux.ServeHTTP(w, r)
}

func (s *PACServer) handlePAC(w http.ResponseWriter, r *http.Request) {
	content, err := s.Generate()
	if err != nil {
		http.Error(w, "PAC generation failed", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/x-ns-proxy-autoconfig")
	w.Header().Set("Cache-Control", "no-cache")
	fmt.Fprint(w, content)
}

// patternToJS converts a domain or CIDR pattern to a PAC JavaScript expression.
func patternToJS(pattern string) string {
	if strings.Contains(pattern, "/") {
		// CIDR: isInNet(host, "192.168.0.0", "255.255.0.0")
		parts := strings.SplitN(pattern, "/", 2)
		return fmt.Sprintf(`isInNet(host, "%s", cidrToMask("%s"))`, parts[0], parts[1])
	}
	if strings.HasPrefix(pattern, "*.") {
		// Wildcard subdomain
		domain := strings.TrimPrefix(pattern, "*.")
		return fmt.Sprintf(`dnsDomainIs(host, ".%s") || host == "%s"`, domain, domain)
	}
	return fmt.Sprintf(`host == "%s"`, pattern)
}
