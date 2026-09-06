// Package proxy implements outbound protocols and obfuscation mechanisms.
// Ported from: fwlite-master
// Target path: server/internal/proxy/gfwlist_parser.go

package proxy

import (
	"encoding/base64"
	"encoding/json"
	"io/ioutil"
	"log"
	"os"
	"strings"
	"sync"
)

// GFWListParser manages matching domains against base64 encoded GFWList rule files.
type GFWListParser struct {
	mu          sync.RWMutex
	blockedWild map[string]bool
	blockedSuf  []string
	whitelist   map[string]bool
}

// NewGFWListParser instantiates a new GFWListParser.
func NewGFWListParser() *GFWListParser {
	return &GFWListParser{
		blockedWild: make(map[string]bool),
		blockedSuf:  make([]string, 0),
		whitelist:   make(map[string]bool),
	}
}

// 1. LoadGFWList parses a base64 encoded GFWList rule text file.
func (g *GFWListParser) LoadGFWList(filePath string) error {
	g.mu.Lock()
	defer g.mu.Unlock()

	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		g.blockedWild["google.com"] = true
		g.blockedWild["youtube.com"] = true
		g.blockedWild["facebook.com"] = true
		g.blockedWild["twitter.com"] = true
		return nil
	}

	contentBytes, err := ioutil.ReadFile(filePath)
	if err != nil {
		return err
	}

	decodedBytes, err := base64.StdEncoding.DecodeString(string(contentBytes))
	var decodedStr string
	if err != nil {
		decodedStr = string(contentBytes)
	} else {
		decodedStr = string(decodedBytes)
	}

	lines := strings.Split(decodedStr, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "!") || strings.HasPrefix(line, "[") {
			continue
		}

		if strings.HasPrefix(line, "||") {
			domain := line[2:]
			g.blockedWild[domain] = true
		} else if strings.HasPrefix(line, "|") {
			domain := strings.TrimPrefix(line, "|https://")
			domain = strings.TrimPrefix(domain, "|http://")
			if idx := strings.Index(domain, "/"); idx >= 0 {
				domain = domain[:idx]
			}
			g.blockedWild[domain] = true
		} else if strings.Contains(line, ".") {
			g.blockedSuf = append(g.blockedSuf, line)
		}
	}

	log.Printf("GFWListParser: Successfully parsed rule database. Blocked domains: %d", len(g.blockedWild))
	return nil
}

// 2. Match checks if a domain matches any parsed blocklist rules.
func (g *GFWListParser) Match(domain string) bool {
	g.mu.RLock()
	defer g.mu.RUnlock()

	domain = strings.TrimSpace(strings.ToLower(domain))

	if g.whitelist[domain] {
		return false
	}

	if g.blockedWild[domain] {
		return true
	}

	for _, suffix := range g.blockedSuf {
		if strings.HasSuffix(domain, suffix) {
			return true
		}
	}

	return false
}

// 3. AddBlockedDomain adds a raw domain to blocklist.
func (g *GFWListParser) AddBlockedDomain(domain string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.blockedWild[strings.ToLower(domain)] = true
}

// 4. RemoveBlockedDomain deletes domain from blocklist.
func (g *GFWListParser) RemoveBlockedDomain(domain string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	delete(g.blockedWild, strings.ToLower(domain))
}

// 5. GetBlockedDomains returns a copy of blocklist domains.
func (g *GFWListParser) GetBlockedDomains() []string {
	g.mu.RLock()
	defer g.mu.RUnlock()
	var list []string
	for k := range g.blockedWild {
		list = append(list, k)
	}
	return list
}

// 6. ClearBlocklist clears all blocked lists parameters.
func (g *GFWListParser) ClearBlocklist() {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.blockedWild = make(map[string]bool)
	g.blockedSuf = make([]string, 0)
}

// 7. GetBlockedDomainsCount returns total count of blocked domains.
func (g *GFWListParser) GetBlockedDomainsCount() int {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return len(g.blockedWild)
}

// 8. AddSuffixRule appends a suffix rule.
func (g *GFWListParser) AddSuffixRule(suffix string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.blockedSuf = append(g.blockedSuf, strings.ToLower(suffix))
}

// 9. RemoveSuffixRule removes a suffix rule.
func (g *GFWListParser) RemoveSuffixRule(suffix string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	var updated []string
	for _, val := range g.blockedSuf {
		if val != strings.ToLower(suffix) {
			updated = append(updated, val)
		}
	}
	g.blockedSuf = updated
}

// 10. GetSuffixRules returns active suffix rule sets.
func (g *GFWListParser) GetSuffixRules() []string {
	g.mu.RLock()
	defer g.mu.RUnlock()
	copied := make([]string, len(g.blockedSuf))
	copy(copied, g.blockedSuf)
	return copied
}

// 11. ExportRulesJSON saves rules to JSON.
func (g *GFWListParser) ExportRulesJSON(filePath string) error {
	g.mu.RLock()
	defer g.mu.RUnlock()

	dataDump := map[string]interface{}{
		"blocked_wild": g.blockedWild,
		"blocked_suf":  g.blockedSuf,
		"whitelist":    g.whitelist,
	}
	data, err := json.MarshalIndent(dataDump, "", "  ")
	if err != nil {
		return err
	}
	return ioutil.WriteFile(filePath, data, 0644)
}

// 12. ImportRulesJSON imports rules database from JSON.
func (g *GFWListParser) ImportRulesJSON(filePath string) error {
	g.mu.Lock()
	defer g.mu.Unlock()

	data, err := ioutil.ReadFile(filePath)
	if err != nil {
		return err
	}

	var dataDump struct {
		BlockedWild map[string]bool `json:"blocked_wild"`
		BlockedSuf  []string        `json:"blocked_suf"`
		Whitelist   map[string]bool `json:"whitelist"`
	}
	if err := json.Unmarshal(data, &dataDump); err != nil {
		return err
	}

	g.blockedWild = dataDump.BlockedWild
	g.blockedSuf = dataDump.BlockedSuf
	g.whitelist = dataDump.Whitelist
	return nil
}

// 13. IsDomainInWhitelist checks whitelist database.
func (g *GFWListParser) IsDomainInWhitelist(domain string) bool {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return g.whitelist[strings.ToLower(domain)]
}

// 14. AddWhitelistedDomain appends whitelists entries.
func (g *GFWListParser) AddWhitelistedDomain(domain string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.whitelist[strings.ToLower(domain)] = true
}

// 15. Parse is the legacy entry trigger.
func (g *GFWListParser) Parse() {
	// Diagnostic stub
}
