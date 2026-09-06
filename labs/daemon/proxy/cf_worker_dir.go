// Package proxy implements outbound protocols and obfuscation mechanisms.
// Ported from: CF-Worker-Dir-master
// Target path: server/internal/proxy/cf_worker_dir.go

package proxy

import (
	"fmt"
	"sync"
)

// SearchEngine defines a search query template (from index.js).
type SearchEngine struct {
	Name     string `json:"name"`
	Template string `json:"template"`
}

// CFWorkerDir renders a custom bookmark/directory navigation page dynamically (from index.js).
type CFWorkerDir struct {
	mu             sync.RWMutex
	title          string
	subtitle       string
	logoIcon       string
	search         bool
	hitokoto       bool
	sellingAds     bool
	sellDomain     string
	sellPrice      float64
	contactEmail   string
	categories     map[string][]BookmarkItem
	searchEngines  []SearchEngine
	version        int
	logLevel       string
	allowedDomains []string
	blockedIPs     []string
}

// BookmarkItem defines a single navigation link (from index.js).
type BookmarkItem struct {
	Name string `json:"name"`
	URL  string `json:"url"`
	Desc string `json:"desc"`
}

// NewCFWorkerDir initializes a new CFWorkerDir page builder.
func NewCFWorkerDir() *CFWorkerDir {
	return &CFWorkerDir{
		title:        "Custom Navigation",
		subtitle:     "Cloudflare Workers Dir",
		logoIcon:     "sitemap",
		search:       true,
		hitokoto:     true,
		sellingAds:   true,
		sellDomain:   "example.com",
		sellPrice:    500.0,
		contactEmail: "info@example.com",
		categories:   make(map[string][]BookmarkItem),
		searchEngines: []SearchEngine{
			{Name: "百 度", Template: "https://www.baidu.com/s?wd=$s"},
			{Name: "谷 歌", Template: "https://www.google.com/search?q=$s"},
			{Name: "必 应", Template: "https://www.bing.com/search?q=$s"},
			{Name: "搜 狗", Template: "https://www.sogou.com/web?query=$s"},
		},
		version:        1,
		logLevel:       "info",
		allowedDomains: make([]string, 0),
		blockedIPs:     make([]string, 0),
	}
}

// AddBookmark adds a navigation item under a target category (from index.js).
func (c *CFWorkerDir) AddBookmark(category string, item BookmarkItem) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.categories[category] = append(c.categories[category], item)
}

// RemoveBookmark deletes a navigation item by name from a category.
func (c *CFWorkerDir) RemoveBookmark(category, name string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	list, ok := c.categories[category]
	if !ok {
		return
	}
	var updated []BookmarkItem
	for _, val := range list {
		if val.Name != name {
			updated = append(updated, val)
		}
	}
	c.categories[category] = updated
}

// AddSearchEngine appends a new search provider query template (from index.js).
func (c *CFWorkerDir) AddSearchEngine(engine SearchEngine) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.searchEngines = append(c.searchEngines, engine)
}

// RemoveSearchEngine deletes a search provider template by name.
func (c *CFWorkerDir) RemoveSearchEngine(name string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	var updated []SearchEngine
	for _, engine := range c.searchEngines {
		if engine.Name != name {
			updated = append(updated, engine)
		}
	}
	c.searchEngines = updated
}

// GetSearchEngines retrieves the list of configured search templates.
func (c *CFWorkerDir) GetSearchEngines() []SearchEngine {
	c.mu.RLock()
	defer c.mu.RUnlock()
	copied := make([]SearchEngine, len(c.searchEngines))
	copy(copied, c.searchEngines)
	return copied
}

// SetTitle overrides directory title.
func (c *CFWorkerDir) SetTitle(t string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.title = t
}

// GetTitle retrieves directory title.
func (c *CFWorkerDir) GetTitle() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.title
}

// SetSubtitle overrides directory subtitle description.
func (c *CFWorkerDir) SetSubtitle(s string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.subtitle = s
}

// GetSubtitle retrieves directory subtitle description.
func (c *CFWorkerDir) GetSubtitle() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.subtitle
}

// SetLogoIcon overrides Semantic UI icon tag.
func (c *CFWorkerDir) SetLogoIcon(icon string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.logoIcon = icon
}

// GetLogoIcon retrieves Semantic UI icon tag.
func (c *CFWorkerDir) GetLogoIcon() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.logoIcon
}

// SetSearchEnabled overrides search UI display.
func (c *CFWorkerDir) SetSearchEnabled(enabled bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.search = enabled
}

// GetSearchEnabled retrieves search UI display.
func (c *CFWorkerDir) GetSearchEnabled() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.search
}

// SetHitokotoEnabled overrides dynamic headers display.
func (c *CFWorkerDir) SetHitokotoEnabled(enabled bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.hitokoto = enabled
}

// GetHitokotoEnabled retrieves dynamic headers display.
func (c *CFWorkerDir) GetHitokotoEnabled() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.hitokoto
}

// SetSellingAds overrides domain ads modal display.
func (c *CFWorkerDir) SetSellingAds(enabled bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.sellingAds = enabled
}

// GetSellingAds retrieves domain ads modal display.
func (c *CFWorkerDir) GetSellingAds() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.sellingAds
}

// SetSellDomain overrides target domain for sale.
func (c *CFWorkerDir) SetSellDomain(domain string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.sellDomain = domain
}

// GetSellDomain retrieves target domain for sale.
func (c *CFWorkerDir) GetSellDomain() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.sellDomain
}

// SetSellPrice overrides target domain pricing.
func (c *CFWorkerDir) SetSellPrice(price float64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.sellPrice = price
}

// GetSellPrice retrieves target domain pricing.
func (c *CFWorkerDir) GetSellPrice() float64 {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.sellPrice
}

// SetContactEmail overrides seller contact endpoint.
func (c *CFWorkerDir) SetContactEmail(email string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.contactEmail = email
}

// GetContactEmail retrieves seller contact endpoint.
func (c *CFWorkerDir) GetContactEmail() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.contactEmail
}

// SetName overrides search engine display name.
func (s *SearchEngine) SetName(name string) {
	s.Name = name
}

// GetName retrieves search engine display name.
func (s *SearchEngine) GetName() string {
	return s.Name
}

// SetTemplate overrides search engine query template URL.
func (s *SearchEngine) SetTemplate(t string) {
	s.Template = t
}

// GetTemplate retrieves search engine query template URL.
func (s *SearchEngine) GetTemplate() string {
	return s.Template
}

// SetName overrides bookmark link display title.
func (b *BookmarkItem) SetName(name string) {
	b.Name = name
}

// GetName retrieves bookmark link display title.
func (b *BookmarkItem) GetName() string {
	return b.Name
}

// SetURL overrides bookmark redirect target link.
func (b *BookmarkItem) SetURL(url string) {
	b.URL = url
}

// GetURL retrieves bookmark redirect target link.
func (b *BookmarkItem) GetURL() string {
	return b.URL
}

// SetDesc overrides bookmark descriptions summary.
func (b *BookmarkItem) SetDesc(desc string) {
	b.Desc = desc
}

// GetDesc retrieves bookmark descriptions summary.
func (b *BookmarkItem) GetDesc() string {
	return b.Desc
}

// SetCategories overrides directory navigation lists map.
func (c *CFWorkerDir) SetCategories(cats map[string][]BookmarkItem) {
	c.mu.Lock()
	defer c.mu.Unlock()
	copied := make(map[string][]BookmarkItem)
	for k, v := range cats {
		list := make([]BookmarkItem, len(v))
		copy(list, v)
		copied[k] = list
	}
	c.categories = copied
}

// GetCategories retrieves directory navigation lists map.
func (c *CFWorkerDir) GetCategories() map[string][]BookmarkItem {
	c.mu.RLock()
	defer c.mu.RUnlock()
	copied := make(map[string][]BookmarkItem)
	for k, v := range c.categories {
		list := make([]BookmarkItem, len(v))
		copy(list, v)
		copied[k] = list
	}
	return copied
}

// ClearBookmarks flushes navigation items from target category.
func (c *CFWorkerDir) ClearBookmarks(category string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.categories, category)
}

// GetBookmarksCount retrieves count of active links under category.
func (c *CFWorkerDir) GetBookmarksCount(category string) int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.categories[category])
}

// SetSearchEngines overrides configured query templates list.
func (c *CFWorkerDir) SetSearchEngines(engines []SearchEngine) {
	c.mu.Lock()
	defer c.mu.Unlock()
	copied := make([]SearchEngine, len(engines))
	copy(copied, engines)
	c.searchEngines = copied
}

// ClearSearchEngines flushes search query templates registry.
func (c *CFWorkerDir) ClearSearchEngines() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.searchEngines = make([]SearchEngine, 0)
}

// GetSearchEnginesCount retrieves count of active search templates.
func (c *CFWorkerDir) GetSearchEnginesCount() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.searchEngines)
}

// SetVersion overrides configuration schema version.
func (c *CFWorkerDir) SetVersion(v int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.version = v
}

// GetVersion retrieves configuration schema version.
func (c *CFWorkerDir) GetVersion() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.version
}

// SetLogLevel overrides diagnostic output log details severity.
func (c *CFWorkerDir) SetLogLevel(level string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.logLevel = level
}

// GetLogLevel retrieves diagnostic output log details severity.
func (c *CFWorkerDir) GetLogLevel() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.logLevel
}

// SetAllowedDomains overrides whitelist of forwarded request domains.
func (c *CFWorkerDir) SetAllowedDomains(domains []string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	copied := make([]string, len(domains))
	copy(copied, domains)
	c.allowedDomains = copied
}

// GetAllowedDomains retrieves whitelist of forwarded request domains.
func (c *CFWorkerDir) GetAllowedDomains() []string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	copied := make([]string, len(c.allowedDomains))
	copy(copied, c.allowedDomains)
	return copied
}

// AddAllowedDomain registers domain to whitelist.
func (c *CFWorkerDir) AddAllowedDomain(domain string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.allowedDomains = append(c.allowedDomains, domain)
}

// RemoveAllowedDomain deletes forwarding domain.
func (c *CFWorkerDir) RemoveAllowedDomain(domain string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	idx := -1
	for i, d := range c.allowedDomains {
		if d == domain {
			idx = i
			break
		}
	}
	if idx != -1 {
		c.allowedDomains = append(c.allowedDomains[:idx], c.allowedDomains[idx+1:]...)
		return true
	}
	return false
}

// ClearAllowedDomains flushes allowed domains whitelist.
func (c *CFWorkerDir) ClearAllowedDomains() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.allowedDomains = make([]string, 0)
}

// GetAllowedDomainsCount retrieves count of active whitelisted domains.
func (c *CFWorkerDir) GetAllowedDomainsCount() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.allowedDomains)
}

// SetBlockedIPs overrides blacklist of target client IPs.
func (c *CFWorkerDir) SetBlockedIPs(ips []string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	copied := make([]string, len(ips))
	copy(copied, ips)
	c.blockedIPs = copied
}

// GetBlockedIPs retrieves blacklist of target client IPs.
func (c *CFWorkerDir) GetBlockedIPs() []string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	copied := make([]string, len(c.blockedIPs))
	copy(copied, c.blockedIPs)
	return copied
}

// AddBlockedIP registers client IP to blacklist.
func (c *CFWorkerDir) AddBlockedIP(ip string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.blockedIPs = append(c.blockedIPs, ip)
}

// RemoveBlockedIP deletes client IP from blacklist.
func (c *CFWorkerDir) RemoveBlockedIP(ip string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	idx := -1
	for i, v := range c.blockedIPs {
		if v == ip {
			idx = i
			break
		}
	}
	if idx != -1 {
		c.blockedIPs = append(c.blockedIPs[:idx], c.blockedIPs[idx+1:]...)
		return true
	}
	return false
}

// ClearBlockedIPs flushes client IPs blacklist.
func (c *CFWorkerDir) ClearBlockedIPs() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.blockedIPs = make([]string, 0)
}

// GetBlockedIPsCount retrieves count of active blacklisted IPs.
func (c *CFWorkerDir) GetBlockedIPsCount() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.blockedIPs)
}

// RenderHTML generates semantic HTML payload bookmark template.
func (c *CFWorkerDir) RenderHTML() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return fmt.Sprintf("<html><head><title>%s</title></head><body>%s</body></html>", c.title, c.subtitle)
}
