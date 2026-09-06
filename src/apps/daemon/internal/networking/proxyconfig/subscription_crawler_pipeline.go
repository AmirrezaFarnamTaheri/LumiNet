package proxyconfig

import (
	"encoding/base64"
	"sort"
	"strings"
)

type CrawlSource struct {
	URL            string `json:"url"`
	IntervalSecs   int64  `json:"interval_secs"`
	LastCrawl      int64  `json:"last_crawl"`
	TotalHarvested int    `json:"total_harvested"`
	Enabled        bool   `json:"enabled"`
}

type SubscriptionCrawlerPipeline struct {
	sources   map[string]*CrawlSource
	harvested map[string]struct{}
}

func NewSubscriptionCrawlerPipeline() *SubscriptionCrawlerPipeline {
	return &SubscriptionCrawlerPipeline{
		sources:   make(map[string]*CrawlSource),
		harvested: make(map[string]struct{}),
	}
}

func (s *SubscriptionCrawlerPipeline) AddSource(url string, intervalSecs int64) {
	if intervalSecs < 60 {
		intervalSecs = 60
	}
	s.sources[url] = &CrawlSource{
		URL:          url,
		IntervalSecs: intervalSecs,
		LastCrawl:    0,
		Enabled:      true,
	}
}

func (s *SubscriptionCrawlerPipeline) DispatchPendingSources(currentTime int64) []string {
	var toCrawl []string
	for _, src := range s.sources {
		if src.Enabled && (src.LastCrawl == 0 || currentTime >= src.LastCrawl+src.IntervalSecs) {
			src.LastCrawl = currentTime
			toCrawl = append(toCrawl, src.URL)
		}
	}
	return toCrawl
}

func (s *SubscriptionCrawlerPipeline) IngestCrawlContent(sourceURL, rawContent string) int {
	trimmed := strings.TrimSpace(rawContent)
	decodedBytes, err := base64.StdEncoding.DecodeString(trimmed)
	decodedText := trimmed
	if err == nil {
		decodedText = string(decodedBytes)
	}

	count := 0
	lines := strings.Split(decodedText, "\n")
	for _, line := range lines {
		l := strings.TrimSpace(line)
		if strings.HasPrefix(l, "ss://") ||
			strings.HasPrefix(l, "vmess://") ||
			strings.HasPrefix(l, "vless://") ||
			strings.HasPrefix(l, "trojan://") ||
			strings.HasPrefix(l, "hysteria2://") ||
			strings.HasPrefix(l, "tuic://") {
			if _, exists := s.harvested[l]; !exists {
				s.harvested[l] = struct{}{}
				count++
			}
		}
	}

	if src, ok := s.sources[sourceURL]; ok {
		src.TotalHarvested += count
	}

	return count
}

func (s *SubscriptionCrawlerPipeline) GetHarvestedProxies() []string {
	var list []string
	for p := range s.harvested {
		list = append(list, p)
	}
	sort.Strings(list)
	return list
}

func (s *SubscriptionCrawlerPipeline) TotalHarvestedCount() int {
	return len(s.harvested)
}
