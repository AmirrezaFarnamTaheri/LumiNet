package sub

import (
	"context"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"
)

func FetchLinksFromTelegramChannel(ctx context.Context, channel string) ([]string, error) {
	if channel == "" {
		return nil, fmt.Errorf("channel username cannot be empty")
	}
	var targetURL string
	if strings.HasPrefix(channel, "http://") || strings.HasPrefix(channel, "https://") {
		targetURL = channel
	} else {
		channel = strings.TrimPrefix(channel, "@")
		targetURL = fmt.Sprintf("https://t.me/s/%s", channel)
	}

	req, err := http.NewRequestWithContext(ctx, "GET", targetURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch telegram page: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("telegram returned status %d", resp.StatusCode)
	}

	bodyBytes, err := readBoundedSubscriptionBody(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read telegram page: %w", err)
	}
	body := string(bodyBytes)

	// Clean HTML
	body = regexp.MustCompile(`<[^>]+>`).ReplaceAllString(body, " ")

	var rawLinks []string

	// Define Shin-TG patterns for extraction
	patterns := []string{
		`(?:tg://proxy|t\.me/proxy)\?[^\s"'<>]+`,
		`ss://[^\s"'<>]+`,
		`ss2022://[^\s"'<>]+`,
		`socks5://[^\s"'<>]+`,
		`socks://[^\s"'<>]+`,
		`wg://[^\s"'<>]+`,
		`wireguard://[^\s"'<>]+`,
		`trojan://[^\s"'<>]+`,
		`vmess://[^\s"'<>]+`,
		`vless://[^\s"'<>]+`,
		`tuic://[^\s"'<>]+`,
		`hysteria://[^\s"'<>]+`,
		`hy2://[^\s"'<>]+`,
		`juicity://[^\s"'<>]+`,
		`dnst://[^\s"'<>]+`,
		`dnstt://[^\s"'<>]+`,
		`vaydns://[^\s"'<>]+`,
		`slipstream://[^\s"'<>]+`,
		`stormdns://[^\s"'<>]+`,
		`masterdns://[^\s"'<>]+`,
		`masterdnsvpn://[^\s"'<>]+`,
		`noizdns://[^\s"'<>]+`,
		`slowdns://[^\s"'<>]+`,
		`ssh-dns://[^\s"'<>]+`,
		`dns-ssh://[^\s"'<>]+`,
		`ssh-over-dns://[^\s"'<>]+`,
	}

	seen := make(map[string]bool)

	for _, p := range patterns {
		re := regexp.MustCompile(p)
		matches := re.FindAllString(body, -1)
		for _, match := range matches {
			match = strings.ReplaceAll(match, "&amp;", "&")
			// Remove common ellipses truncation artifacts
			if strings.Contains(match, "…") {
				continue
			}
			// Trim trailing punctuation and brackets (including Farsi characters)
			match = regexp.MustCompile(`[),.!؟?؛\]}\s]+$`).ReplaceAllString(match, "")
			if !seen[match] {
				seen[match] = true
				rawLinks = append(rawLinks, match)
			}
		}
	}

	if len(rawLinks) == 0 {
		return nil, fmt.Errorf("no proxy links found in channel")
	}

	return rawLinks, nil
}
