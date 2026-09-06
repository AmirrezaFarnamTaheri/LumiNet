// Package isppresets provides ISP-specific IP range presets for CDN scanning.
// Ported from RKh-CF-Scanner's ip-ranges/ directory.
//
// Contains Cloudflare-accessible IP ranges organized by ISP,
// useful for finding clean IPs that bypass CDN restrictions.
package isppresets

import (
	"embed"
	"io/fs"
	"strings"
)

//go:embed ranges/*.txt
var rangeFS embed.FS

// ISPPreset represents an ISP's IP range configuration.
type ISPPreset struct {
	Name     string   `json:"name"`
	Region   string   `json:"region"` // "iran" or "international"
	CIDRs    []string `json:"cidrs"`
}

// GetAllPresets loads all ISP presets from embedded data.
func GetAllPresets() ([]ISPPreset, error) {
	var presets []ISPPreset

	// Load Iran presets
	iranPresets, err := loadPresetsFromDir("ranges/iran")
	if err == nil {
		presets = append(presets, iranPresets...)
	}

	// Load international presets
	intlPresets, err := loadPresetsFromDir("ranges/international")
	if err == nil {
		presets = append(presets, intlPresets...)
	}

	return presets, nil
}

// GetIranPresets loads only Iranian ISP presets.
func GetIranPresets() ([]ISPPreset, error) {
	return loadPresetsFromDir("ranges/iran")
}

// GetInternationalPresets loads only international ISP presets.
func GetInternationalPresets() ([]ISPPreset, error) {
	return loadPresetsFromDir("ranges/international")
}

// GetPresetByName returns a specific ISP preset by name.
func GetPresetByName(name string) (*ISPPreset, error) {
	presets, err := GetAllPresets()
	if err != nil {
		return nil, err
	}
	for _, p := range presets {
		if strings.EqualFold(p.Name, name) {
			return &p, nil
		}
	}
	return nil, nil
}

func loadPresetsFromDir(dir string) ([]ISPPreset, error) {
	var presets []ISPPreset

	entries, err := fs.ReadDir(rangeFS, dir)
	if err != nil {
		return nil, err
	}

	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".txt") {
			continue
		}

		data, err := fs.ReadFile(rangeFS, dir+"/"+entry.Name())
		if err != nil {
			continue
		}

		name := strings.TrimSuffix(entry.Name(), ".txt")
		region := "international"
		if strings.Contains(dir, "iran") {
			region = "iran"
		}

		var cidrs []string
		for _, line := range strings.Split(string(data), "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			// Strip trailing * (marks uncertain ranges)
			line = strings.TrimRight(line, "*")
			line = strings.TrimSpace(line)
			if line != "" {
				cidrs = append(cidrs, line)
			}
		}

		if len(cidrs) > 0 {
			presets = append(presets, ISPPreset{
				Name:   name,
				Region: region,
				CIDRs:  cidrs,
			})
		}
	}

	return presets, nil
}

// CloudflareOfficialRanges returns Cloudflare's official IPv4 CIDR ranges.
func CloudflareOfficialRanges() []string {
	return []string{
		"1.0.0.0/24", "1.1.1.0/24",
		"104.16.0.0/13", "104.24.0.0/14",
		"108.162.192.0/18", "131.0.72.0/22",
		"141.101.64.0/18", "172.64.0.0/13",
		"173.245.48.0/20", "188.114.96.0/20",
		"190.93.240.0/20", "197.234.240.0/22",
		"198.41.128.0/17",
	}
}

// CloudflareOfficialRangesIPv6 returns Cloudflare's official IPv6 CIDR ranges.
func CloudflareOfficialRangesIPv6() []string {
	return []string{
		"2400:cb00::/32",
		"2606:4700::/32",
		"2803:f800::/32",
		"2405:b500::/32",
		"2405:8100::/32",
		"2a06:98c0::/29",
		"2c0f:f248::/32",
	}
}

// FastlyRanges returns Fastly CDN IPv4 CIDR ranges.
func FastlyRanges() []string {
	return []string{
		"151.101.0.0/22",
		"199.232.0.0/22",
		"23.235.32.0/24",
		"23.235.47.0/24",
		"199.27.72.0/24",
		"199.27.79.0/24",
	}
}

// AkamaiRanges returns Akamai CDN IPv4 CIDR ranges.
func AkamaiRanges() []string {
	return []string{
		"23.0.0.0/12",
		"23.32.0.0/11",
		"23.64.0.0/14",
		"23.72.0.0/13",
		"104.64.0.0/10",
		"184.24.0.0/13",
		"184.50.0.0/15",
		"184.84.0.0/14",
	}
}

// CommonSNIs returns common SNI values for CDN probing.
func CommonSNIs() []string {
	return []string{
		"www.speedtest.net",
		"www.google.com",
		"www.microsoft.com",
		"www.apple.com",
		"www.cloudflare.com",
		"www.github.com",
		"www.youtube.com",
		"www.facebook.com",
		"www.twitter.com",
		"www.instagram.com",
		"www.wikipedia.org",
		"www.amazon.com",
		"www.netflix.com",
		"www.spotify.com",
		"www.reddit.com",
		"cdnjs.cloudflare.com",
		"one.one.one.one",
		"dns.google",
	}
}

// CloudflarePorts returns commonly used Cloudflare-compatible ports.
func CloudflarePorts() []int {
	return []int{
		80, 443,
		2052, 2053, 2082, 2083, 2086, 2087, 2095, 2096,
		8080, 8443, 8880,
	}
}
