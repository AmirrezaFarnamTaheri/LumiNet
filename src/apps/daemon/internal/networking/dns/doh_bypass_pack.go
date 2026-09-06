// SPDX-License-Identifier: MIT
//
// Embedded DoH-bypass blocklist pack (R3 roadmap activation). The asset
// ships in blocklist_packs/doh_bypass.txt (AdGuard-compatible plain
// domain list); embedding makes it available to the DNS cluster with no
// runtime download, while LoadDoHBypassPack parses it into a domain set.

package dns

import (
	_ "embed"
	"sort"
	"strings"
)

//go:embed blocklist_packs/doh_bypass.txt
var dohBypassPackRaw string

// LoadDoHBypassPack parses the embedded pack. Comment (#) and blank lines
// are skipped; every other line is treated as one exact domain. Returns
// the sorted unique domain list and the number of skipped lines.
func LoadDoHBypassPack() (domains []string, skipped int) {
	seen := make(map[string]struct{})
	for _, raw := range strings.Split(dohBypassPackRaw, "\n") {
		line := strings.TrimSpace(raw)
		line = strings.TrimSuffix(line, "\r")
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if _, ok := seen[line]; ok {
			skipped++
			continue
		}
		seen[line] = struct{}{}
		domains = append(domains, strings.ToLower(line))
	}
	sort.Strings(domains)
	return domains, skipped
}
