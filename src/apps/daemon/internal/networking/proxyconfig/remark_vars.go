// SPDX-License-Identifier: MIT
// Dynamic Node Remark Template Variable Interpolator
// Enables operator and client subscription node display names to dynamically
// display traffic quota, days remaining, protocol, and usage percentage while
// pruning unlimited token segments.

package proxyconfig

import (
	"fmt"
	"regexp"
	"strings"
	"time"
)

// RemarkContext carries the per-client data interpolated into remark templates.
type RemarkContext struct {
	Email        string
	Protocol     string
	Transport    string
	Security     string
	InboundTag   string
	TrafficUsed  int64
	TrafficTotal int64 // 0 or negative means unlimited
	ExpiryTime   int64 // Unix timestamp in seconds, <= 0 means unlimited
}

var remarkVarRe = regexp.MustCompile(`\{\{([A-Z_]+)\}\}`)

var uiTokenMap = map[string]string{
	"EMAIL":            "EMAIL",
	"DATA_USAGE":       "TRAFFIC_USED",
	"TRAFFIC_USED":     "TRAFFIC_USED",
	"DATA_LEFT":        "TRAFFIC_LEFT",
	"TRAFFIC_LEFT":     "TRAFFIC_LEFT",
	"DATA_LIMIT":       "TRAFFIC_TOTAL",
	"TRAFFIC_TOTAL":    "TRAFFIC_TOTAL",
	"DAYS_LEFT":        "DAYS_LEFT",
	"EXPIRE_DATE":      "EXPIRE_DATE",
	"STATUS_EMOJI":     "STATUS_EMOJI",
	"USAGE_PERCENTAGE": "USAGE_PERCENTAGE",
	"PROTOCOL":         "PROTOCOL",
	"TRANSPORT":        "TRANSPORT",
	"SECURITY":         "SECURITY",
	"INBOUND":          "INBOUND",
}

var unlimitedDropTokens = map[string]bool{
	"TRAFFIC_LEFT":  true,
	"TRAFFIC_TOTAL": true,
	"DAYS_LEFT":     true,
}

// FormatBytes formats a byte count into a human-readable string.
func FormatBytes(b int64) string {
	const (
		kb = 1024
		mb = kb * 1024
		gb = mb * 1024
		tb = gb * 1024
	)
	if b < 0 {
		return "0 B"
	}
	switch {
	case b >= tb:
		return fmt.Sprintf("%.2f TB", float64(b)/float64(tb))
	case b >= gb:
		return fmt.Sprintf("%.2f GB", float64(b)/float64(gb))
	case b >= mb:
		return fmt.Sprintf("%.2f MB", float64(b)/float64(mb))
	case b >= kb:
		return fmt.Sprintf("%.2f KB", float64(b)/float64(kb))
	default:
		return fmt.Sprintf("%d B", b)
	}
}

// TranslateUISingleBrackets translates user single-brace {TOKEN} into internal {{TOKEN}}.
func TranslateUISingleBrackets(template string) string {
	singleTokenRe := regexp.MustCompile(`\{([A-Z_]+)\}`)
	return singleTokenRe.ReplaceAllStringFunc(template, func(m string) string {
		name := strings.Trim(m, "{}")
		if mapped, ok := uiTokenMap[name]; ok {
			return "{{" + mapped + "}}"
		}
		return m
	})
}

// ExpandRemarkTemplate evaluates template tokens using the provided RemarkContext.
// Pipe-separated segments ("|") that contain only unlimited values are pruned.
func ExpandRemarkTemplate(template string, ctx RemarkContext) string {
	if template == "" {
		return ""
	}

	normalized := TranslateUISingleBrackets(template)
	segments := strings.Split(normalized, "|")
	var evaluatedSegments []string

	isUnlimitedTraffic := ctx.TrafficTotal <= 0
	isUnlimitedExpiry := ctx.ExpiryTime <= 0
	nowUnix := time.Now().Unix()

	for _, seg := range segments {
		trimmedSeg := strings.TrimSpace(seg)
		if trimmedSeg == "" {
			continue
		}

		// Check if segment only carries dropped tokens when unlimited
		tokens := remarkVarRe.FindAllStringSubmatch(seg, -1)
		allUnlimitedTokens := len(tokens) > 0
		for _, tok := range tokens {
			tokName := tok[1]
			switch tokName {
			case "TRAFFIC_LEFT", "TRAFFIC_TOTAL":
				if !isUnlimitedTraffic {
					allUnlimitedTokens = false
				}
			case "DAYS_LEFT", "EXPIRE_DATE":
				if !isUnlimitedExpiry {
					allUnlimitedTokens = false
				}
			default:
				allUnlimitedTokens = false
			}
		}

		if allUnlimitedTokens && (isUnlimitedTraffic || isUnlimitedExpiry) {
			continue
		}

		// Replace tokens
		expanded := remarkVarRe.ReplaceAllStringFunc(seg, func(tok string) string {
			name := strings.Trim(tok, "{}")
			switch name {
			case "EMAIL":
				return ctx.Email
			case "PROTOCOL":
				return ctx.Protocol
			case "TRANSPORT":
				return ctx.Transport
			case "SECURITY":
				return ctx.Security
			case "INBOUND":
				return ctx.InboundTag
			case "TRAFFIC_USED":
				return FormatBytes(ctx.TrafficUsed)
			case "TRAFFIC_TOTAL":
				if isUnlimitedTraffic {
					return "∞"
				}
				return FormatBytes(ctx.TrafficTotal)
			case "TRAFFIC_LEFT":
				if isUnlimitedTraffic {
					return "∞"
				}
				left := ctx.TrafficTotal - ctx.TrafficUsed
				if left < 0 {
					left = 0
				}
				return FormatBytes(left)
			case "USAGE_PERCENTAGE":
				if isUnlimitedTraffic {
					return "0%"
				}
				pct := float64(ctx.TrafficUsed) / float64(ctx.TrafficTotal) * 100.0
				if pct > 100.0 {
					pct = 100.0
				}
				return fmt.Sprintf("%.1f%%", pct)
			case "STATUS_EMOJI":
				if !isUnlimitedExpiry && ctx.ExpiryTime < nowUnix {
					return "🔴" // Expired
				}
				if !isUnlimitedTraffic && ctx.TrafficUsed >= ctx.TrafficTotal {
					return "⚠️" // Quota exceeded
				}
				return "🟢" // Active
			case "DAYS_LEFT":
				if isUnlimitedExpiry {
					return "∞"
				}
				diff := ctx.ExpiryTime - nowUnix
				if diff <= 0 {
					return "0"
				}
				days := diff / 86400
				return fmt.Sprintf("%d", days)
			case "EXPIRE_DATE":
				if isUnlimitedExpiry {
					return "Unlimited"
				}
				t := time.Unix(ctx.ExpiryTime, 0).UTC()
				return t.Format("2006-01-02")
			default:
				return tok
			}
		})

		evaluatedSegments = append(evaluatedSegments, strings.TrimSpace(expanded))
	}

	return strings.Join(evaluatedSegments, " | ")
}
