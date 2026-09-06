package sub

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/maybeknott/luminet/internal/networking/proxyconfig"
)

type RoundTripIssue struct {
	Index   int    `json:"index"`
	Code    string `json:"code"`
	Message string `json:"message"`
}

type RoundTripReport struct {
	Attempted     bool             `json:"attempted"`
	Compatible    bool             `json:"compatible"`
	SourceNodes   int              `json:"source_nodes"`
	ReparsedNodes int              `json:"reparsed_nodes"`
	ExactNodes    int              `json:"exact_nodes"`
	ChangedNodes  int              `json:"changed_nodes"`
	MissingNodes  int              `json:"missing_nodes"`
	ExtraNodes    int              `json:"extra_nodes"`
	ParserError   string           `json:"parser_error,omitempty"`
	Issues        []RoundTripIssue `json:"issues,omitempty"`
}

type ContentParser func(string) ([]*proxyconfig.ProxyConfig, error)

// ValidateRoundTrip compares semantic node state after re-ingesting generated
// content. Names and raw source text are intentionally non-semantic; top-level
// detour relationships are compared by stable node position. The function has
// no network or process side effects and is suitable for strict export gates.
func ValidateRoundTrip(source []*proxyconfig.ProxyConfig, content string, parser ContentParser) RoundTripReport {
	report := RoundTripReport{Attempted: true, SourceNodes: len(source)}
	if parser == nil {
		report.ParserError = "round-trip parser is unavailable"
		return report
	}
	reparsed, err := parser(content)
	if err != nil {
		report.ParserError = err.Error()
		report.MissingNodes = len(source)
		return report
	}
	report.ReparsedNodes = len(reparsed)
	limit := len(source)
	if len(reparsed) < limit {
		limit = len(reparsed)
	}
	if len(source) > len(reparsed) {
		report.MissingNodes = len(source) - len(reparsed)
	}
	if len(reparsed) > len(source) {
		report.ExtraNodes = len(reparsed) - len(source)
	}

	sourceGraph := topLevelDetourIndices(source)
	reparsedGraph := topLevelDetourIndices(reparsed)
	for i := 0; i < limit; i++ {
		left, lerr := roundTripSemanticKey(source[i])
		right, rerr := roundTripSemanticKey(reparsed[i])
		if lerr != nil || rerr != nil {
			report.ChangedNodes++
			report.Issues = append(report.Issues, RoundTripIssue{Index: i + 1, Code: "semantic_key", Message: firstNonEmptyError(lerr, rerr)})
			continue
		}
		if left != right {
			report.ChangedNodes++
			report.Issues = append(report.Issues, RoundTripIssue{Index: i + 1, Code: "semantic_change", Message: "re-ingested node differs from canonical source semantics"})
			continue
		}
		if sourceGraph[i] != reparsedGraph[i] {
			report.ChangedNodes++
			report.Issues = append(report.Issues, RoundTripIssue{Index: i + 1, Code: "detour_change", Message: fmt.Sprintf("detour target changed from %d to %d", sourceGraph[i], reparsedGraph[i])})
			continue
		}
		report.ExactNodes++
	}
	report.Compatible = report.ParserError == "" && report.ChangedNodes == 0 && report.MissingNodes == 0 && report.ExtraNodes == 0 && report.ExactNodes == len(source)
	return report
}

func roundTripSemanticKey(cfg *proxyconfig.ProxyConfig) (string, error) {
	if cfg == nil {
		return "<nil>", nil
	}
	clone := cloneProxyConfigShallow(cfg)
	clone.Name = ""
	clone.RawURI = ""
	clone.Detour = nil
	clone.DialerProxy = ""
	data, err := json.Marshal(clone)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// topLevelDetourIndices returns -1 for no detour, -2 for an unresolved or
// ambiguous relationship, otherwise the stable top-level target index.
func topLevelDetourIndices(configs []*proxyconfig.ProxyConfig) []int {
	out := make([]int, len(configs))
	for i := range out {
		out[i] = -1
	}
	byPtr := make(map[*proxyconfig.ProxyConfig]int, len(configs))
	byName := make(map[string][]int, len(configs))
	for i, cfg := range configs {
		if cfg == nil {
			continue
		}
		byPtr[cfg] = i
		if name := strings.TrimSpace(cfg.Name); name != "" {
			byName[name] = append(byName[name], i)
		}
	}
	for i, cfg := range configs {
		if cfg == nil {
			continue
		}
		target := -1
		if cfg.Detour != nil {
			if idx, ok := byPtr[cfg.Detour]; ok {
				target = idx
			} else {
				target = -2
			}
		}
		if raw := strings.TrimSpace(cfg.DialerProxy); raw != "" {
			matches := byName[raw]
			if len(matches) != 1 {
				out[i] = -2
				continue
			}
			if target >= 0 && target != matches[0] {
				out[i] = -2
				continue
			}
			target = matches[0]
		}
		out[i] = target
	}
	return out
}

func firstNonEmptyError(a, b error) string {
	if a != nil {
		return a.Error()
	}
	if b != nil {
		return b.Error()
	}
	return "semantic comparison failed"
}
