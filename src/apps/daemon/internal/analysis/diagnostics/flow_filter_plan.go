package diagnostics

import (
	"fmt"
	"sort"
	"strings"
)

const maxFlowFilterClauses = 16

type FlowFilterClause struct {
	Field    string `json:"field"`
	Operator string `json:"operator"`
	Value    string `json:"value"`
}
type FlowFilterPlanRequest struct {
	Clauses []FlowFilterClause `json:"clauses"`
	Match   string             `json:"match,omitempty"`
}
type FlowFilterPlan struct {
	Match           string             `json:"match"`
	Canonical       string             `json:"canonical"`
	Clauses         []FlowFilterClause `json:"clauses"`
	ReadsFlowBodies bool               `json:"reads_flow_bodies"`
	ModifiesFlows   bool               `json:"modifies_flows"`
	ReplaysFlows    bool               `json:"replays_flows"`
	ReadOnly        bool               `json:"read_only"`
	Invariants      []string           `json:"invariants"`
}

func BuildFlowFilterPlan(req FlowFilterPlanRequest) (FlowFilterPlan, error) {
	if len(req.Clauses) == 0 || len(req.Clauses) > maxFlowFilterClauses {
		return FlowFilterPlan{}, fmt.Errorf("flow filter clause count must be 1..%d", maxFlowFilterClauses)
	}
	match := strings.ToLower(strings.TrimSpace(req.Match))
	if match == "" {
		match = "all"
	}
	if match != "all" && match != "any" {
		return FlowFilterPlan{}, fmt.Errorf("flow filter match must be all or any")
	}
	fields := map[string]bool{"owner": true, "protocol": true, "network": true, "destination": true, "state": true, "provider": true}
	operators := map[string]bool{"eq": true, "contains": true, "prefix": true}
	clauses := make([]FlowFilterClause, 0, len(req.Clauses))
	for _, raw := range req.Clauses {
		c := raw
		c.Field = strings.ToLower(strings.TrimSpace(c.Field))
		c.Operator = strings.ToLower(strings.TrimSpace(c.Operator))
		c.Value = strings.TrimSpace(c.Value)
		if !fields[c.Field] {
			return FlowFilterPlan{}, fmt.Errorf("unsupported flow filter field %q", c.Field)
		}
		if !operators[c.Operator] {
			return FlowFilterPlan{}, fmt.Errorf("unsupported flow filter operator %q", c.Operator)
		}
		if c.Value == "" || len(c.Value) > 256 || strings.ContainsAny(c.Value, "\r\n\x00") {
			return FlowFilterPlan{}, fmt.Errorf("invalid flow filter value")
		}
		clauses = append(clauses, c)
	}
	sort.Slice(clauses, func(i, j int) bool {
		if clauses[i].Field != clauses[j].Field {
			return clauses[i].Field < clauses[j].Field
		}
		if clauses[i].Operator != clauses[j].Operator {
			return clauses[i].Operator < clauses[j].Operator
		}
		return clauses[i].Value < clauses[j].Value
	})
	parts := make([]string, 0, len(clauses))
	for _, c := range clauses {
		parts = append(parts, c.Field+":"+c.Operator+":"+c.Value)
	}
	return FlowFilterPlan{Match: match, Canonical: match + "(" + strings.Join(parts, ",") + ")", Clauses: clauses, ReadOnly: true, Invariants: []string{
		"filters operate only on metadata already exposed by owner-declared flow observability",
		"body bytes, credentials, TLS secrets, and arbitrary headers are outside the filter model",
		"operators are a bounded literal subset with no executable expression or regular-expression engine",
		"the planner cannot modify, replay, intercept, or close a flow",
	}}, nil
}
