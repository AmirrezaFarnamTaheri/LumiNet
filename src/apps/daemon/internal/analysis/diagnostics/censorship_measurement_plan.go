package diagnostics

import (
	"fmt"
	"sort"
	"strings"
)

const maxCensorshipObservations = 128

type CensorshipObservation struct {
	ID                 string `json:"id"`
	Kind               string `json:"kind"`
	Subject            string `json:"subject,omitempty"`
	ExperimentObserved bool   `json:"experiment_observed"`
	ExperimentSuccess  bool   `json:"experiment_success"`
	ControlObserved    bool   `json:"control_observed"`
	ControlSuccess     bool   `json:"control_success"`
	DifferenceCode     string `json:"difference_code,omitempty"`
}

type CensorshipAnomaly struct {
	ID       string `json:"id"`
	Kind     string `json:"kind"`
	Strength string `json:"strength"`
	Reason   string `json:"reason"`
}

type CensorshipMeasurementRequest struct {
	Observations []CensorshipObservation `json:"observations"`
}

type CensorshipMeasurementPlan struct {
	Conclusion      string              `json:"conclusion"`
	Confidence      string              `json:"confidence"`
	Anomalies       []CensorshipAnomaly `json:"anomalies"`
	MissingControls []string            `json:"missing_controls"`
	ComparablePairs int                 `json:"comparable_pairs"`
	PerformsProbes  bool                `json:"performs_probes"`
	AppliesEvasion  bool                `json:"applies_evasion"`
	ReadOnly        bool                `json:"read_only"`
	Invariants      []string            `json:"invariants"`
}

func BuildCensorshipMeasurementPlan(req CensorshipMeasurementRequest) (CensorshipMeasurementPlan, error) {
	if len(req.Observations) == 0 || len(req.Observations) > maxCensorshipObservations {
		return CensorshipMeasurementPlan{}, fmt.Errorf("censorship observation count must be 1..%d", maxCensorshipObservations)
	}
	allowed := map[string]bool{"dns": true, "tcp": true, "tls": true, "http": true, "quic": true, "stun": true}
	seen := map[string]bool{}
	plan := CensorshipMeasurementPlan{Anomalies: []CensorshipAnomaly{}, MissingControls: []string{}, ReadOnly: true}
	for _, raw := range req.Observations {
		id := strings.TrimSpace(raw.ID)
		kind := strings.ToLower(strings.TrimSpace(raw.Kind))
		if id == "" || len(id) > 96 || seen[id] {
			return CensorshipMeasurementPlan{}, fmt.Errorf("invalid or duplicate observation id %q", id)
		}
		seen[id] = true
		if !allowed[kind] {
			return CensorshipMeasurementPlan{}, fmt.Errorf("unsupported censorship observation kind %q", kind)
		}
		if len(raw.Subject) > 512 || len(raw.DifferenceCode) > 96 {
			return CensorshipMeasurementPlan{}, fmt.Errorf("observation %q exceeds text bound", id)
		}
		if !raw.ExperimentObserved {
			continue
		}
		if !raw.ControlObserved {
			plan.MissingControls = append(plan.MissingControls, id)
			if !raw.ExperimentSuccess {
				plan.Anomalies = append(plan.Anomalies, CensorshipAnomaly{ID: id, Kind: kind, Strength: "weak", Reason: "experiment failed without a control observation"})
			}
			continue
		}
		plan.ComparablePairs++
		difference := strings.TrimSpace(raw.DifferenceCode)
		if raw.ControlSuccess && !raw.ExperimentSuccess {
			plan.Anomalies = append(plan.Anomalies, CensorshipAnomaly{ID: id, Kind: kind, Strength: "strong", Reason: "control succeeded while experiment failed"})
		} else if raw.ControlSuccess == raw.ExperimentSuccess && difference != "" {
			plan.Anomalies = append(plan.Anomalies, CensorshipAnomaly{ID: id, Kind: kind, Strength: "moderate", Reason: "experiment and control differed: " + difference})
		}
	}
	sort.Strings(plan.MissingControls)
	strong, moderate := 0, 0
	for _, a := range plan.Anomalies {
		if a.Strength == "strong" {
			strong++
		}
		if a.Strength == "moderate" {
			moderate++
		}
	}
	switch {
	case strong > 0:
		plan.Conclusion, plan.Confidence = "differential-anomaly-detected", "strong"
	case moderate > 0:
		plan.Conclusion, plan.Confidence = "differential-anomaly-detected", "moderate"
	case len(plan.Anomalies) > 0:
		plan.Conclusion, plan.Confidence = "possible-anomaly", "weak"
	case plan.ComparablePairs > 0:
		plan.Conclusion, plan.Confidence = "no-differential-anomaly-observed", "bounded"
	default:
		plan.Conclusion, plan.Confidence = "insufficient-control-evidence", "insufficient"
	}
	plan.Invariants = []string{
		"strong anomaly claims require a comparable control observation rather than experiment failure alone",
		"measurement evidence is kept separate from causal attribution to a censor, ISP, product, or middlebox",
		"the planner never performs DNS, TCP, TLS, HTTP, QUIC, or STUN probes and never enables an evasion mechanism",
		"missing controls remain explicit instead of being silently treated as successful baselines",
	}
	return plan, nil
}
