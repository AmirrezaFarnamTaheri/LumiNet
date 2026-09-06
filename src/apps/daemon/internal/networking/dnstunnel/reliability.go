package dnstunnel

import (
	"fmt"
	"math"
	"sort"
	"strings"
)

const (
	maxReliabilityResolvers = 64
	maxReedSolomonShards    = 256
)

type ResolverObservation struct {
	Name           string  `json:"name"`
	Reachable      bool    `json:"reachable"`
	MTU            int     `json:"mtu"`
	LossPct        float64 `json:"loss_pct"`
	RTTMs          float64 `json:"rtt_ms"`
	ThroughputKbps float64 `json:"throughput_kbps,omitempty"`
}

type ResolverPlan struct {
	Name                 string  `json:"name"`
	Tier                 string  `json:"tier"`
	MTU                  int     `json:"mtu"`
	LossPct              float64 `json:"loss_pct"`
	RTTMs                float64 `json:"rtt_ms"`
	ThroughputKbps       float64 `json:"throughput_kbps,omitempty"`
	EffectiveGoodputKbps float64 `json:"effective_goodput_kbps"`
}

type ReliabilityPlan struct {
	Preset                 string         `json:"preset"`
	Mode                   string         `json:"mode"`
	PreferredTransport     string         `json:"preferred_transport"`
	ObservedLossPct        *float64       `json:"observed_loss_pct,omitempty"`
	LossThresholdPct       float64        `json:"loss_threshold_pct"`
	SuperLossFloorPct      float64        `json:"super_loss_floor_pct"`
	SuperLossCeilPct       float64        `json:"super_loss_ceil_pct"`
	TargetRecoveryPct      float64        `json:"target_recovery_pct"`
	DataShards             int            `json:"data_shards"`
	BaseParityShards       int            `json:"base_parity_shards"`
	ParityShards           int            `json:"parity_shards"`
	RecoveryProbabilityPct float64        `json:"recovery_probability_pct"`
	OperatingMTU           int            `json:"operating_mtu,omitempty"`
	Resolvers              []ResolverPlan `json:"resolvers,omitempty"`
}

type reliabilityDefaults struct {
	preset            string
	transport         string
	lossThresholdPct  float64
	superFloorPct     float64
	superCeilPct      float64
	recoveryTargetPct float64
	dataShards        int
	baseParity        int
}

func buildReliabilityPlan(req PlanRequest) (ReliabilityPlan, error) {
	cfg, err := reliabilityPreset(req.Preset)
	if err != nil {
		return ReliabilityPlan{}, err
	}
	if req.PreferredTransport != "" {
		transport := strings.ToLower(strings.TrimSpace(req.PreferredTransport))
		if transport != "udp" && transport != "tcp" {
			return ReliabilityPlan{}, fmt.Errorf("preferred DNS transport must be udp or tcp")
		}
		cfg.transport = transport
	}
	if req.FECDataShards != nil {
		cfg.dataShards = *req.FECDataShards
	}
	if req.FECBaseParity != nil {
		cfg.baseParity = *req.FECBaseParity
	}
	if req.FECLossThresholdPct != nil {
		cfg.lossThresholdPct = *req.FECLossThresholdPct
	}
	if req.SuperLossFloorPct != nil {
		cfg.superFloorPct = *req.SuperLossFloorPct
	}
	if req.SuperLossCeilPct != nil {
		cfg.superCeilPct = *req.SuperLossCeilPct
	}
	if req.RecoveryTargetPct != nil {
		cfg.recoveryTargetPct = *req.RecoveryTargetPct
	}
	if cfg.dataShards < 1 || cfg.dataShards >= maxReedSolomonShards {
		return ReliabilityPlan{}, fmt.Errorf("FEC data shards must be between 1 and 255")
	}
	if cfg.baseParity < 0 || cfg.dataShards+cfg.baseParity > maxReedSolomonShards {
		return ReliabilityPlan{}, fmt.Errorf("FEC base parity exceeds 256-shard limit")
	}
	for name, value := range map[string]float64{
		"FEC loss threshold":     cfg.lossThresholdPct,
		"super-FEC loss floor":   cfg.superFloorPct,
		"super-FEC loss ceiling": cfg.superCeilPct,
		"recovery target":        cfg.recoveryTargetPct,
	} {
		if !finite(value) || value < 0 || value > 100 {
			return ReliabilityPlan{}, fmt.Errorf("%s must be finite and between 0 and 100", name)
		}
	}
	if cfg.superFloorPct <= cfg.lossThresholdPct || cfg.superCeilPct < cfg.superFloorPct || cfg.superCeilPct >= 100 {
		return ReliabilityPlan{}, fmt.Errorf("super-FEC band must be above the normal FEC threshold and below 100%% loss")
	}
	if cfg.recoveryTargetPct <= 0 || cfg.recoveryTargetPct >= 100 {
		return ReliabilityPlan{}, fmt.Errorf("recovery target must be between 0 and 100")
	}

	plan := ReliabilityPlan{
		Preset: cfg.preset, PreferredTransport: cfg.transport,
		LossThresholdPct: cfg.lossThresholdPct, SuperLossFloorPct: cfg.superFloorPct,
		SuperLossCeilPct: cfg.superCeilPct, TargetRecoveryPct: cfg.recoveryTargetPct,
		DataShards: cfg.dataShards, BaseParityShards: cfg.baseParity,
		Mode: "raw",
	}
	if req.ObservedLossPct != nil {
		loss := *req.ObservedLossPct
		if !finite(loss) || loss < 0 || loss > 100 {
			return ReliabilityPlan{}, fmt.Errorf("observed loss must be finite and between 0 and 100")
		}
		copyLoss := loss
		plan.ObservedLossPct = &copyLoss
		lossFrac := loss / 100
		switch {
		case loss > cfg.superCeilPct:
			plan.Mode = "arq-primary"
			plan.ParityShards = cfg.baseParity
		case loss >= cfg.superFloorPct:
			plan.Mode = "super-fec"
			plan.ParityShards = parityForLossTarget(cfg.dataShards, lossFrac, cfg.recoveryTargetPct/100)
		case loss >= cfg.lossThresholdPct:
			plan.Mode = "fec"
			plan.ParityShards = parityForLoss(cfg.dataShards, lossFrac)
			if plan.ParityShards < cfg.baseParity {
				plan.ParityShards = cfg.baseParity
			}
		default:
			plan.Mode = "raw"
			plan.ParityShards = 0
		}
		if plan.ParityShards > maxReedSolomonShards-cfg.dataShards {
			plan.ParityShards = maxReedSolomonShards - cfg.dataShards
		}
		plan.RecoveryProbabilityPct = math.Round(shardRecoveryProbability(cfg.dataShards+plan.ParityShards, cfg.dataShards, 1-lossFrac)*10000) / 100
	} else if cfg.preset == "survival" {
		plan.Mode = "fec"
		plan.ParityShards = cfg.baseParity
		plan.RecoveryProbabilityPct = 100
	}

	resolvers, operatingMTU, err := planResolvers(req.Resolvers)
	if err != nil {
		return ReliabilityPlan{}, err
	}
	plan.Resolvers = resolvers
	plan.OperatingMTU = operatingMTU
	return plan, nil
}

func reliabilityPreset(raw string) (reliabilityDefaults, error) {
	preset := strings.ToLower(strings.TrimSpace(raw))
	if preset == "" {
		preset = "balanced"
	}
	cfg := reliabilityDefaults{preset: preset, transport: "udp", lossThresholdPct: 25, superFloorPct: 75, superCeilPct: 85, recoveryTargetPct: 90, dataShards: 4, baseParity: 1}
	switch preset {
	case "balanced", "speed":
	case "survival":
		cfg.lossThresholdPct = 20
		cfg.baseParity = 4
	case "tcp-survival":
		cfg.transport = "tcp"
	case "high-latency":
		cfg.baseParity = 2
	case "":
	default:
		return reliabilityDefaults{}, fmt.Errorf("unsupported DNS reliability preset %q", raw)
	}
	return cfg, nil
}

func parityForLoss(dataShards int, lossFrac float64) int {
	lossFrac = math.Max(0, math.Min(0.95, lossFrac))
	survive := 1 - lossFrac
	total := int(math.Ceil(float64(dataShards) / survive))
	parity := total - dataShards + 1
	if parity < 1 {
		parity = 1
	}
	if parity > maxReedSolomonShards-dataShards {
		parity = maxReedSolomonShards - dataShards
	}
	return parity
}

func parityForLossTarget(dataShards int, lossFrac, target float64) int {
	minimum := parityForLoss(dataShards, lossFrac)
	for total := dataShards + minimum; total <= maxReedSolomonShards; total++ {
		if shardRecoveryProbability(total, dataShards, 1-lossFrac) >= target {
			return total - dataShards
		}
	}
	return maxReedSolomonShards - dataShards
}

func shardRecoveryProbability(total, required int, p float64) float64 {
	if required <= 0 {
		return 1
	}
	if total < required || p <= 0 {
		return 0
	}
	if p >= 1 {
		return 1
	}
	q := 1 - p
	term := math.Pow(q, float64(total))
	failure := term
	for k := 0; k < required-1; k++ {
		term *= float64(total-k) / float64(k+1) * p / q
		failure += term
	}
	return math.Max(0, math.Min(1, 1-failure))
}

func planResolvers(observations []ResolverObservation) ([]ResolverPlan, int, error) {
	if len(observations) > maxReliabilityResolvers {
		return nil, 0, fmt.Errorf("resolver evidence count %d exceeds limit %d", len(observations), maxReliabilityResolvers)
	}
	seen := make(map[string]struct{}, len(observations))
	validMTUs := make([]int, 0, len(observations))
	rows := make([]ResolverPlan, 0, len(observations))
	for _, observation := range observations {
		name := strings.TrimSpace(observation.Name)
		if name == "" || len(name) > 255 {
			return nil, 0, fmt.Errorf("resolver name is empty or too long")
		}
		if _, ok := seen[name]; ok {
			return nil, 0, fmt.Errorf("duplicate resolver %q", name)
		}
		seen[name] = struct{}{}
		if !finite(observation.LossPct) || observation.LossPct < 0 || observation.LossPct > 100 || !finite(observation.RTTMs) || observation.RTTMs < 0 || observation.RTTMs > 600000 || !finite(observation.ThroughputKbps) || observation.ThroughputKbps < 0 || observation.ThroughputKbps > 1e9 {
			return nil, 0, fmt.Errorf("resolver %q has invalid measurement evidence", name)
		}
		row := ResolverPlan{Name: name, MTU: observation.MTU, LossPct: observation.LossPct, RTTMs: observation.RTTMs, ThroughputKbps: observation.ThroughputKbps, Tier: "invalid"}
		if observation.Reachable && observation.MTU > 0 && observation.MTU <= 65535 {
			row.Tier = "candidate"
			base := observation.ThroughputKbps
			if base <= 0 {
				base = float64(observation.MTU)
			}
			row.EffectiveGoodputKbps = math.Round(base*(1-observation.LossPct/100)*100) / 100
			validMTUs = append(validMTUs, observation.MTU)
		}
		rows = append(rows, row)
	}
	operating := 0
	if len(validMTUs) > 0 {
		sort.Sort(sort.Reverse(sort.IntSlice(validMTUs)))
		idx := 0
		if len(validMTUs) >= 2 {
			idx = 1
		}
		operating = validMTUs[idx]
	}
	for i := range rows {
		if rows[i].Tier != "candidate" {
			continue
		}
		if rows[i].MTU >= operating {
			rows[i].Tier = "active"
		} else {
			rows[i].Tier = "reserve"
		}
	}
	tierRank := map[string]int{"active": 0, "reserve": 1, "invalid": 2}
	sort.SliceStable(rows, func(i, j int) bool {
		if tierRank[rows[i].Tier] != tierRank[rows[j].Tier] {
			return tierRank[rows[i].Tier] < tierRank[rows[j].Tier]
		}
		if rows[i].EffectiveGoodputKbps != rows[j].EffectiveGoodputKbps {
			return rows[i].EffectiveGoodputKbps > rows[j].EffectiveGoodputKbps
		}
		if rows[i].RTTMs != rows[j].RTTMs {
			return rows[i].RTTMs < rows[j].RTTMs
		}
		return rows[i].Name < rows[j].Name
	})
	return rows, operating, nil
}

func finite(value float64) bool { return !math.IsNaN(value) && !math.IsInf(value, 0) }
