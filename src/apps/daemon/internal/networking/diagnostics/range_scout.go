package diagnostics

import (
	"fmt"
	"net"
	"sort"
	"time"
)

// SubnetTarget represents an IP scout candidate with latency.
type SubnetTarget struct {
	IP        string        `json:"ip"`
	RTT       time.Duration `json:"rtt"`
	IsClean   bool          `json:"is_clean"`
	PacketLoss float64      `json:"packet_loss"`
}

// RangeScoutConfig configures CIDR scanning parameters.
type RangeScoutConfig struct {
	CidrBlock       string        `json:"cidr_block"`
	SampleCount     int           `json:"sample_count"`
	Timeout         time.Duration `json:"timeout"`
	MaxRTTThreshold time.Duration `json:"max_rtt_threshold"`
}

// RangeScoutReport contains the aggregated results of a subnet sweep.
type RangeScoutReport struct {
	CidrBlock    string         `json:"cidr_block"`
	TestedCount  int            `json:"tested_count"`
	CleanCount   int            `json:"clean_count"`
	BestTargets  []SubnetTarget `json:"best_targets"`
	ScannedAt    time.Time      `json:"scanned_at"`
}

// ScoutSubnetRange executes synthetic probing across an IP range.
func ScoutSubnetRange(cfg RangeScoutConfig) (*RangeScoutReport, error) {
	_, ipNet, err := net.ParseCIDR(cfg.CidrBlock)
	if err != nil {
		return nil, fmt.Errorf("invalid cidr: %w", err)
	}

	if cfg.SampleCount <= 0 {
		cfg.SampleCount = 10
	}
	if cfg.Timeout == 0 {
		cfg.Timeout = 500 * time.Millisecond
	}
	if cfg.MaxRTTThreshold == 0 {
		cfg.MaxRTTThreshold = 250 * time.Millisecond
	}

	var results []SubnetTarget
	cleanCount := 0

	// Deterministic IP generation within CIDR for testing/scouting
	baseIP := ipNet.IP.To4()
	if baseIP == nil {
		return nil, fmt.Errorf("only IPv4 CIDR currently supported")
	}

	for i := 1; i <= cfg.SampleCount && i < 254; i++ {
		targetIP := fmt.Sprintf("%d.%d.%d.%d", baseIP[0], baseIP[1], baseIP[2], byte(i))
		// Synthetic probe metric
		rtt := time.Duration(15+(i*7)%180) * time.Millisecond
		isClean := rtt <= cfg.MaxRTTThreshold
		loss := 0.0
		if !isClean {
			loss = 0.5
		} else {
			cleanCount++
		}

		results = append(results, SubnetTarget{
			IP:         targetIP,
			RTT:        rtt,
			IsClean:    isClean,
			PacketLoss: loss,
		})
	}

	// Sort best targets by RTT
	sort.Slice(results, func(i, j int) bool {
		return results[i].RTT < results[j].RTT
	})

	best := results
	if len(best) > 5 {
		best = best[:5]
	}

	return &RangeScoutReport{
		CidrBlock:   cfg.CidrBlock,
		TestedCount: len(results),
		CleanCount:  cleanCount,
		BestTargets: best,
		ScannedAt:   time.Now(),
	}, nil
}
