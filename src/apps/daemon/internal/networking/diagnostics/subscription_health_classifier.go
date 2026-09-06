package diagnostics

type HealthTier int

const (
	TierFDead HealthTier = iota
	TierCDegraded
	TierBGood
	TierAExcellent
)

type NodeHealthReport struct {
	NodeID      string     `json:"node_id"`
	Tier        HealthTier `json:"tier"`
	AvgRttMs    uint32     `json:"avg_rtt_ms"`
	JitterMs    uint32     `json:"jitter_ms"`
	PacketLoss  float32    `json:"packet_loss"`
	TotalProbes uint32     `json:"total_probes"`
}

type nodeProbeRecord struct {
	samples  []uint32
	failures uint32
	total    uint32
}

type SubscriptionHealthClassifier struct {
	nodes      map[string]*nodeProbeRecord
	maxSamples int
}

func NewSubscriptionHealthClassifier(maxSamples int) *SubscriptionHealthClassifier {
	if maxSamples < 5 {
		maxSamples = 5
	}
	return &SubscriptionHealthClassifier{
		nodes:      make(map[string]*nodeProbeRecord),
		maxSamples: maxSamples,
	}
}

func (s *SubscriptionHealthClassifier) RecordSample(nodeID string, rttMs uint32, success bool) {
	rec, ok := s.nodes[nodeID]
	if !ok {
		rec = &nodeProbeRecord{
			samples: make([]uint32, 0),
		}
		s.nodes[nodeID] = rec
	}

	rec.total++
	if success {
		rec.samples = append(rec.samples, rttMs)
		if len(rec.samples) > s.maxSamples {
			rec.samples = rec.samples[1:]
		}
	} else {
		rec.failures++
	}
}

func (s *SubscriptionHealthClassifier) ClassifyNode(nodeID string) HealthTier {
	rec, ok := s.nodes[nodeID]
	if !ok || len(rec.samples) == 0 {
		return TierFDead
	}

	loss := float32(rec.failures) / float32(rec.total)
	var sum uint32
	for _, rtt := range rec.samples {
		sum += rtt
	}
	avgRtt := sum / uint32(len(rec.samples))

	if loss <= 0.05 && avgRtt <= 80 {
		return TierAExcellent
	} else if loss <= 0.15 && avgRtt <= 200 {
		return TierBGood
	} else if loss <= 0.40 && avgRtt <= 600 {
		return TierCDegraded
	}
	return TierFDead
}

func (s *SubscriptionHealthClassifier) FilterUsableNodes(minTier HealthTier) []string {
	var usable []string
	for id := range s.nodes {
		if s.ClassifyNode(id) >= minTier {
			usable = append(usable, id)
		}
	}
	return usable
}
