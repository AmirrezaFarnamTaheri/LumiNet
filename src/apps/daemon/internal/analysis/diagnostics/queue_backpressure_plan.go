package diagnostics

import "fmt"

type QueueBackpressurePolicyRequest struct {
	Capacity               int    `json:"capacity"`
	CurrentDepth           int    `json:"current_depth"`
	IncomingItems          int    `json:"incoming_items"`
	Strategy               string `json:"strategy,omitempty"`
	MaxBatchItems          int    `json:"max_batch_items,omitempty"`
	MaxBatchBytes          int    `json:"max_batch_bytes,omitempty"`
	AverageItemBytes       int    `json:"average_item_bytes,omitempty"`
	ExportFailed           bool   `json:"export_failed,omitempty"`
	ExportBatchItems       int    `json:"export_batch_items,omitempty"`
	RestoreOnExportFailure bool   `json:"restore_on_export_failure,omitempty"`
	WireCount              int    `json:"wire_count,omitempty"`
	WirePayloadBytes       int    `json:"wire_payload_bytes,omitempty"`
	MinWireItemBytes       int    `json:"min_wire_item_bytes,omitempty"`
}

type QueueBackpressurePolicyPlan struct {
	AcceptedIncoming int      `json:"accepted_incoming"`
	EvictedOldest    int      `json:"evicted_oldest"`
	RejectedIncoming int      `json:"rejected_incoming"`
	NewDepth         int      `json:"new_depth"`
	BatchItems       int      `json:"batch_items"`
	RestoreItems     int      `json:"restore_items"`
	Backlog          int      `json:"backlog"`
	Strategy         string   `json:"strategy"`
	Invariants       []string `json:"invariants"`
	ReadOnly         bool     `json:"read_only"`
}

func BuildQueueBackpressurePolicyPlan(req QueueBackpressurePolicyRequest) (QueueBackpressurePolicyPlan, error) {
	if req.Capacity < 1 || req.Capacity > 1_000_000 {
		return QueueBackpressurePolicyPlan{}, fmt.Errorf("queue capacity must be between 1 and 1000000")
	}
	if req.CurrentDepth < 0 || req.CurrentDepth > req.Capacity || req.IncomingItems < 0 || req.IncomingItems > 1_000_000 {
		return QueueBackpressurePolicyPlan{}, fmt.Errorf("queue depth/incoming count is outside supported bounds")
	}
	strategy := req.Strategy
	if strategy == "" {
		strategy = "drop-oldest"
	}
	if strategy != "drop-oldest" && strategy != "reject-new" && strategy != "backpressure" {
		return QueueBackpressurePolicyPlan{}, fmt.Errorf("unsupported queue strategy %q", strategy)
	}
	maxBatchItems := req.MaxBatchItems
	if maxBatchItems == 0 {
		maxBatchItems = 64
	}
	maxBatchBytes := req.MaxBatchBytes
	if maxBatchBytes == 0 {
		maxBatchBytes = 256 << 10
	}
	if maxBatchItems < 1 || maxBatchItems > 4096 || maxBatchBytes < 1 || maxBatchBytes > 64<<20 || req.AverageItemBytes < 0 || req.AverageItemBytes > 1<<20 {
		return QueueBackpressurePolicyPlan{}, fmt.Errorf("batch policy is outside supported bounds")
	}
	if req.ExportBatchItems < 0 || req.ExportBatchItems > req.Capacity {
		return QueueBackpressurePolicyPlan{}, fmt.Errorf("export batch size is outside queue capacity")
	}
	if req.WireCount < 0 || req.WirePayloadBytes < 0 || req.MinWireItemBytes < 0 {
		return QueueBackpressurePolicyPlan{}, fmt.Errorf("wire framing evidence cannot be negative")
	}
	if req.WireCount > 0 {
		if req.MinWireItemBytes == 0 {
			return QueueBackpressurePolicyPlan{}, fmt.Errorf("wire count requires a non-zero minimum item size")
		}
		if req.WireCount > req.WirePayloadBytes/req.MinWireItemBytes {
			return QueueBackpressurePolicyPlan{}, fmt.Errorf("wire frame count exceeds payload capacity")
		}
	}

	available := req.Capacity - req.CurrentDepth
	accepted, evicted, rejected := 0, 0, 0
	switch strategy {
	case "drop-oldest":
		accepted = req.IncomingItems
		if accepted > req.Capacity {
			rejected = accepted - req.Capacity
			accepted = req.Capacity
		}
		overflow := req.CurrentDepth + accepted - req.Capacity
		if overflow > 0 {
			evicted = overflow
		}
	case "reject-new", "backpressure":
		accepted = req.IncomingItems
		if accepted > available {
			accepted = available
		}
		rejected = req.IncomingItems - accepted
	}
	newDepth := req.CurrentDepth - evicted + accepted
	if newDepth > req.Capacity {
		newDepth = req.Capacity
	}

	batchItems := newDepth
	if batchItems > maxBatchItems {
		batchItems = maxBatchItems
	}
	if req.AverageItemBytes > 0 {
		byBytes := maxBatchBytes / req.AverageItemBytes
		if byBytes < batchItems {
			batchItems = byBytes
		}
	}
	if batchItems < 0 {
		batchItems = 0
	}

	restore := 0
	if req.ExportFailed && req.RestoreOnExportFailure {
		restore = req.ExportBatchItems
		if restore+newDepth > req.Capacity {
			restore = req.Capacity - newDepth
		}
	}

	return QueueBackpressurePolicyPlan{
		AcceptedIncoming: accepted,
		EvictedOldest:    evicted,
		RejectedIncoming: rejected,
		NewDepth:         newDepth,
		BatchItems:       batchItems,
		RestoreItems:     restore,
		Backlog:          newDepth + restore,
		Strategy:         strategy,
		Invariants: []string{
			"queue capacity is a hard memory bound rather than an advisory target",
			"drop/eviction decisions are observable and monotonic counters must not be inferred from queue depth",
			"failed export batches may be restored only within the same bounded capacity",
			"wire decoders validate count against payload length before slicing or allocating",
			"batch item and byte ceilings are enforced together",
		},
		ReadOnly: true,
	}, nil
}
