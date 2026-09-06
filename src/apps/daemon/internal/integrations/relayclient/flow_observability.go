package relayclient

import (
	"sync"

	"github.com/maybeknott/luminet/internal/foundation/flowregistry"
	"github.com/maybeknott/luminet/internal/platform/system"
)

var relayFlowCoverageOnce sync.Once

func init() { declareRelayFlowCoverage() }

func declareRelayFlowCoverage() {
	relayFlowCoverageOnce.Do(func() {
		reg := flowregistry.Default()
		for _, c := range []flowregistry.OwnerCoverage{
			{Owner: "relay-serverless-ws", Visible: true, Closeable: true, ByteCounters: true, DestinationMetadata: true, Notes: []string{"covers confirmed WebSocket serverless relay virtual TCP connections"}},
			{Owner: "relay-serverless-http", Visible: true, Closeable: true, ByteCounters: true, DestinationMetadata: true, Notes: []string{"counts HTTP relay upload bytes only after successful relay acknowledgement"}},
			{Owner: "relay-gsa", Visible: true, Closeable: true, ByteCounters: true, DestinationMetadata: true, Notes: []string{"counts GSA relay upload bytes only after successful relay acknowledgement"}},
		} {
			_ = reg.DeclareOwner(c)
		}
	})
}

func registerRelayFlow(owner, protocol, destination string, closeFn flowregistry.CloseFunc) *flowregistry.Handle {
	declareRelayFlowCoverage()
	epoch := system.GetNetworkMonitor().Snapshot().Revision
	h, err := flowregistry.Default().Register(flowregistry.Descriptor{
		Owner: owner, Network: "tcp", Protocol: protocol, Destination: destination,
		Chain: []string{"serverless-relay"}, NetworkEpoch: epoch,
	}, closeFn)
	if err != nil {
		return nil
	}
	return h
}

func closeFlowHandle(h *flowregistry.Handle) {
	if h != nil {
		h.End()
	}
}
func addFlowUpload(h *flowregistry.Handle, n int) {
	if h != nil && n > 0 {
		h.AddUpload(uint64(n))
	}
}
func addFlowDownload(h *flowregistry.Handle, n int) {
	if h != nil && n > 0 {
		h.AddDownload(uint64(n))
	}
}
