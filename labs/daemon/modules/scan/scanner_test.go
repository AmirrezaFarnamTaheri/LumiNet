package scan

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/maybeknott/luminet/internal/probe"
)

type fixtureExecutor struct{}

func (fixtureExecutor) Probe(_ context.Context, request probe.Request) probe.Observation {
	return probe.Observation{
		Endpoint:     request.Endpoint,
		Protocol:     request.Protocol,
		Verification: probe.VerificationNotApplicable,
		Succeeded:    request.Endpoint.Port == 443,
	}
}

type blockingExecutor struct {
	started chan struct{}
}

func (executor blockingExecutor) Probe(ctx context.Context, request probe.Request) probe.Observation {
	select {
	case executor.started <- struct{}{}:
	default:
	}
	<-ctx.Done()
	return probe.Observation{Endpoint: request.Endpoint, Protocol: request.Protocol, Error: ctx.Err().Error()}
}

func TestSubnetScanner(t *testing.T) {
	// Start mock TCP listener
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to start mock listener: %v", err)
	}
	defer ln.Close()

	_, portStr, _ := net.SplitHostPort(ln.Addr().String())
	var port uint16
	for _, ch := range portStr {
		port = port*10 + uint16(ch-'0')
	}

	scanner := NewSubnetScanner()
	scanner.Timeout = 500 * time.Millisecond

	targets := []ScanTarget{
		{Host: "127.0.0.1", Ports: []uint16{port, 65530}},
	}

	results := scanner.ScanTargets(context.Background(), targets)
	if len(results) == 0 {
		t.Fatal("expected at least 1 host result")
	}

	if len(results[0].OpenPorts) != 1 || results[0].OpenPorts[0] != port {
		t.Errorf("expected open port %d, got %v", port, results[0].OpenPorts)
	}
}

func TestSubnetScannerUsesExecutorObservations(t *testing.T) {
	scanner := NewSubnetScannerWithExecutor(fixtureExecutor{})
	results := scanner.ScanTargets(context.Background(), []ScanTarget{{
		Host:  "example.test",
		Ports: []uint16{80, 443},
	}})
	if len(results) != 1 {
		t.Fatalf("expected one host result, got %d", len(results))
	}
	result := results[0]
	if len(result.OpenPorts) != 1 || result.OpenPorts[0] != 443 {
		t.Fatalf("unexpected open ports: %v", result.OpenPorts)
	}
	if len(result.Observations) != 2 || result.Observations[0].Protocol != probe.ProtocolTCP {
		t.Fatalf("expected TCP observations for every port: %+v", result.Observations)
	}
}

func TestSubnetScannerCancellationStopsDispatch(t *testing.T) {
	started := make(chan struct{}, 1)
	scanner := NewSubnetScannerWithExecutor(blockingExecutor{started: started})
	scanner.Concurrency = 1
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		scanner.ScanTargets(ctx, []ScanTarget{
			{Host: "one.example", Ports: []uint16{443}},
			{Host: "two.example", Ports: []uint16{443}},
		})
		close(done)
	}()
	select {
	case <-started:
		cancel()
	case <-time.After(time.Second):
		t.Fatal("probe did not start")
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("scanner did not stop after cancellation")
	}
}
