package scanner

import (
	"context"
	"net"
	"testing"
	"time"
)

func TestGoExecutorTCPObservation(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go func() {
		connection, acceptErr := listener.Accept()
		if acceptErr == nil {
			connection.Close()
		}
	}()
	port := listener.Addr().(*net.TCPAddr).Port
	observation := (goProbeExecutor{}).probe(context.Background(), probeRequest{
		Endpoint: probeEndpoint{Host: "127.0.0.1", Port: uint16(port)},
		Protocol: probeProtocolTCP,
		Timeout:  time.Second,
	})
	if !observation.Succeeded || observation.Protocol != probeProtocolTCP || observation.Verification != probeVerificationNotApplicable {
		t.Fatalf("unexpected observation: %+v", observation)
	}
	if observation.ConnectLatency <= 0 || observation.TLSLatency != 0 {
		t.Fatalf("unexpected latency semantics: %+v", observation)
	}
}

func TestGoExecutorRejectsInvalidEndpoint(t *testing.T) {
	observation := (goProbeExecutor{}).probe(context.Background(), probeRequest{Protocol: probeProtocolTCP})
	if observation.Succeeded || observation.Error == "" {
		t.Fatalf("expected invalid endpoint failure: %+v", observation)
	}
}
