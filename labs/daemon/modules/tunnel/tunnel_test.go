package tunnel

import (
	"context"
	"net"
	"sync"
	"testing"
)

func TestTunnelLifecycleAndAuth(t *testing.T) {
	secret := "bore-tunnel-secret"
	server := NewTunnelServer(10000, 20000, secret, "127.0.0.1")

	// 1. Start control listener
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	defer l.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		conn, err := l.Accept()
		if err != nil {
			return
		}
		_ = server.HandleConnection(ctx, conn)
	}()

	// 2. Connect client to control server
	clientConn, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatalf("client failed to dial control: %v", err)
	}
	defer clientConn.Close()

	// Authenticator to answer server challenge
	auth := NewAuthenticator(secret)

	// Read challenge from server
	var challengeMsg ServerMessage
	if err := recvJSON(clientConn, &challengeMsg); err != nil {
		t.Fatalf("failed to read challenge: %v", err)
	}
	if challengeMsg.Type != "challenge" {
		t.Fatalf("expected challenge message type, got: %s", challengeMsg.Type)
	}

	// Send authentication response
	ans := auth.Answer(challengeMsg.UUID)
	if err := sendJSON(clientConn, ClientMessage{Type: "authenticate", Auth: ans}); err != nil {
		t.Fatalf("failed to send authenticate: %v", err)
	}

	// Send hello request (asking for random port)
	if err := sendJSON(clientConn, ClientMessage{Type: "hello", Port: 0}); err != nil {
		t.Fatalf("failed to send hello: %v", err)
	}

	// Read hello response from server (assigning port)
	var helloResp ServerMessage
	if err := recvJSON(clientConn, &helloResp); err != nil {
		t.Fatalf("failed to read hello response: %v", err)
	}
	if helloResp.Type != "hello" {
		t.Fatalf("expected hello response, got: %s", helloResp.Type)
	}
	if helloResp.Port < 10000 || helloResp.Port > 20000 {
		t.Errorf("allocated port out of range: %d", helloResp.Port)
	}

	cancel()
	wg.Wait()
}
