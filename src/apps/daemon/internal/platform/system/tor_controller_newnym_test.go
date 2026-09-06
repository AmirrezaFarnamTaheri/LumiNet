package system

import (
	"bufio"
	"net"
	"strings"

	"github.com/maybeknott/luminet/internal/foundation/boundedio"
	"testing"
)

func TestSignalNewNymSendsBoundedControlCommand(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	controller := &TorController{conn: client, reader: bufio.NewReader(client)}
	done := make(chan string, 1)
	go func() {
		line, _ := boundedio.ReadLine(bufio.NewReader(server), maxTorControlLineBytes)
		done <- strings.TrimSpace(line)
		_, _ = server.Write([]byte("250 OK\r\n"))
	}()

	if err := controller.SignalNewNym(); err != nil {
		t.Fatalf("SignalNewNym: %v", err)
	}
	if got := <-done; got != "SIGNAL NEWNYM" {
		t.Fatalf("control command = %q, want SIGNAL NEWNYM", got)
	}
}
