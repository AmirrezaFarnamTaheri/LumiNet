package system

import (
	"bufio"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/maybeknott/luminet/internal/foundation/boundedio"
)

func pipeTorController(t *testing.T) (*TorController, net.Conn) {
	t.Helper()
	client, server := net.Pipe()
	t.Cleanup(func() {
		_ = client.Close()
		_ = server.Close()
	})
	return &TorController{conn: client, reader: bufio.NewReader(client)}, server
}

func TestTorControllerRejectsInjectedCommandBeforeWrite(t *testing.T) {
	controller, server := pipeTorController(t)
	controller.commandTimeout = 50 * time.Millisecond

	if _, err := controller.SendRawCommand("SIGNAL NEWNYM\r\nQUIT"); err == nil {
		t.Fatal("newline-bearing control command was accepted")
	}
	_ = server.SetReadDeadline(time.Now().Add(20 * time.Millisecond))
	buf := make([]byte, 1)
	if n, err := server.Read(buf); err == nil || n != 0 {
		t.Fatalf("rejected command wrote %d bytes, err=%v", n, err)
	}
}

func TestTorControllerSkipsAsyncEventBeforeReply(t *testing.T) {
	controller, server := pipeTorController(t)
	done := make(chan struct{})
	go func() {
		defer close(done)
		line, _ := boundedio.ReadLine(bufio.NewReader(server), maxTorControlLineBytes)
		if strings.TrimSpace(line) != "SIGNAL NEWNYM" {
			return
		}
		_, _ = server.Write([]byte("650 STATUS_CLIENT NOTICE BOOTSTRAP PROGRESS=80\r\n250 OK\r\n"))
	}()

	reply, err := controller.SendRawCommand("SIGNAL NEWNYM")
	if err != nil {
		t.Fatalf("SendRawCommand: %v", err)
	}
	if strings.TrimSpace(reply) != "250 OK" {
		t.Fatalf("reply=%q, want only command reply", reply)
	}
	<-done
}

func TestTorControllerConsumesDataReplyAndDotUnstuffs(t *testing.T) {
	controller, server := pipeTorController(t)
	go func() {
		_, _ = boundedio.ReadLine(bufio.NewReader(server), maxTorControlLineBytes)
		_, _ = server.Write([]byte("250+config-text=\r\nalpha\r\n..dot-prefixed\r\n.\r\n250 OK\r\n"))
	}()

	reply, err := controller.SendRawCommand("GETINFO config-text")
	if err != nil {
		t.Fatalf("SendRawCommand: %v", err)
	}
	for _, want := range []string{"250+config-text=", "alpha", ".dot-prefixed", "250 OK"} {
		if !strings.Contains(reply, want) {
			t.Fatalf("reply=%q missing %q", reply, want)
		}
	}
}

func TestTorControllerBoundsWholeReply(t *testing.T) {
	controller, server := pipeTorController(t)
	go func() {
		_, _ = boundedio.ReadLine(bufio.NewReader(server), maxTorControlLineBytes)
		chunk := strings.Repeat("x", 60<<10)
		for i := 0; i < 18; i++ {
			if _, err := server.Write([]byte("250-" + chunk + "\r\n")); err != nil {
				return
			}
		}
		_, _ = server.Write([]byte("250 OK\r\n"))
	}()

	if _, err := controller.SendRawCommand("GETINFO version"); err == nil || !strings.Contains(err.Error(), "reply exceeds") {
		t.Fatalf("oversized reply error=%v", err)
	}
}

func TestTorControllerCommandTimeoutBreaksConnection(t *testing.T) {
	controller, server := pipeTorController(t)
	controller.commandTimeout = 30 * time.Millisecond
	go func() {
		_, _ = boundedio.ReadLine(bufio.NewReader(server), maxTorControlLineBytes)
		<-time.After(100 * time.Millisecond)
	}()

	if _, err := controller.SendRawCommand("GETINFO version"); err == nil {
		t.Fatal("command without reply did not time out")
	}
	if controller.conn != nil || controller.reader != nil {
		t.Fatal("timed-out connection remained reusable")
	}
}

func TestTorControllerBootstrapProgressRequiresValidProgress(t *testing.T) {
	tests := []struct {
		name    string
		reply   string
		want    int
		wantErr bool
	}{
		{name: "ready", reply: "250-status/bootstrap-phase=NOTICE BOOTSTRAP PROGRESS=100 TAG=done\r\n250 OK\r\n", want: 100},
		{name: "partial", reply: "250-status/bootstrap-phase=NOTICE BOOTSTRAP PROGRESS=45 TAG=loading\r\n250 OK\r\n", want: 45},
		{name: "missing", reply: "250 OK\r\n", wantErr: true},
		{name: "out-of-range", reply: "250-status/bootstrap-phase=NOTICE BOOTSTRAP PROGRESS=101\r\n250 OK\r\n", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			controller, server := pipeTorController(t)
			go func() {
				_, _ = boundedio.ReadLine(bufio.NewReader(server), maxTorControlLineBytes)
				_, _ = server.Write([]byte(tt.reply))
			}()
			got, err := controller.BootstrapProgress()
			if tt.wantErr {
				if err == nil {
					t.Fatalf("BootstrapProgress=%d, want error", got)
				}
				return
			}
			if err != nil || got != tt.want {
				t.Fatalf("BootstrapProgress=%d err=%v, want %d", got, err, tt.want)
			}
		})
	}
}

func TestParseReplyMarksDataHeader(t *testing.T) {
	lines := ParseReply("250+config-text=\nalpha\n250 OK\n")
	if len(lines) != 3 || !lines[0].Multi || !lines[0].Data || lines[0].Status != 250 {
		t.Fatalf("ParseReply=%#v", lines)
	}
	if lines[1].Status != 0 || lines[2].Status != 250 || lines[2].Multi {
		t.Fatalf("ParseReply=%#v", lines)
	}
}
