package system

import (
	"testing"
)

type mockProgressListener struct {
	messages []string
}

func (m *mockProgressListener) OnProgress(msg string) {
	m.messages = append(m.messages, msg)
}

func TestGomobileAPI(t *testing.T) {
	ml := &mockProgressListener{}
	RegisterProgressListener(ml)

	res := StartT2S(10, "127.0.0.1:1080")
	if res != "SUCCESS" {
		t.Errorf("expected SUCCESS, got %s", res)
	}

	StopT2S()

	if len(ml.messages) != 2 {
		t.Errorf("expected 2 progress callbacks, got %d", len(ml.messages))
	}
	if ml.messages[0] != "Starting Mobile Tun2socks interface" {
		t.Errorf("unexpected message: %s", ml.messages[0])
	}
	if ml.messages[1] != "Stopping Mobile Tun2socks interface" {
		t.Errorf("unexpected message: %s", ml.messages[1])
	}
}
