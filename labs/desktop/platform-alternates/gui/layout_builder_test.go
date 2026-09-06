package gui

import "testing"

func TestClientGuiCreation(t *testing.T) {
	win, err := CreateMainWindow("LumiNet Dashboard", 800, 600)
	if err != nil {
		t.Fatalf("expected no error creating main window: %v", err)
	}

	if win.Title != "LumiNet Dashboard" || win.Width != 800 || win.Height != 600 {
		t.Errorf("unexpected window properties: %+v", win)
	}

	clicked := false
	btn := AddButton(win, "Connect", func() {
		clicked = true
	})

	if btn.Label != "Connect" {
		t.Errorf("expected button label 'Connect', got %s", btn.Label)
	}

	btn.OnClick()
	if !clicked {
		t.Error("expected click handler to trigger")
	}

	builder := NewClientLayoutBuilder()
	builder.AddWidget("SideSidebar")
	builder.AddWidget("ConnectRing")
	builder.AddWidget("StatusLabel")

	layoutStr := builder.BuildLayout()
	expectedLayout := "GUI Layout Flow: [SideSidebar ConnectRing StatusLabel]"
	if layoutStr != expectedLayout {
		t.Errorf("expected layout %q, got %q", expectedLayout, layoutStr)
	}
}
