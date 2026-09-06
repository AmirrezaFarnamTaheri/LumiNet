package gui

import (
	"fmt"
	"log"
)

// ClientWindow represents a window in the desktop GUI application.
type ClientWindow struct {
	Title  string
	Width  int
	Height int
}

// ClientButton represents a button widget.
type ClientButton struct {
	Label   string
	OnClick func()
}

// ClientLayoutBuilder constructs custom grid/box layouts.
type ClientLayoutBuilder struct {
	widgets []string
}

// NewClientLayoutBuilder creates a new layout builder instance.
func NewClientLayoutBuilder() *ClientLayoutBuilder {
	return &ClientLayoutBuilder{
		widgets: make([]string, 0),
	}
}

// AddWidget registers a widget type into the layout flow.
func (b *ClientLayoutBuilder) AddWidget(name string) {
	b.widgets = append(b.widgets, name)
}

// BuildLayout compiles the widgets into a structured layout schema.
func (b *ClientLayoutBuilder) BuildLayout() string {
	return fmt.Sprintf("GUI Layout Flow: %v", b.widgets)
}

// CreateMainWindow initializes the main application window.
func CreateMainWindow(title string, w, h int) (*ClientWindow, error) {
	log.Printf("Initializing GUI Window: %s (%dx%d)", title, w, h)
	return &ClientWindow{
		Title:  title,
		Width:  w,
		Height: h,
	}, nil
}

// AddButton attaches a button to a window with a click callback.
func AddButton(win *ClientWindow, label string, action func()) *ClientButton {
	log.Printf("Adding button %q to window %s", label, win.Title)
	return &ClientButton{
		Label:   label,
		OnClick: action,
	}
}
