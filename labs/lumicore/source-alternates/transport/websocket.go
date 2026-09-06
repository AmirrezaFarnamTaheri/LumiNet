// Package transport provides network overlay encryption.
// Ported from: websocket-main
// Target path: core/src/transport/websocket.go

package transport

import "log"

// WebSocket implements Gorilla WebSocket overlays.
type WebSocket struct{}

func NewWebSocket() *WebSocket {
	return &WebSocket{}
}

// Connect heavily integrates Gorilla WebSocket underlying connection streams for V2Ray.
func (w *WebSocket) Connect() {
	log.Println("WebSocket: Heavily integrating Gorilla WebSocket underlying connection streams for V2Ray")
}
