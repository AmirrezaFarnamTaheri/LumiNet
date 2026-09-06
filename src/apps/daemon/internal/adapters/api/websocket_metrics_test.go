package api

import "testing"

func TestHubBackpressureStatsCountBroadcastDropsAndSlowClients(t *testing.T) {
	hub := NewHub(nil)

	for i := 0; i < cap(hub.broadcast); i++ {
		hub.broadcast <- &wsBroadcast{eventType: "FILL"}
	}
	hub.enqueueBroadcast(&wsBroadcast{eventType: "DROP"})
	if got := hub.Stats(); got.BroadcastDrops != 1 || got.SlowClientDisconnects != 0 {
		t.Fatalf("Stats after broadcast pressure = %+v, want drops=1 slow=0", got)
	}

	client := &Client{
		hub:           hub,
		send:          make(chan []byte, 1),
		subscriptions: map[string]bool{"*": true},
	}
	client.send <- []byte("already full")
	hub.clients[client] = true
	hub.deliverBroadcast(&wsBroadcast{eventType: "TEST"})

	got := hub.Stats()
	if got.BroadcastDrops != 1 || got.SlowClientDisconnects != 1 {
		t.Fatalf("Stats after slow client = %+v, want drops=1 slow=1", got)
	}
	if _, ok := hub.clients[client]; ok {
		t.Fatal("slow client remained registered")
	}
}
