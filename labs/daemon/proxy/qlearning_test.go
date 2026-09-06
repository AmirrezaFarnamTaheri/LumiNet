package proxy

import (
	"testing"
)

func TestQLearning(t *testing.T) {
	qt := NewQTable()
	state := State("target_ip_blocked")

	// 1. Select action (epsilon-greedy)
	action := qt.SelectAction(state)
	if action < 0 || action >= NumActions {
		t.Errorf("Selected action %d is out of range", action)
	}

	// 2. Update Q value
	nextState := State("target_ip_alive")
	reward := 10.0 // success reward
	qt.UpdateQ(state, action, nextState, reward)

	// Check if Q-value updated
	val := qt.q[state][action]
	if val <= 0.0 {
		t.Errorf("Expected Q-value to increase after positive reward, got: %f", val)
	}
}
