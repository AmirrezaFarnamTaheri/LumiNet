package proxy

import (
	"math/rand"
	"sync"
	"time"
)

type State string

const (
	ActionNone    = 0
	ActionPadding = 1
	ActionDelay   = 2
	ActionRotate  = 3
	NumActions    = 4
)

type QTable struct {
	mu      sync.RWMutex
	q       map[State][NumActions]float64
	alpha   float64 // Learning rate
	gamma   float64 // Discount factor
	epsilon float64 // Exploration rate
	rng     *rand.Rand
}

func NewQTable() *QTable {
	return &QTable{
		q:       make(map[State][NumActions]float64),
		alpha:   0.1,
		gamma:   0.9,
		epsilon: 0.2,
		rng:     rand.New(rand.NewSource(time.Now().UnixNano())),
	}
}

// SelectAction selects an action using epsilon-greedy policy.
func (qt *QTable) SelectAction(state State) int {
	qt.mu.Lock()
	defer qt.mu.Unlock()

	// Initialize state values if they don't exist
	if _, exists := qt.q[state]; !exists {
		qt.q[state] = [NumActions]float64{}
	}

	// Exploration: choose random action
	if qt.rng.Float64() < qt.epsilon {
		return qt.rng.Intn(NumActions)
	}

	// Exploitation: choose action with max Q-value
	values := qt.q[state]
	maxIdx := 0
	maxVal := values[0]
	for i := 1; i < NumActions; i++ {
		if values[i] > maxVal {
			maxVal = values[i]
			maxIdx = i
		}
	}
	return maxIdx
}

// UpdateQ updates the Q-value for a given state-action pair based on the reward.
func (qt *QTable) UpdateQ(state State, action int, nextState State, reward float64) {
	qt.mu.Lock()
	defer qt.mu.Unlock()

	if _, exists := qt.q[state]; !exists {
		qt.q[state] = [NumActions]float64{}
	}
	if _, exists := qt.q[nextState]; !exists {
		qt.q[nextState] = [NumActions]float64{}
	}

	currentQ := qt.q[state][action]

	// Find max Q for next state
	nextValues := qt.q[nextState]
	maxNextQ := nextValues[0]
	for i := 1; i < NumActions; i++ {
		if nextValues[i] > maxNextQ {
			maxNextQ = nextValues[i]
		}
	}

	// Q-Learning update formula
	newQ := currentQ + qt.alpha*(reward+qt.gamma*maxNextQ-currentQ)
	values := qt.q[state]
	values[action] = newQ
	qt.q[state] = values
}
