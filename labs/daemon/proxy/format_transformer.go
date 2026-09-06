package proxy

import (
	"bytes"
	"fmt"
	"math/bits"
)

// Transition defines a transition in the DFA.
type Transition struct {
	Char      byte
	NextState int
	Value     int // The value this transition represents (in bits)
}

// DFAState represents a state in the format-transforming DFA.
type DFAState struct {
	ID          int
	Transitions []Transition
	IsAccept    bool
}

// FormatTransformer implements format-transforming encryption/encoding (FTE).
// It encodes arbitrary byte slices into strings that match a specific DFA grammar,
// and decodes them back.
type FormatTransformer struct {
	States     map[int]*DFAState
	StartState int
}

// NewFormatTransformer creates a new FormatTransformer.
func NewFormatTransformer() *FormatTransformer {
	return &FormatTransformer{
		States: make(map[int]*DFAState),
	}
}

// AddState adds a state to the DFA.
func (ft *FormatTransformer) AddState(state *DFAState) {
	ft.States[state.ID] = state
}

// NewAlphanumericTransformer creates a transformer that outputs alphanumeric strings.
func NewAlphanumericTransformer() *FormatTransformer {
	ft := NewFormatTransformer()
	// Alphanumeric alphabet: 0-9, a-z, A-Z (62 chars). Let's use 32 transitions (5 bits of choice) for simplicity
	chars := "abcdefghijklmnopqrstuvwxyz234567" // 32 chars
	state := &DFAState{
		ID:       0,
		IsAccept: true,
	}
	for i := 0; i < len(chars); i++ {
		state.Transitions = append(state.Transitions, Transition{
			Char:      chars[i],
			NextState: 0,
			Value:     i,
		})
	}
	ft.AddState(state)
	ft.StartState = 0
	return ft
}

// NewHttpGetRequestTransformer creates a transformer that wraps data in a simulated HTTP GET request.
// Format: GET /<alphanumeric> HTTP/1.1\r\n\r\n
func NewHttpGetRequestTransformer() *FormatTransformer {
	ft := NewFormatTransformer()
	// State 0: 'G'
	// State 1: 'E'
	// State 2: 'T'
	// State 3: ' '
	// State 4: '/'
	// State 5: payload loop (using alphanumeric with 32 choices, transition on end to ' ')
	// State 6: ' '
	// State 7: 'H'
	// State 8: 'T'
	// State 9: 'T'
	// State 10: 'P'
	// State 11: '/'
	// State 12: '1'
	// State 13: '.'
	// State 14: '1'
	// State 15: '\r'
	// State 16: '\n'
	// State 17: '\r'
	// State 18: '\n' (Accept)

	// We define fixed path transitions:
	addFixedPath := func(start int, str string, next int) {
		for i := 0; i < len(str); i++ {
			s := start + i
			n := s + 1
			if i == len(str)-1 {
				n = next
			}
			ft.AddState(&DFAState{
				ID: s,
				Transitions: []Transition{
					{Char: str[i], NextState: n, Value: 0},
				},
				IsAccept: false,
			})
		}
	}

	addFixedPath(0, "GET /", 5)

	// State 5 is the payload state.
	// It can output alphanumeric characters (values 0-31) and stay in State 5.
	// We also need a transition to exit State 5 to State 6 (representing space).
	// To make encoding deterministic: we can specify a special marker or length prefix.
	// In standard FTE, the DFA itself determines when to stop based on the input stream exhaustion.
	// Let's implement State 5 transitions:
	chars := "abcdefghijklmnopqrstuvwxyz234567" // 32 choices (5 bits)
	state5 := &DFAState{
		ID: 5,
	}
	for i := 0; i < len(chars); i++ {
		state5.Transitions = append(state5.Transitions, Transition{
			Char:      chars[i],
			NextState: 5,
			Value:     i,
		})
	}
	// We also add a transition for space ' ' to state 6, which indicates end of payload.
	// To avoid ambiguity during decoding, we define that if we encounter ' ', we transition to state 6.
	state5.Transitions = append(state5.Transitions, Transition{
		Char:      ' ',
		NextState: 6,
		Value:     32, // special value
	})
	ft.AddState(state5)

	addFixedPath(6, "HTTP/1.1\r\n\r\n", 19)

	ft.States[19] = &DFAState{
		ID:       19,
		IsAccept: true,
	}

	ft.StartState = 0
	return ft
}

// Encode transforms a byte stream into a format matching the DFA.
func (ft *FormatTransformer) Encode(data []byte) (string, error) {
	var buf bytes.Buffer
	stateID := ft.StartState

	// Convert bytes to a bit stream
	bits := bytesToBits(data)
	bitOffset := 0

	for {
		state, ok := ft.States[stateID]
		if !ok {
			return "", fmt.Errorf("invalid state: %d", stateID)
		}

		if len(state.Transitions) == 0 {
			if state.IsAccept {
				break
			}
			return "", fmt.Errorf("dead-end state reached: %d", stateID)
		}

		// If we are at the payload loop state and out of bits, we want to transition out of it.
		if stateID == 5 && bitOffset >= len(bits) {
			// Find the exit transition (' ')
			var exitTrans *Transition
			for i := range state.Transitions {
				if state.Transitions[i].Char == ' ' {
					exitTrans = &state.Transitions[i]
					break
				}
			}
			if exitTrans != nil {
				buf.WriteByte(exitTrans.Char)
				stateID = exitTrans.NextState
				continue
			}
		}

		// Count the number of choice transitions (excluding the exit transition ' ' if we still have bits)
		choices := 0
		for _, t := range state.Transitions {
			if stateID == 5 && t.Char == ' ' {
				continue
			}
			choices++
		}

		if choices <= 1 {
			// Deterministic path
			t := state.Transitions[0]
			buf.WriteByte(t.Char)
			stateID = t.NextState
			continue
		}

		// We have multiple choices. Determine how many bits we can consume.
		numBits := bitsNeeded(choices)
		if bitOffset+numBits > len(bits) {
			// Pad the remaining bits with zeros to complete the chunk
			padding := make([]int, bitOffset+numBits-len(bits))
			bits = append(bits, padding...)
		}

		val := bitsToInt(bits[bitOffset : bitOffset+numBits])
		bitOffset += numBits

		// Find the transition corresponding to this value
		var selected *Transition
		for i := range state.Transitions {
			if stateID == 5 && state.Transitions[i].Char == ' ' {
				continue
			}
			if state.Transitions[i].Value == val {
				selected = &state.Transitions[i]
				break
			}
		}

		if selected == nil {
			return "", fmt.Errorf("no transition found for value %d in state %d", val, stateID)
		}

		buf.WriteByte(selected.Char)
		stateID = selected.NextState

		if state.IsAccept && bitOffset >= len(bits) {
			break
		}
	}

	return buf.String(), nil
}

// Decode recovers the original byte stream from the formatted string.
func (ft *FormatTransformer) Decode(str string) ([]byte, error) {
	var bitList []int
	stateID := ft.StartState
	strIndex := 0

	for strIndex < len(str) {
		state, ok := ft.States[stateID]
		if !ok {
			return nil, fmt.Errorf("invalid state: %d", stateID)
		}

		char := str[strIndex]
		strIndex++

		// Find matching transition
		var matched *Transition
		for i := range state.Transitions {
			if state.Transitions[i].Char == char {
				matched = &state.Transitions[i]
				break
			}
		}

		if matched == nil {
			return nil, fmt.Errorf("invalid character '%c' in state %d", char, stateID)
		}

		// Count the choices to determine how many bits this state choice encoded
		choices := 0
		for _, t := range state.Transitions {
			if stateID == 5 && t.Char == ' ' {
				continue
			}
			choices++
		}

		if choices > 1 && matched.Char != ' ' {
			numBits := bitsNeeded(choices)
			bitsSlice := intToBits(matched.Value, numBits)
			bitList = append(bitList, bitsSlice...)
		}

		stateID = matched.NextState
	}

	// Reconstruct bytes from bits
	return bitsToBytes(bitList), nil
}

func bitsNeeded(n int) int {
	if n <= 1 {
		return 0
	}
	return bits.Len(uint(n - 1))
}

func bytesToBits(data []byte) []int {
	bitsSlice := make([]int, len(data)*8)
	for i, b := range data {
		for j := 0; j < 8; j++ {
			bitsSlice[i*8+j] = int((b >> uint(7-j)) & 1)
		}
	}
	return bitsSlice
}

func bitsToBytes(bitsSlice []int) []byte {
	numBytes := len(bitsSlice) / 8
	data := make([]byte, numBytes)
	for i := 0; i < numBytes; i++ {
		var val byte
		for j := 0; j < 8; j++ {
			val |= byte(bitsSlice[i*8+j]) << uint(7-j)
		}
		data[i] = val
	}
	return data
}

func bitsToInt(bitsSlice []int) int {
	val := 0
	for _, b := range bitsSlice {
		val = (val << 1) | b
	}
	return val
}

func intToBits(val, numBits int) []int {
	bitsSlice := make([]int, numBits)
	for i := 0; i < numBits; i++ {
		bitsSlice[numBits-1-i] = (val >> uint(i)) & 1
	}
	return bitsSlice
}
