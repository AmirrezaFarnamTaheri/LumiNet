package proxy

import (
	"bytes"
	"encoding/binary"
	"math/rand"
)

// EmulateHTTP2Preface restructures the initial HTTP/2 settings and window parameters
// to align with modern browser fingerprints (e.g. Chrome vs Firefox HTTP/2 SETTINGS).
func EmulateHTTP2Preface(payload []byte, fingerprint string) []byte {
	preface := []byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")
	if !bytes.HasPrefix(payload, preface) {
		return payload
	}

	// Rebuild settings frame based on the target browser signature
	var settingsFrame []byte
	switch fingerprint {
	case "firefox", "firefox120":
		// Firefox HTTP/2 Settings
		settingsFrame = buildSettingsFrame([]SettingsEntry{
			{ID: 1, Val: 65536},  // HEADER_TABLE_SIZE
			{ID: 3, Val: 100},    // MAX_CONCURRENT_STREAMS
			{ID: 4, Val: 131072}, // INITIAL_WINDOW_SIZE
			{ID: 5, Val: 16384},  // MAX_FRAME_SIZE
		})
	default:
		// Chrome HTTP/2 Settings (Standard chrome-like settings)
		settingsFrame = buildSettingsFrame([]SettingsEntry{
			{ID: 1, Val: 65536},   // HEADER_TABLE_SIZE
			{ID: 2, Val: 0},       // ENABLE_PUSH (0)
			{ID: 4, Val: 6291456}, // INITIAL_WINDOW_SIZE
			{ID: 6, Val: 262144},  // MAX_HEADER_LIST_SIZE
		})
	}

	// Append a Window Update frame (Frame Type 0x8) to mimic typical flow control
	var windowUpdateFrame []byte
	switch fingerprint {
	case "firefox", "firefox120":
		windowUpdateFrame = buildWindowUpdateFrame(0, 12517377)
	default:
		windowUpdateFrame = buildWindowUpdateFrame(0, 15663105+uint32(rand.Intn(100)))
	}

	// Reassemble payload: Preface + Settings Frame + Window Update + remaining content
	var buf bytes.Buffer
	buf.Write(preface)
	buf.Write(settingsFrame)
	buf.Write(windowUpdateFrame)

	// Skip standard settings frames in the original client request to avoid duplicates
	originalContent := payload[len(preface):]
	if len(originalContent) >= 9 {
		// Verify if it is a SETTINGS frame (Frame Type 0x4)
		frameType := originalContent[3]
		if frameType == 0x4 {
			frameLength := binary.BigEndian.Uint32(append([]byte{0}, originalContent[0:3]...))
			totalLen := int(9 + frameLength)
			if len(originalContent) >= totalLen {
				originalContent = originalContent[totalLen:]
			}
		}
	}

	buf.Write(originalContent)
	return buf.Bytes()
}

type SettingsEntry struct {
	ID  uint16
	Val uint32
}

func buildSettingsFrame(entries []SettingsEntry) []byte {
	length := uint32(len(entries) * 6)
	frame := make([]byte, 9+length)

	// Length (3 bytes)
	frame[0] = byte(length >> 16)
	frame[1] = byte(length >> 8)
	frame[2] = byte(length)

	// Type (Settings = 0x4)
	frame[3] = 0x4

	// Flags (0x0)
	frame[4] = 0x0

	// Stream ID (0)
	binary.BigEndian.PutUint32(frame[5:9], 0)

	// Payload entries
	offset := 9
	for _, entry := range entries {
		binary.BigEndian.PutUint16(frame[offset:offset+2], entry.ID)
		binary.BigEndian.PutUint32(frame[offset+2:offset+6], entry.Val)
		offset += 6
	}

	return frame
}

func buildWindowUpdateFrame(streamID uint32, increment uint32) []byte {
	frame := make([]byte, 13)

	// Length (4 bytes = 0x000004)
	frame[0] = 0
	frame[1] = 0
	frame[2] = 4

	// Type (Window Update = 0x8)
	frame[3] = 0x8

	// Flags (0x0)
	frame[4] = 0x0

	// Stream ID
	binary.BigEndian.PutUint32(frame[5:9], streamID)

	// Window Size Increment
	binary.BigEndian.PutUint32(frame[9:13], increment)

	return frame
}
