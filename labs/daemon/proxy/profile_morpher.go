package proxy

import (
	"crypto/rand"
	"math/big"
	"strings"
)

// TrafficProfile defines statistical distributions to mimic.
type TrafficProfile struct {
	Name            string
	PacketSizes     []int
	PacketSizeProbs []float64
	MinPadding      int
	MaxPadding      int
}

var (
	// YandexVideoProfile mimics Yandex Video stream packet distributions.
	YandexVideoProfile = &TrafficProfile{
		Name:            "Yandex Video",
		PacketSizes:     []int{200, 600, 1200, 1400},
		PacketSizeProbs: []float64{0.10, 0.20, 0.35, 0.35},
		MinPadding:      50,
		MaxPadding:      200,
	}

	// BaiduVideoProfile mimics Baidu Video stream packet distributions.
	BaiduVideoProfile = &TrafficProfile{
		Name:            "Baidu Video",
		PacketSizes:     []int{250, 700, 1100, 1450},
		PacketSizeProbs: []float64{0.12, 0.18, 0.35, 0.35},
		MinPadding:      60,
		MaxPadding:      250,
	}
)

// ProfileMorpher applies statistical payload sizing to make traffic match traffic profiles.
type ProfileMorpher struct {
	Profile *TrafficProfile
}

// NewProfileMorpher builds a ProfileMorpher for the given profile.
func NewProfileMorpher(profileName string) *ProfileMorpher {
	var prof *TrafficProfile
	switch strings.ToLower(profileName) {
	case "yandex", "yandexvideo":
		prof = YandexVideoProfile
	case "baidu", "baiduvideo":
		prof = BaiduVideoProfile
	default:
		prof = YandexVideoProfile
	}
	return &ProfileMorpher{Profile: prof}
}

// ChooseTargetSize returns a target packet size matching the profile's PDF.
func (pm *ProfileMorpher) ChooseTargetSize() int {
	n, err := rand.Int(rand.Reader, big.NewInt(10000))
	if err != nil {
		return pm.Profile.PacketSizes[len(pm.Profile.PacketSizes)-1]
	}
	r := float64(n.Int64()) / 10000.0
	var cumulative float64
	for i, prob := range pm.Profile.PacketSizeProbs {
		cumulative += prob
		if r <= cumulative {
			return pm.Profile.PacketSizes[i]
		}
	}
	return pm.Profile.PacketSizes[len(pm.Profile.PacketSizes)-1]
}

// Morph frames the payload into a profile-matching size.
func (pm *ProfileMorpher) Morph(payload []byte) []byte {
	targetSize := pm.ChooseTargetSize()
	if len(payload) >= targetSize {
		// If already larger, we add minimum padding to disrupt signature analysis
		padLen := pm.Profile.MinPadding
		n, err := rand.Int(rand.Reader, big.NewInt(int64(pm.Profile.MaxPadding-pm.Profile.MinPadding+1)))
		if err == nil {
			padLen += int(n.Int64())
		}
		targetSize = len(payload) + padLen
	}

	padded := make([]byte, targetSize)
	copy(padded, payload)
	_, _ = rand.Read(padded[len(payload):])

	finalPayload := make([]byte, targetSize+4)
	finalPayload[0] = byte(len(payload) >> 24)
	finalPayload[1] = byte(len(payload) >> 16)
	finalPayload[2] = byte(len(payload) >> 8)
	finalPayload[3] = byte(len(payload))
	copy(finalPayload[4:], padded)

	return finalPayload
}

// Restore unwraps the morphed payload and returns the original content.
func (pm *ProfileMorpher) Restore(morphed []byte) ([]byte, error) {
	if len(morphed) < 4 {
		return nil, nil
	}

	length := (int(morphed[0]) << 24) |
		(int(morphed[1]) << 16) |
		(int(morphed[2]) << 8) |
		int(morphed[3])

	if length < 0 || length > len(morphed)-4 {
		return nil, nil
	}

	original := make([]byte, length)
	copy(original, morphed[4:4+length])
	return original, nil
}
