package security

import "sort"

type EvasionTrait string

const (
	TraitTlsSpoofing   EvasionTrait = "tls_spoofing"
	TraitPadding       EvasionTrait = "record_padding"
	TraitSniFrag       EvasionTrait = "sni_fragmentation"
	TraitMultipathUdp  EvasionTrait = "multipath_udp"
	TraitReplayDefense EvasionTrait = "replay_defense"
)

type ProtocolProfile struct {
	Name            string
	Traits          map[EvasionTrait]bool
	ResistanceScore int
	OverheadRatio   float32
}

type ProtocolMatrix struct {
	profiles []ProtocolProfile
}

func NewProtocolMatrix() *ProtocolMatrix {
	m := &ProtocolMatrix{profiles: make([]ProtocolProfile, 0)}
	m.RegisterDefaultProfiles()
	return m
}

func (m *ProtocolMatrix) RegisterDefaultProfiles() {
	m.profiles = append(m.profiles, ProtocolProfile{
		Name: "Hysteria2",
		Traits: map[EvasionTrait]bool{
			TraitMultipathUdp: true,
			TraitPadding:      true,
			TraitTlsSpoofing:  true,
		},
		ResistanceScore: 95,
		OverheadRatio:   1.08,
	})
	m.profiles = append(m.profiles, ProtocolProfile{
		Name: "VLESS-Reality",
		Traits: map[EvasionTrait]bool{
			TraitTlsSpoofing:   true,
			TraitReplayDefense: true,
			TraitPadding:       true,
		},
		ResistanceScore: 92,
		OverheadRatio:   1.02,
	})
	m.profiles = append(m.profiles, ProtocolProfile{
		Name: "Trojan-SNI-Fragment",
		Traits: map[EvasionTrait]bool{
			TraitSniFrag:     true,
			TraitTlsSpoofing: true,
		},
		ResistanceScore: 88,
		OverheadRatio:   1.05,
	})
}

func (m *ProtocolMatrix) Recommend(required []EvasionTrait) *ProtocolProfile {
	candidates := make([]ProtocolProfile, 0)
	for _, p := range m.profiles {
		hasAll := true
		for _, req := range required {
			if !p.Traits[req] {
				hasAll = false
				break
			}
		}
		if hasAll {
			candidates = append(candidates, p)
		}
	}

	if len(candidates) == 0 {
		return nil
	}

	sort.Slice(candidates, func(i, j int) bool {
		return candidates[i].ResistanceScore > candidates[j].ResistanceScore
	})
	res := candidates[0]
	return &res
}
