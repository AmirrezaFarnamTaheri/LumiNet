package proxy

import (
	"sync"
)

type SNISpoofConfig struct {
	Enabled           bool
	TargetSNI         string
	FakeSNI           string
	InjectWrongSeq    bool
	FragmentationSize int
}

// SNISpoofingInjector modifies outbound handshakes to override target SNIs.
type SNISpoofingInjector struct {
	mu            sync.Mutex
	cfg           SNISpoofConfig
	injectedCount int
}

func NewSNISpoofingInjector(cfg SNISpoofConfig) *SNISpoofingInjector {
	return &SNISpoofingInjector{cfg: cfg}
}

func (s *SNISpoofingInjector) UpdateConfig(cfg SNISpoofConfig) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cfg = cfg
}

func (s *SNISpoofingInjector) GetStats() map[string]interface{} {
	s.mu.Lock()
	defer s.mu.Unlock()
	return map[string]interface{}{
		"injected_count":     s.injectedCount,
		"active":             s.cfg.Enabled,
		"target_sni":         s.cfg.TargetSNI,
		"fake_sni":           s.cfg.FakeSNI,
		"fragmentation_size": s.cfg.FragmentationSize,
	}
}

func (s *SNISpoofingInjector) ProcessHandshake(sni string) string {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.cfg.Enabled {
		return sni
	}

	if s.cfg.TargetSNI == "" || sni == s.cfg.TargetSNI {
		s.injectedCount++
		return s.cfg.FakeSNI
	}

	return sni
}

// NewSniSpoofConfig returns a default SNISpoofConfig with google.com as the fake SNI.
func NewSniSpoofConfig() *SNISpoofConfig {
	return &SNISpoofConfig{
		Enabled:           true,
		FakeSNI:           "google.com",
		FragmentationSize: 40,
	}
}
