package transport

type SniDecoyInjector struct {
	DecoyDomain string
}

func NewSniDecoyInjector(decoy string) *SniDecoyInjector {
	return &SniDecoyInjector{DecoyDomain: decoy}
}

func (s *SniDecoyInjector) InjectDecoy(realClientHello []byte) [][]byte {
	decoy := append([]byte{0x16, 0x03, 0x01, 0x00, 0x10}, []byte(s.DecoyDomain)...)
	return [][]byte{decoy, realClientHello}
}
