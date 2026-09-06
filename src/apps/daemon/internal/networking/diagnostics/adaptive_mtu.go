package diagnostics

type AdaptiveMtuDiscovery struct {
	MinMtu       uint16
	MaxMtu       uint16
	CurrentProbe uint16
	ConvergedMtu *uint16
}

func NewAdaptiveMtuDiscovery(minMtu, maxMtu uint16) *AdaptiveMtuDiscovery {
	probe := (minMtu + maxMtu) / 2
	return &AdaptiveMtuDiscovery{
		MinMtu:       minMtu,
		MaxMtu:       maxMtu,
		CurrentProbe: probe,
	}
}

func (a *AdaptiveMtuDiscovery) NextProbeSize() uint16 {
	return a.CurrentProbe
}

func (a *AdaptiveMtuDiscovery) RecordResult(size uint16, success bool) {
	if success {
		a.MinMtu = size
	} else {
		if size > 0 {
			a.MaxMtu = size - 1
		}
	}

	if a.MinMtu >= a.MaxMtu {
		conv := a.MinMtu
		a.ConvergedMtu = &conv
	} else {
		a.CurrentProbe = (a.MinMtu + a.MaxMtu + 1) / 2
	}
}

func (a *AdaptiveMtuDiscovery) OptimalMtu() uint16 {
	if a.ConvergedMtu != nil {
		return *a.ConvergedMtu
	}
	return a.MinMtu
}

func (a *AdaptiveMtuDiscovery) WireguardPayloadMtu(isIPv6 bool) uint16 {
	overhead := uint16(60)
	if isIPv6 {
		overhead = 80
	}
	opt := a.OptimalMtu()
	if opt > overhead {
		return opt - overhead
	}
	return 1280
}

func (a *AdaptiveMtuDiscovery) OptimalKeepaliveSecs() uint32 {
	if a.OptimalMtu() < 1360 {
		return 15
	}
	return 25
}
