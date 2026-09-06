package runtimecore

// Capability describes whether a long-lived runtime engine can be started on
// this host without mutating runtime state. BinaryPath is operator evidence;
// callers must still handle the binary disappearing before Start.
type Capability struct {
	Engine     Engine `json:"engine"`
	Available  bool   `json:"available"`
	BinaryPath string `json:"binary_path,omitempty"`
	Mode       string `json:"mode"`
	Reason     string `json:"reason,omitempty"`
}

// ProbeEngine performs a read-only executable discovery for a runtime engine.
func ProbeEngine(kind Engine) Capability {
	var (
		path string
		err  error
		mode = "socks"
	)
	switch kind {
	case EngineTor:
		path, err = newTorEngine(10950, 10951).FindBinary()
	case EnginePsiphon:
		path, err = newPsiphonEngine(10890).FindBinary()
	case EngineSSTP:
		mode = "system-tunnel"
		path, err = (&sstpEngine{}).FindBinary()
	case EngineIKEv2:
		mode = "system-tunnel"
		path, err = (&ikev2Engine{}).FindBinary()
	default:
		return Capability{Engine: kind, Mode: "unknown", Reason: "unsupported runtime engine"}
	}
	if err != nil {
		return Capability{Engine: kind, Mode: mode, Available: false, Reason: err.Error()}
	}
	return Capability{Engine: kind, Mode: mode, Available: true, BinaryPath: path}
}
