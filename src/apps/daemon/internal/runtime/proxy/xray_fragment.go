package proxy

import (
	"fmt"
	"strconv"
	"strings"
)

// XrayFragmentSettings mirrors the `settings.fragment` block of an Xray
// freedom-outbound used to defeat SNI-based blocking by splitting TLS records.
//
//   - Packets: "tlshello" fragments only the TLS ClientHello, or a range such
//     as "1-3" fragmenting every packet of that length class.
//   - Length:  "min-max" byte range each fragment is cut into.
//   - Interval: "min-max" milliseconds between fragments.
//
// Upstream presets observed in the wild: tlshello/10-20/10-20,
// tlshello/100-200/10-20, 1-3/10-20/10-20.
type XrayFragmentSettings struct {
	Packets  string
	Length   string
	Interval string
}

// Validate checks the three fields against the grammar accepted by Xray-core.
func (f XrayFragmentSettings) Validate() error {
	switch f.Packets {
	case "tlshello":
	case "":
		return fmt.Errorf("fragment packets is empty")
	default:
		if err := validateRange(f.Packets); err != nil {
			return fmt.Errorf("fragment packets %q: %w", f.Packets, err)
		}
	}
	for _, field := range []struct{ name, value string }{{"length", f.Length}, {"interval", f.Interval}} {
		if err := validateRange(field.value); err != nil {
			return fmt.Errorf("fragment %s %q: %w", field.name, field.value, err)
		}
	}
	return nil
}

func validateRange(value string) error {
	parts := strings.SplitN(value, "-", 2)
	if len(parts) != 2 {
		return fmt.Errorf("expected min-max range")
	}
	minimum, err1 := strconv.Atoi(strings.TrimSpace(parts[0]))
	maximum, err2 := strconv.Atoi(strings.TrimSpace(parts[1]))
	if err1 != nil || err2 != nil {
		return fmt.Errorf("non-numeric bounds")
	}
	if minimum < 0 || maximum < minimum {
		return fmt.Errorf("bounds must satisfy 0 <= min <= max")
	}
	return nil
}

// Apply inserts the settings.fragment block into an Xray outbound map
// (freedom outbound). No-op when the settings fail validation — callers that
// require strictness should Validate first.
func (f XrayFragmentSettings) Apply(outbound map[string]any) {
	if err := f.Validate(); err != nil {
		return
	}
	outbound["fragment"] = map[string]any{
		"packets":  f.Packets,
		"length":   f.Length,
		"interval": f.Interval,
	}
}

// ParseXrayFragmentSettings builds settings from "packets,length,interval".
func ParseXrayFragmentSettings(csv string) (XrayFragmentSettings, error) {
	parts := strings.Split(csv, ",")
	if len(parts) != 3 {
		return XrayFragmentSettings{}, fmt.Errorf("expected packets,length,interval")
	}
	settings := XrayFragmentSettings{
		Packets:  strings.TrimSpace(parts[0]),
		Length:   strings.TrimSpace(parts[1]),
		Interval: strings.TrimSpace(parts[2]),
	}
	if err := settings.Validate(); err != nil {
		return XrayFragmentSettings{}, err
	}
	return settings, nil
}
