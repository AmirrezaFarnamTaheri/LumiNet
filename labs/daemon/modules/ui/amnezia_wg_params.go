// Package ui implements AmneziaWG obfuscation parameter generation and validation,
// ported from 3ax-ui-main.
// Source: 3ax-ui-main/awg/params.go
// Target: server/internal/ui/amnezia_wg_params.go

package ui

import (
	"fmt"
	"strconv"
	"strings"
)

// AwgHMax is the upper bound for H1-H4 values (2^31-1) for cross-client compatibility.
// Source: awg/params.go awgHMax
const AwgHMax = 2147483647

// AwgHMaxValid is the largest accepted H value at the kernel level (uint32 max).
// Source: awg/params.go hMaxValid
const AwgHMaxValid int64 = 4294967295

// AwgHMinWidth is the minimum width of each H1-H4 range.
// Source: awg/params.go hMinWidth
const AwgHMinWidth = 1000

// AwgObfuscation20 is a generated AmneziaWG 2.0 obfuscation parameter set.
// Source: awg/params.go Obfuscation20
type AwgObfuscation20 struct {
	Jc   int    `json:"jc"`
	Jmin int    `json:"jmin"`
	Jmax int    `json:"jmax"`
	S1   int    `json:"s1"`
	S2   int    `json:"s2"`
	S3   int    `json:"s3"`
	S4   int    `json:"s4"`
	H1   string `json:"h1"`
	H2   string `json:"h2"`
	H3   string `json:"h3"`
	H4   string `json:"h4"`
	I1   string `json:"i1"`
}

func (o *AwgObfuscation20) GetJc() int    { return o.Jc }
func (o *AwgObfuscation20) SetJc(v int)   { o.Jc = v }
func (o *AwgObfuscation20) GetJmin() int  { return o.Jmin }
func (o *AwgObfuscation20) SetJmin(v int) { o.Jmin = v }
func (o *AwgObfuscation20) GetJmax() int  { return o.Jmax }
func (o *AwgObfuscation20) SetJmax(v int) { o.Jmax = v }
func (o *AwgObfuscation20) GetS1() int    { return o.S1 }
func (o *AwgObfuscation20) SetS1(v int)   { o.S1 = v }
func (o *AwgObfuscation20) GetS2() int    { return o.S2 }
func (o *AwgObfuscation20) SetS2(v int)   { o.S2 = v }
func (o *AwgObfuscation20) GetS3() int    { return o.S3 }
func (o *AwgObfuscation20) SetS3(v int)   { o.S3 = v }
func (o *AwgObfuscation20) GetS4() int    { return o.S4 }
func (o *AwgObfuscation20) SetS4(v int)   { o.S4 = v }
func (o *AwgObfuscation20) GetH1() string { return o.H1 }
func (o *AwgObfuscation20) SetH1(v string){ o.H1 = v }
func (o *AwgObfuscation20) GetH2() string { return o.H2 }
func (o *AwgObfuscation20) SetH2(v string){ o.H2 = v }
func (o *AwgObfuscation20) GetH3() string { return o.H3 }
func (o *AwgObfuscation20) SetH3(v string){ o.H3 = v }
func (o *AwgObfuscation20) GetH4() string { return o.H4 }
func (o *AwgObfuscation20) SetH4(v string){ o.H4 = v }
func (o *AwgObfuscation20) GetI1() string { return o.I1 }
func (o *AwgObfuscation20) SetI1(v string){ o.I1 = v }

// ValidateAwgObfuscationServer validates obfuscation parameters for an AwgServer.
// Source: awg/params.go ValidateObfuscation
func ValidateAwgObfuscationServer(s *AwgServer) error {
	if s.Jmin > s.Jmax {
		return fmt.Errorf("invalid Jmin/Jmax: %d must not exceed %d", s.Jmin, s.Jmax)
	}
	if s.S3 < 0 || s.S3 > 64 {
		return fmt.Errorf("invalid S3 value %d (must be 0..64)", s.S3)
	}
	if s.S4 < 0 || s.S4 > 32 {
		return fmt.Errorf("invalid S4 value %d (must be 0..32)", s.S4)
	}
	for i, h := range []string{s.H1, s.H2, s.H3, s.H4} {
		if err := validateAwgHValue(h); err != nil {
			return fmt.Errorf("invalid H%d: %w", i+1, err)
		}
	}
	return nil
}

// ValidateAwgObfuscation20 validates an AwgObfuscation20 parameter set.
// Source: awg/params.go ValidateObfuscation (adapted for Obfuscation20 struct).
func ValidateAwgObfuscation20(o *AwgObfuscation20) error {
	if o.Jmin > o.Jmax {
		return fmt.Errorf("invalid Jmin/Jmax: %d must not exceed %d", o.Jmin, o.Jmax)
	}
	if o.S3 < 0 || o.S3 > 64 {
		return fmt.Errorf("invalid S3 value %d (must be 0..64)", o.S3)
	}
	if o.S4 < 0 || o.S4 > 32 {
		return fmt.Errorf("invalid S4 value %d (must be 0..32)", o.S4)
	}
	for i, h := range []string{o.H1, o.H2, o.H3, o.H4} {
		if err := validateAwgHValue(h); err != nil {
			return fmt.Errorf("invalid H%d: %w", i+1, err)
		}
	}
	return nil
}

// validateAwgHValue checks one H parameter: empty, a single uint32, or "low-high" range.
// Source: awg/params.go validateHValue
func validateAwgHValue(v string) error {
	v = strings.TrimSpace(v)
	if v == "" {
		return nil
	}
	if lo, hi, isRange := strings.Cut(v, "-"); isRange {
		l, err1 := strconv.ParseInt(strings.TrimSpace(lo), 10, 64)
		h, err2 := strconv.ParseInt(strings.TrimSpace(hi), 10, 64)
		if err1 != nil || err2 != nil {
			return fmt.Errorf("range %q must be two integers", v)
		}
		if l < 0 || h > AwgHMaxValid || l > h {
			return fmt.Errorf("range %q must satisfy 0 <= low <= high <= %d", v, AwgHMaxValid)
		}
		return nil
	}
	n, err := strconv.ParseInt(v, 10, 64)
	if err != nil || n < 0 || n > AwgHMaxValid {
		return fmt.Errorf("value %q must be an integer in 0..%d or a low-high range", v, AwgHMaxValid)
	}
	return nil
}

// AwgPreset enumerates the obfuscation generation presets.
// Source: awg/params.go GenerateObfuscation20 switch.
type AwgPreset string

const (
	AwgPresetDefault AwgPreset = "default"
	AwgPresetMobile  AwgPreset = "mobile"
)

// AwgObfuscationRanges holds the H-range band configuration used during generation.
// Source: awg/params.go generateHRanges constants.
type AwgObfuscationRanges struct {
	BandLo    int
	BandHi    int
	BandSize  int
	HMinWidth int
}

// NewAwgObfuscationRanges returns the default generation range configuration.
// Source: awg/params.go constants awgHMax=2147483647, hMinWidth=1000, lo=5.
func NewAwgObfuscationRanges() AwgObfuscationRanges {
	const lo = 5
	bandSize := (AwgHMax - lo + 1) / 4
	return AwgObfuscationRanges{
		BandLo:    lo,
		BandHi:    AwgHMax,
		BandSize:  bandSize,
		HMinWidth: AwgHMinWidth,
	}
}

// AwgMobilePresetJc is the fixed Jc value for the mobile preset.
// Source: awg/params.go GenerateObfuscation20 "mobile" case
const AwgMobilePresetJc = 3

// AwgS3Max is the maximum S3 (cookie padding) value. Source: awg/params.go S3 constraints.
const AwgS3Max = 64

// AwgS4Max is the maximum S4 (transport padding) value. Source: awg/params.go S4 constraints.
const AwgS4Max = 32
