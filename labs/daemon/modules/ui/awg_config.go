// Package ui implements admin panel models, wireguard obfuscation, and subscription services.
// Ported from: 3ax-ui-main (awg/params.go)
// Target path: server/internal/ui/awg_config.go

package ui

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"strconv"
	"strings"
)

// Obfuscation20 represents AmneziaWG 2.0 obfuscation parameters.
type Obfuscation20 struct {
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

// Getters & Setters for Obfuscation20
func (o *Obfuscation20) GetJc() int { return o.Jc }
func (o *Obfuscation20) SetJc(v int) { o.Jc = v }

const (
	awgHMax   = 2147483647
	hMinWidth = 1000
	hMaxValid = 4294967295
)

// randInt returns a uniform random integer in [min, max].
func randInt(min, max int) int {
	if max <= min {
		return min
	}
	n, err := rand.Int(rand.Reader, big.NewInt(int64(max-min)+1))
	if err != nil {
		return min
	}
	return min + int(n.Int64())
}

// GenerateObfuscation20 generates a unique AmneziaWG fingerprint.
// Maps to GenerateObfuscation20() in params.go.
func GenerateObfuscation20(preset string) Obfuscation20 {
	var o Obfuscation20

	switch preset {
	case "mobile":
		o.Jc = 3
		o.Jmin = randInt(30, 50)
		o.Jmax = o.Jmin + randInt(20, 80)
	default:
		o.Jc = randInt(3, 6)
		o.Jmin = randInt(40, 89)
		o.Jmax = o.Jmin + randInt(50, 250)
	}

	o.S1 = randInt(15, 150)
	o.S2 = randInt(15, 150)
	for o.S1+56 == o.S2 {
		o.S2 = randInt(15, 150)
	}
	o.S3 = randInt(8, 55)
	o.S4 = randInt(4, 27)

	h := generateHRanges()
	o.H1, o.H2, o.H3, o.H4 = h[0], h[1], h[2], h[3]

	o.I1 = fmt.Sprintf("<r %d>", randInt(32, 256))
	return o
}

func generateHRanges() [4]string {
	const lo = 5
	bandSize := (awgHMax - lo + 1) / 4
	var out [4]string
	for i := 0; i < 4; i++ {
		bandLo := lo + i*bandSize
		bandHi := bandLo + bandSize - 1
		start := randInt(bandLo, bandHi-hMinWidth-1)
		end := randInt(start+hMinWidth, bandHi-1)
		out[i] = fmt.Sprintf("%d-%d", start, end)
	}
	return out
}

// ValidateObfuscationParams checks if the parameters satisfy WG specifications.
func ValidateObfuscationParams(jc, jmin, jmax, s3, s4 int, h1, h2, h3, h4 string) error {
	if jmin > jmax {
		return fmt.Errorf("invalid jmin/jmax: %d must not exceed %d", jmin, jmax)
	}
	if s3 < 0 || s3 > 64 {
		return fmt.Errorf("invalid S3 value %d (must be 0..64)", s3)
	}
	if s4 < 0 || s4 > 32 {
		return fmt.Errorf("invalid S4 value %d (must be 0..32)", s4)
	}
	for i, h := range []string{h1, h2, h3, h4} {
		if err := validateHValue(h); err != nil {
			return fmt.Errorf("invalid H%d: %w", i+1, err)
		}
	}
	return nil
}

func validateHValue(v string) error {
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
		if l < 0 || h > hMaxValid || l > h {
			return fmt.Errorf("range %q must satisfy 0 <= low <= high <= %d", v, hMaxValid)
		}
		return nil
	}
	n, err := strconv.ParseInt(v, 10, 64)
	if err != nil || n < 0 || n > hMaxValid {
		return fmt.Errorf("value %q must be an integer in 0..%d or a low-high range", v, hMaxValid)
	}
	return nil
}
