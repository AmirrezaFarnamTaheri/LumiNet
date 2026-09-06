package dns

import (
	"encoding/base32"
	"strings"
)

// LowerBase36 codec for DNS tunneling
// We use a custom encoding (often a variant of base32 with lower case)
// to pack data into DNS subdomains securely.

var encoder = base32.NewEncoding("abcdefghijklmnopqrstuvwxyz012345").WithPadding(base32.NoPadding)

// Encode returns a lowercase string suitable for a DNS label.
func Encode(data []byte) string {
	return strings.ToLower(encoder.EncodeToString(data))
}

// Decode converts the DNS label back into bytes.
func Decode(s string) ([]byte, error) {
	return encoder.DecodeString(strings.ToUpper(s))
}
