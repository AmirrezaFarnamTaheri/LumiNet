// Copyright 2024 LumiNet. Use of this source code is governed by the MIT license.

// Validation framework additions,
// model (frp-dev/pkg/config/v1/validation): composable primitive validators
// with bounded, deterministic errors, a warning channel distinct from errors,
// and an aggregation helper for multi-error reporting. All validators are
// pure — no DNS lookups, file access, or network calls.

package config

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"
)

// Warning marks a non-fatal validation finding. Warnings never block
// admission but are reported alongside errors.
type Warning error

// AppendError joins err with additional errors, mirroring the frp helper.
// A nil err with no extras returns nil.
func AppendError(err error, errs ...error) error {
	if len(errs) == 0 {
		return err
	}
	joined := append([]error{err}, errs...)
	return errors.Join(joined...)
}

// ValidationSet accumulates errors and warnings during one validation run.
// It is not safe for concurrent use; each validation run owns its set.
type ValidationSet struct {
	errs    []error
	warns   []error
	warnCap int
}

// NewValidationSet returns an empty set. A non-positive warnCap means
// unlimited warning retention.
func NewValidationSet(warnCap int) *ValidationSet {
	return &ValidationSet{warnCap: warnCap}
}

// Errorf records a fatal validation error.
func (v *ValidationSet) Errorf(format string, args ...any) {
	v.errs = append(v.errs, fmt.Errorf(format, args...))
}

// Error records a fatal validation error.
func (v *ValidationSet) Error(err error) {
	if err != nil {
		v.errs = append(v.errs, err)
	}
}

// Warnf records a non-fatal warning, respecting the retention cap.
func (v *ValidationSet) Warnf(format string, args ...any) {
	if v.warnCap > 0 && len(v.warns) >= v.warnCap {
		return
	}
	v.warns = append(v.warns, Warning(fmt.Errorf(format, args...)))
}

// Err returns the joined fatal errors, or nil when the set is clean.
func (v *ValidationSet) Err() error {
	return errors.Join(v.errs...)
}

// Warnings returns the retained warnings.
func (v *ValidationSet) Warnings() []Warning {
	out := make([]Warning, len(v.warns))
	for i, w := range v.warns {
		out[i] = w
	}
	return out
}

// Clean reports whether no fatal errors were recorded.
func (v *ValidationSet) Clean() bool { return len(v.errs) == 0 }

// ValidateStringNotEmpty rejects empty or whitespace-only values.
func ValidateStringNotEmpty(field, value string) error {
	if strings.TrimSpace(value) == "" {
		return fmt.Errorf("%s: must not be empty", field)
	}
	return nil
}

// ValidateStringLength bounds the value length to [min, max] (inclusive).
func ValidateStringLength(field, value string, min, max int) error {
	if min < 0 || max < min {
		return fmt.Errorf("%s: invalid length bounds [%d, %d]", field, min, max)
	}
	if len(value) < min || len(value) > max {
		return fmt.Errorf("%s: length %d outside [%d, %d]", field, len(value), min, max)
	}
	return nil
}

// ValidateStringInSlice requires value to be one of the allowed entries.
func ValidateStringInSlice(field, value string, allowed []string) error {
	for _, a := range allowed {
		if value == a {
			return nil
		}
	}
	return fmt.Errorf("%s: value %q not in allowed set %v", field, value, allowed)
}

// ValidateUniqueStrings rejects duplicate entries, reporting the first one.
func ValidateUniqueStrings(field string, values []string) error {
	seen := make(map[string]struct{}, len(values))
	for _, v := range values {
		if _, dup := seen[v]; dup {
			return fmt.Errorf("%s: duplicate entry %q", field, v)
		}
		seen[v] = struct{}{}
	}
	return nil
}

// ValidatePort requires 1 <= port <= 65535.
func ValidatePort(field string, port int) error {
	if port < 1 || port > 65535 {
		return fmt.Errorf("%s: port %d outside [1, 65535]", field, port)
	}
	return nil
}

// PortRange is an inclusive port interval.
type PortRange struct {
	From int
	To   int
}

// ValidatePortRange validates both endpoints and their ordering.
func ValidatePortRange(field string, r PortRange) error {
	if err := ValidatePort(field+".from", r.From); err != nil {
		return err
	}
	if err := ValidatePort(field+".to", r.To); err != nil {
		return err
	}
	if r.From > r.To {
		return fmt.Errorf("%s: range start %d exceeds end %d", field, r.From, r.To)
	}
	return nil
}

// ValidateNonOverlappingPortRanges rejects overlapping ranges by index pair.
func ValidateNonOverlappingPortRanges(owner string, ranges []PortRange) error {
	for i := range ranges {
		if err := ValidatePortRange(fmt.Sprintf("%s[%d]", owner, i), ranges[i]); err != nil {
			return err
		}
		for j := 0; j < i; j++ {
			if ranges[i].From <= ranges[j].To && ranges[j].From <= ranges[i].To {
				return fmt.Errorf("%s: ranges %d and %d overlap", owner, j, i)
			}
		}
	}
	return nil
}

// ValidateIP requires a parseable IPv4 or IPv6 address.
func ValidateIP(field, value string) error {
	if net.ParseIP(value) == nil {
		return fmt.Errorf("%s: %q is not a valid IP address", field, value)
	}
	return nil
}

// ValidateCIDR requires a parseable CIDR block of either family.
func ValidateCIDR(field, value string) error {
	if _, _, err := net.ParseCIDR(value); err != nil {
		return fmt.Errorf("%s: %q is not a valid CIDR block", field, value)
	}
	return nil
}

// ValidateDomain enforces a bounded RFC-1035-shaped hostname: total length
// ≤ 253, ASCII letters/digits/hyphen labels of length 1..63, no leading or
// trailing hyphen, and no DNS lookups.
func ValidateDomain(field, value string) error {
	if len(value) == 0 || len(value) > 253 {
		return fmt.Errorf("%s: domain length %d outside [1, 253]", field, len(value))
	}
	value = strings.TrimSuffix(value, ".")
	for _, label := range strings.Split(value, ".") {
		if len(label) == 0 || len(label) > 63 {
			return fmt.Errorf("%s: label %q length outside [1, 63]", field, label)
		}
		if strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return fmt.Errorf("%s: label %q must not start or end with '-'", field, label)
		}
		for _, r := range label {
			if !('a' <= r && r <= 'z' || 'A' <= r && r <= 'Z' || '0' <= r && r <= '9' || r == '-') {
				return fmt.Errorf("%s: label %q contains invalid character %q", field, label, r)
			}
		}
	}
	return nil
}

// ValidateURLScheme requires a parseable absolute URL whose scheme is one of
// the allowed values (case-insensitive).
func ValidateURLScheme(field, rawURL string, allowed []string) error {
	u, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("%s: unparseable URL: %w", field, err)
	}
	scheme := strings.ToLower(u.Scheme)
	for _, a := range allowed {
		if scheme == strings.ToLower(a) {
			return nil
		}
	}
	return fmt.Errorf("%s: scheme %q not in allowed set %v", field, u.Scheme, allowed)
}

// ValidatePositiveDuration requires a strictly positive duration.
func ValidatePositiveDuration(field string, d time.Duration) error {
	if d <= 0 {
		return fmt.Errorf("%s: duration %s must be positive", field, d)
	}
	return nil
}