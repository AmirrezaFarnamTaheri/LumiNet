// Copyright 2024 LumiNet. Use of this source code is governed by the MIT license.

package config

import (
	"errors"
	"strings"
	"testing"
)

func TestAppendError(t *testing.T) {
	if err := AppendError(nil); err != nil {
		t.Fatalf("nil append must stay nil, got %v", err)
	}
	base := errors.New("base")
	if got := AppendError(base); got != base {
		t.Fatalf("no extras must return original error")
	}
	joined := AppendError(base, errors.New("a"), errors.New("b"))
	msg := joined.Error()
	for _, want := range []string{"base", "a", "b"} {
		if !strings.Contains(msg, want) {
			t.Fatalf("joined error %q missing %q", msg, want)
		}
	}
}

func TestValidationSetAggregation(t *testing.T) {
	vs := NewValidationSet(2)
	vs.Errorf("first problem")
	vs.Errorf("second problem")
	vs.Warnf("warning one")
	vs.Warnf("warning two")
	vs.Warnf("warning three (over cap)")
	if vs.Clean() {
		t.Fatal("set with errors must not be clean")
	}
	err := vs.Err()
	if err == nil {
		t.Fatal("expected joined error")
	}
	msg := err.Error()
	if !strings.Contains(msg, "first problem") || !strings.Contains(msg, "second problem") {
		t.Fatalf("joined error missing entries: %q", msg)
	}
	if warns := vs.Warnings(); len(warns) != 2 {
		t.Fatalf("warning cap not honored: %d warnings", len(warns))
	}
	vs.Error(nil)
	if len(vs.errs) != 2 {
		t.Fatal("nil Error must be a no-op")
	}

	clean := NewValidationSet(0)
	if !clean.Clean() || clean.Err() != nil {
		t.Fatal("empty set must be clean with nil error")
	}
}

func TestStringValidators(t *testing.T) {
	if err := ValidateStringNotEmpty("f", "x"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, v := range []string{"", "   ", "\t"} {
		if err := ValidateStringNotEmpty("f", v); err == nil {
			t.Fatalf("value %q must be rejected", v)
		}
	}

	if err := ValidateStringLength("f", "abc", 1, 5); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if err := ValidateStringLength("f", "abcdef", 1, 5); err == nil {
		t.Fatal("overlong value must be rejected")
	}
	if err := ValidateStringLength("f", "", 1, 5); err == nil {
		t.Fatal("short value must be rejected")
	}
	if err := ValidateStringLength("f", "x", 5, 1); err == nil {
		t.Fatal("inverted bounds must be rejected")
	}

	if err := ValidateStringInSlice("f", "tcp", []string{"tcp", "udp"}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if err := ValidateStringInSlice("f", "sctp", []string{"tcp", "udp"}); err == nil {
		t.Fatal("unlisted value must be rejected")
	}

	if err := ValidateUniqueStrings("f", []string{"a", "b", "a"}); err == nil {
		t.Fatal("duplicates must be rejected")
	}
	if err := ValidateUniqueStrings("f", []string{"a", "b", "c"}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}