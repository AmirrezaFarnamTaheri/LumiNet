// Package abimanifest verifies that the checked-in ABI manifest agrees with
// the Rust FFI authority.  It deliberately reads source rather than a built
// artifact so every platform receives the same pre-build compatibility gate.
package abimanifest

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

type Options struct {
	RepositoryRoot string
	ManifestPath   string
	EnvelopePath   string
	VersionPath    string
}

type Result struct {
	ABIMajor   int
	Operations int
}

type manifest struct {
	SchemaVersion int `json:"schema_version"`
	ABI           struct {
		Major int `json:"major"`
		Minor int `json:"minor"`
		Patch int `json:"patch"`
	} `json:"abi"`
	Envelope struct {
		Request   string `json:"request"`
		Status    string `json:"status"`
		Ownership string `json:"ownership"`
	} `json:"envelope"`
	Operations []operation `json:"operations"`
}

type operation struct {
	ID     int    `json:"id"`
	Name   string `json:"name"`
	Status string `json:"status"`
}

var allowedOperationStatuses = map[string]struct{}{
	"implemented":              {},
	"declared_not_implemented": {},
	"deprecated":               {},
}

var operationPattern = regexp.MustCompile(`(?m)^\s*([A-Za-z][A-Za-z0-9]*)\s*=\s*([0-9]+)\s*,`)

func Validate(opts Options) (Result, error) {
	if opts.RepositoryRoot == "" {
		return Result{}, fmt.Errorf("repository root is required")
	}
	manifestPath := defaultPath(opts.ManifestPath, opts.RepositoryRoot, "governance", "conductor", "abi", "manifest-v1.json")
	envelopePath := defaultPath(opts.EnvelopePath, opts.RepositoryRoot, "src", "packages", "lumicore", "src", "ffi", "envelope.rs")
	versionPath := defaultPath(opts.VersionPath, opts.RepositoryRoot, "src", "packages", "lumicore", "src", "ffi", "version.rs")

	contents, err := os.ReadFile(manifestPath)
	if err != nil {
		return Result{}, fmt.Errorf("read manifest: %w", err)
	}
	var value manifest
	if err := json.Unmarshal(contents, &value); err != nil {
		return Result{}, fmt.Errorf("parse manifest: %w", err)
	}
	if value.SchemaVersion != 1 {
		return Result{}, fmt.Errorf("unsupported manifest schema_version %d", value.SchemaVersion)
	}
	if value.ABI.Major <= 0 || value.ABI.Minor < 0 || value.ABI.Patch < 0 {
		return Result{}, fmt.Errorf("invalid ABI version %d.%d.%d", value.ABI.Major, value.ABI.Minor, value.ABI.Patch)
	}
	if len(value.Operations) == 0 {
		return Result{}, fmt.Errorf("manifest declares no operations")
	}
	if value.Envelope.Request == "" || value.Envelope.Status == "" || value.Envelope.Ownership == "" {
		return Result{}, fmt.Errorf("manifest envelope contract must declare request, status, and ownership")
	}

	envelope, err := os.ReadFile(envelopePath)
	if err != nil {
		return Result{}, fmt.Errorf("read Rust envelope authority: %w", err)
	}
	version, err := os.ReadFile(versionPath)
	if err != nil {
		return Result{}, fmt.Errorf("read Rust version authority: %w", err)
	}
	if err := requireVersion(string(envelope), "LUMICORE_ABI_VERSION", value.ABI.Major); err != nil {
		return Result{}, err
	}
	if err := requireVersion(string(version), "ABI_MAJOR", value.ABI.Major); err != nil {
		return Result{}, err
	}
	if err := requireVersion(string(version), "ABI_MINOR", value.ABI.Minor); err != nil {
		return Result{}, err
	}
	if err := requireVersion(string(version), "ABI_PATCH", value.ABI.Patch); err != nil {
		return Result{}, err
	}
	if !strings.Contains(string(envelope), "pub struct FfiEnvelope") || !strings.Contains(string(envelope), "pub struct FfiStatus") {
		return Result{}, fmt.Errorf("Rust envelope authority must define FfiEnvelope and FfiStatus")
	}

	rustOperations, err := parseRustOperations(string(envelope))
	if err != nil {
		return Result{}, err
	}
	if err := compareOperations(value.Operations, rustOperations); err != nil {
		return Result{}, err
	}
	return Result{ABIMajor: value.ABI.Major, Operations: len(value.Operations)}, nil
}

func defaultPath(path, root string, pieces ...string) string {
	if path != "" {
		return path
	}
	return filepath.Join(append([]string{root}, pieces...)...)
}

func requireVersion(source, name string, expected int) error {
	pattern := regexp.MustCompile(`(?m)pub const ` + regexp.QuoteMeta(name) + `:\s*u16\s*=\s*([0-9]+)\s*;`)
	matches := pattern.FindStringSubmatch(source)
	if len(matches) != 2 || matches[1] != fmt.Sprint(expected) {
		return fmt.Errorf("Rust authority %s must equal manifest value %d", name, expected)
	}
	return nil
}

func parseRustOperations(source string) (map[string]int, error) {
	start := strings.Index(source, "pub enum OpCode")
	if start < 0 {
		return nil, fmt.Errorf("Rust envelope authority does not define OpCode")
	}
	end := strings.Index(source[start:], "\n}")
	if end < 0 {
		return nil, fmt.Errorf("Rust OpCode declaration is unterminated")
	}
	values := make(map[string]int)
	for _, match := range operationPattern.FindAllStringSubmatch(source[start:start+end], -1) {
		var id int
		if _, err := fmt.Sscan(match[2], &id); err != nil {
			return nil, fmt.Errorf("parse Rust operation %s: %w", match[1], err)
		}
		values[toManifestName(match[1])] = id
	}
	if len(values) == 0 {
		return nil, fmt.Errorf("Rust OpCode declaration has no operations")
	}
	return values, nil
}

func compareOperations(manifestOps []operation, rustOps map[string]int) error {
	seenIDs := make(map[int]struct{}, len(manifestOps))
	seenNames := make(map[string]struct{}, len(manifestOps))
	for _, op := range manifestOps {
		if op.ID <= 0 || op.Name == "" || op.Status == "" {
			return fmt.Errorf("manifest operation must have positive id, name, and status")
		}
		if _, duplicate := seenIDs[op.ID]; duplicate {
			return fmt.Errorf("manifest operation id %d is duplicated", op.ID)
		}
		if _, duplicate := seenNames[op.Name]; duplicate {
			return fmt.Errorf("manifest operation name %q is duplicated", op.Name)
		}
		if _, allowed := allowedOperationStatuses[op.Status]; !allowed {
			return fmt.Errorf("manifest operation %q has unsupported status %q", op.Name, op.Status)
		}
		seenIDs[op.ID] = struct{}{}
		seenNames[op.Name] = struct{}{}
		if rustID, ok := rustOps[op.Name]; !ok || rustID != op.ID {
			return fmt.Errorf("manifest operation %q=%d does not match Rust OpCode", op.Name, op.ID)
		}
	}
	if len(manifestOps) != len(rustOps) {
		names := make([]string, 0, len(rustOps))
		for name := range rustOps {
			names = append(names, name)
		}
		sort.Strings(names)
		return fmt.Errorf("manifest declares %d operations but Rust declares %d (%s)", len(manifestOps), len(rustOps), strings.Join(names, ", "))
	}
	return nil
}

func toManifestName(name string) string {
	var out []rune
	for index, char := range name {
		if index > 0 && char >= 'A' && char <= 'Z' {
			out = append(out, '_')
		}
		out = append(out, []rune(strings.ToLower(string(char)))...)
	}
	return string(out)
}
