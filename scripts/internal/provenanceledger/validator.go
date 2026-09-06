// Package provenanceledger validates LumiNet's append-only provenance source
// records and their immutable, repository-local raw snapshots.
package provenanceledger

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

const schemaVersion = 1

var (
	sourceRefPattern = regexp.MustCompile(`^source:[a-z0-9][a-z0-9-]*(?::[a-z0-9][a-z0-9-]*)*$`)
	commitPattern    = regexp.MustCompile(`^[a-fA-F0-9]{40,64}$`)
)

type Options struct {
	RepositoryRoot         string
	LedgerPath             string
	SchemaPath             string
	BaseLedgerPath         string
	BaseRef                string
	PreservationLedgerPath string
}

type Result struct {
	Records          int
	Snapshots        int
	ValidatedRecords []Record
}

type Record struct {
	SchemaVersion    int           `json:"schema_version"`
	SourceRef        string        `json:"source_ref"`
	DisplayName      string        `json:"display_name"`
	SourceKind       string        `json:"source_kind"`
	ImmutableLocator string        `json:"immutable_locator"`
	Content          Content       `json:"content"`
	RetrievedAt      time.Time     `json:"retrieved_at"`
	Upstream         Upstream      `json:"upstream"`
	License          License       `json:"license"`
	Qualification    Qualification `json:"qualification"`
}

type Content struct {
	Algorithm string `json:"algorithm"`
	Digest    string `json:"digest"`
	ByteSize  int64  `json:"byte_size"`
}

type Upstream struct {
	Status   string   `json:"status"`
	URL      string   `json:"url,omitempty"`
	Commit   string   `json:"commit,omitempty"`
	Evidence []string `json:"evidence"`
}

type License struct {
	Status   string   `json:"status"`
	SPDXID   string   `json:"spdx_id,omitempty"`
	Evidence []string `json:"evidence"`
}

type Qualification struct {
	State                string   `json:"state"`
	Evidence             []string `json:"evidence"`
	ContradictionMarkers []string `json:"contradiction_markers,omitempty"`
}

type parsedLedger struct {
	records []Record
	lines   [][]byte
}

func Validate(opts Options) (Result, error) {
	if opts.RepositoryRoot == "" {
		opts.RepositoryRoot = "."
	}
	if opts.LedgerPath == "" {
		opts.LedgerPath = filepath.Join(opts.RepositoryRoot, "governance", "conductor", "provenance-ledger", "sources.v1.jsonl")
	}
	if opts.SchemaPath == "" {
		opts.SchemaPath = filepath.Join(opts.RepositoryRoot, "governance", "conductor", "provenance-ledger", "schema-v1.json")
	}
	if opts.PreservationLedgerPath == "" {
		opts.PreservationLedgerPath = filepath.Join(opts.RepositoryRoot, "governance", "conductor", "preservation-ledger", "families.v1.json")
	}
	schema, err := compileSchema(opts.SchemaPath)
	if err != nil {
		return Result{}, err
	}
	current, err := readLedger(opts.LedgerPath, schema)
	if err != nil {
		return Result{}, err
	}
	switch {
	case opts.BaseLedgerPath != "":
		base, readErr := readLedger(opts.BaseLedgerPath, schema)
		if readErr != nil {
			return Result{}, fmt.Errorf("read append-only baseline: %w", readErr)
		}
		if err := validateAppendOnly(base, current); err != nil {
			return Result{}, err
		}
	case opts.BaseRef != "":
		base, readErr := readLedgerAtGitRef(opts.RepositoryRoot, opts.LedgerPath, opts.BaseRef, schema)
		if readErr != nil {
			return Result{}, fmt.Errorf("derive trusted append-only baseline from %q: %w", opts.BaseRef, readErr)
		}
		if err := validateAppendOnly(base, current); err != nil {
			return Result{}, err
		}
	default:
		return Result{}, errors.New("trusted append-only baseline required: set BaseLedgerPath or BaseRef")
	}
	if len(current.records) == 0 {
		return Result{}, errors.New("provenance ledger must contain at least one source record")
	}
	if err := validateRecords(current.records, opts.LedgerPath, opts.RepositoryRoot); err != nil {
		return Result{}, err
	}
	if err := validatePreservationSourceRefs(current.records, opts.PreservationLedgerPath); err != nil {
		return Result{}, err
	}
	return Result{
		Records:          len(current.records),
		Snapshots:        len(current.records),
		ValidatedRecords: append([]Record(nil), current.records...),
	}, nil
}

func MarshalRecord(record Record) ([]byte, error) {
	raw, err := json.Marshal(record)
	if err != nil {
		return nil, fmt.Errorf("marshal provenance record %q: %w", record.SourceRef, err)
	}
	return raw, nil
}

func compileSchema(schemaPath string) (*jsonschema.Schema, error) {
	raw, err := os.ReadFile(schemaPath)
	if err != nil {
		return nil, fmt.Errorf("read provenance schema: %w", err)
	}
	var document any
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err := decoder.Decode(&document); err != nil {
		return nil, fmt.Errorf("parse provenance schema: %w", err)
	}
	compiler := jsonschema.NewCompiler()
	const schemaURL = "https://luminet.invalid/provenance-ledger/schema-v1.json"
	if err := compiler.AddResource(schemaURL, document); err != nil {
		return nil, fmt.Errorf("load provenance schema: %w", err)
	}
	schema, err := compiler.Compile(schemaURL)
	if err != nil {
		return nil, fmt.Errorf("compile provenance schema: %w", err)
	}
	return schema, nil
}

func readLedger(ledgerPath string, schema *jsonschema.Schema) (parsedLedger, error) {
	file, err := os.Open(ledgerPath)
	if err != nil {
		return parsedLedger{}, fmt.Errorf("read provenance ledger: %w", err)
	}
	defer file.Close()
	return readLedgerFrom(file, schema)
}

func readLedgerFrom(reader io.Reader, schema *jsonschema.Schema) (parsedLedger, error) {
	var ledger parsedLedger
	scanner := bufio.NewScanner(reader)
	scanner.Buffer(make([]byte, 64*1024), 4*1024*1024)
	for lineNumber := 1; scanner.Scan(); lineNumber++ {
		line := append([]byte(nil), scanner.Bytes()...)
		if len(bytes.TrimSpace(line)) == 0 {
			return parsedLedger{}, fmt.Errorf("provenance ledger line %d is blank", lineNumber)
		}
		var value any
		decoder := json.NewDecoder(bytes.NewReader(line))
		decoder.UseNumber()
		if err := decoder.Decode(&value); err != nil {
			return parsedLedger{}, fmt.Errorf("parse provenance ledger line %d: %w", lineNumber, err)
		}
		if err := ensureJSONEOF(decoder); err != nil {
			return parsedLedger{}, fmt.Errorf("parse provenance ledger line %d: %w", lineNumber, err)
		}
		if err := schema.Validate(value); err != nil {
			return parsedLedger{}, fmt.Errorf("schema validation line %d: %w", lineNumber, err)
		}
		var record Record
		if err := json.Unmarshal(line, &record); err != nil {
			return parsedLedger{}, fmt.Errorf("decode provenance ledger line %d: %w", lineNumber, err)
		}
		ledger.records = append(ledger.records, record)
		ledger.lines = append(ledger.lines, line)
	}
	if err := scanner.Err(); err != nil {
		return parsedLedger{}, fmt.Errorf("scan provenance ledger: %w", err)
	}
	return ledger, nil
}

func readLedgerAtGitRef(repositoryRoot, ledgerPath, baseRef string, schema *jsonschema.Schema) (parsedLedger, error) {
	root, err := filepath.Abs(repositoryRoot)
	if err != nil {
		return parsedLedger{}, fmt.Errorf("resolve repository root: %w", err)
	}
	ledger, err := filepath.Abs(ledgerPath)
	if err != nil {
		return parsedLedger{}, fmt.Errorf("resolve provenance ledger path: %w", err)
	}
	relative, err := filepath.Rel(root, ledger)
	if err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return parsedLedger{}, fmt.Errorf("ledger %q is outside repository root", ledgerPath)
	}
	gitObject := baseRef + ":" + filepath.ToSlash(relative)
	command := exec.Command("git", "show", gitObject)
	command.Dir = root
	command.Env = append(os.Environ(), "GIT_OPTIONAL_LOCKS=0", "LC_ALL=C")
	raw, err := command.Output()
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			message := strings.TrimSpace(string(exitErr.Stderr))
			if message != "" {
				return parsedLedger{}, fmt.Errorf("git show %s: %s", gitObject, message)
			}
		}
		return parsedLedger{}, fmt.Errorf("git show %s: %w", gitObject, err)
	}
	return readLedgerFrom(bytes.NewReader(raw), schema)
}

func ensureJSONEOF(decoder *json.Decoder) error {
	var extra any
	if err := decoder.Decode(&extra); errors.Is(err, io.EOF) {
		return nil
	} else if err != nil {
		return err
	}
	return errors.New("multiple JSON values on one JSONL line")
}

func validateAppendOnly(base, current parsedLedger) error {
	if len(current.lines) < len(base.lines) {
		return fmt.Errorf(
			"append-only violation: ledger contains %d records, baseline contains %d",
			len(current.lines),
			len(base.lines),
		)
	}
	for index := range base.lines {
		if !bytes.Equal(base.lines[index], current.lines[index]) {
			return fmt.Errorf(
				"append-only violation at record %d (%s): existing records may not be updated or reordered",
				index+1,
				base.records[index].SourceRef,
			)
		}
	}
	return nil
}

func validateRecords(records []Record, ledgerPath, repositoryRoot string) error {
	ledgerDirectory, err := filepath.Abs(filepath.Dir(ledgerPath))
	if err != nil {
		return fmt.Errorf("resolve provenance ledger directory: %w", err)
	}
	repositoryRoot, err = filepath.Abs(repositoryRoot)
	if err != nil {
		return fmt.Errorf("resolve repository root: %w", err)
	}
	if !pathWithin(repositoryRoot, ledgerDirectory) {
		return fmt.Errorf("provenance ledger directory %q is outside repository root", ledgerDirectory)
	}

	seen := make(map[string]int, len(records))
	var problems []string
	for index, record := range records {
		lineNumber := index + 1
		if previous, exists := seen[record.SourceRef]; exists {
			problems = append(problems, fmt.Sprintf(
				"line %d duplicate source_ref %q (first declared on line %d)",
				lineNumber,
				record.SourceRef,
				previous,
			))
			continue
		}
		seen[record.SourceRef] = lineNumber
		if record.SchemaVersion != schemaVersion {
			problems = append(problems, fmt.Sprintf("line %d unsupported schema_version %d", lineNumber, record.SchemaVersion))
		}
		if !sourceRefPattern.MatchString(record.SourceRef) {
			problems = append(problems, fmt.Sprintf("line %d invalid source_ref %q", lineNumber, record.SourceRef))
		}
		if err := validateQualification(record); err != nil {
			problems = append(problems, fmt.Sprintf("line %d %s: %v", lineNumber, record.SourceRef, err))
		}
		if err := validateSnapshot(record, ledgerDirectory); err != nil {
			problems = append(problems, fmt.Sprintf("line %d %s: %v", lineNumber, record.SourceRef, err))
		}
	}
	if len(problems) > 0 {
		sort.Strings(problems)
		return errors.New(strings.Join(problems, "\n"))
	}
	return nil
}

type preservationLedgerRefs struct {
	Sources  []preservationSourceRef `json:"sources"`
	Families []preservationFamilyRef `json:"families"`
}

type preservationSourceRef struct {
	SourceRef string `json:"source_ref"`
}

type preservationFamilyRef struct {
	FamilyID string                `json:"family_id"`
	Peers    []preservationPeerRef `json:"peers"`
}

type preservationPeerRef struct {
	PeerID    string `json:"peer_id"`
	SourceRef string `json:"source_ref"`
}

func validatePreservationSourceRefs(records []Record, preservationLedgerPath string) error {
	raw, err := os.ReadFile(preservationLedgerPath)
	if err != nil {
		return fmt.Errorf("read preservation ledger for source_ref resolution: %w", err)
	}
	var preservation preservationLedgerRefs
	if err := json.Unmarshal(raw, &preservation); err != nil {
		return fmt.Errorf("decode preservation ledger for source_ref resolution: %w", err)
	}
	provenanceRefs := make(map[string]struct{}, len(records))
	for _, record := range records {
		provenanceRefs[record.SourceRef] = struct{}{}
	}
	var problems []string
	for _, source := range preservation.Sources {
		if _, exists := provenanceRefs[source.SourceRef]; !exists {
			problems = append(problems, fmt.Sprintf(
				"preservation source_ref %q does not resolve in provenance ledger",
				source.SourceRef,
			))
		}
	}
	for _, family := range preservation.Families {
		for _, peer := range family.Peers {
			if _, exists := provenanceRefs[peer.SourceRef]; !exists {
				problems = append(problems, fmt.Sprintf(
					"preservation family %q peer %q peer source_ref %q does not resolve in provenance ledger",
					family.FamilyID,
					peer.PeerID,
					peer.SourceRef,
				))
			}
		}
	}
	if len(problems) > 0 {
		sort.Strings(problems)
		return errors.New(strings.Join(problems, "\n"))
	}
	return nil
}

func validateQualification(record Record) error {
	if record.RetrievedAt.IsZero() {
		return errors.New("retrieved_at must be set")
	}
	if record.RetrievedAt.Location() != time.UTC {
		return errors.New("retrieved_at must use UTC")
	}
	switch record.Upstream.Status {
	case "resolved":
		if record.Upstream.URL == "" {
			return errors.New("resolved upstream requires url")
		}
		if !commitPattern.MatchString(record.Upstream.Commit) {
			return errors.New("resolved upstream requires an immutable 40-64 hexadecimal commit")
		}
		if record.Qualification.State != "qualified" && record.Qualification.State != "contradictory" {
			return errors.New("resolved upstream requires qualified or contradictory qualification")
		}
	case "unavailable", "unresolved", "force-push-suspected":
		if record.Qualification.State == "qualified" {
			return fmt.Errorf("upstream status %q cannot have qualified qualification", record.Upstream.Status)
		}
	default:
		return fmt.Errorf("unsupported upstream status %q", record.Upstream.Status)
	}
	if record.Upstream.Status == "force-push-suspected" && len(record.Qualification.ContradictionMarkers) == 0 {
		return errors.New("force-push-suspected upstream requires contradiction_markers")
	}
	if record.Qualification.State == "contradictory" && len(record.Qualification.ContradictionMarkers) == 0 {
		return errors.New("contradictory qualification requires contradiction_markers")
	}
	if record.License.Status == "identified" && record.License.SPDXID == "" {
		return errors.New("identified license requires spdx_id")
	}
	return nil
}

func validateSnapshot(record Record, ledgerDirectory string) error {
	locator, err := normalizeLocator(record.ImmutableLocator)
	if err != nil {
		return fmt.Errorf("immutable_locator: %w", err)
	}
	snapshotPath := filepath.Join(ledgerDirectory, filepath.FromSlash(locator))
	snapshotPath, err = filepath.Abs(snapshotPath)
	if err != nil {
		return fmt.Errorf("immutable_locator %q: %w", locator, err)
	}
	if !pathWithin(ledgerDirectory, snapshotPath) {
		return fmt.Errorf("immutable_locator %q escapes provenance storage", locator)
	}
	resolved, err := filepath.EvalSymlinks(snapshotPath)
	if err != nil {
		return fmt.Errorf("immutable_locator %q is not retrievable: %w", locator, err)
	}
	if !pathWithin(ledgerDirectory, resolved) {
		return fmt.Errorf("immutable_locator %q resolves outside provenance storage", locator)
	}
	info, err := os.Stat(resolved)
	if err != nil {
		return fmt.Errorf("immutable_locator %q: %w", locator, err)
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("immutable_locator %q is not a regular file", locator)
	}
	if info.Size() != record.Content.ByteSize {
		return fmt.Errorf(
			"byte_size mismatch for immutable_locator %q: declared %d actual %d",
			locator,
			record.Content.ByteSize,
			info.Size(),
		)
	}
	raw, err := os.ReadFile(resolved)
	if err != nil {
		return fmt.Errorf("read immutable_locator %q: %w", locator, err)
	}
	sum := sha256.Sum256(raw)
	actual := hex.EncodeToString(sum[:])
	if actual != record.Content.Digest {
		return fmt.Errorf(
			"digest mismatch for immutable_locator %q: declared %s actual %s",
			locator,
			record.Content.Digest,
			actual,
		)
	}
	return nil
}

func normalizeLocator(locator string) (string, error) {
	normalized := strings.ReplaceAll(locator, `\`, "/")
	if normalized == "" || strings.HasPrefix(normalized, "/") {
		return "", fmt.Errorf("%q must be relative", locator)
	}
	cleaned := path.Clean(normalized)
	if cleaned == "." || cleaned == ".." || strings.HasPrefix(cleaned, "../") {
		return "", fmt.Errorf("%q escapes provenance storage", locator)
	}
	if strings.Contains(cleaned, ":") {
		return "", fmt.Errorf("%q must not contain a drive or URI scheme", locator)
	}
	return cleaned, nil
}

func pathWithin(root, candidate string) bool {
	relative, err := filepath.Rel(root, candidate)
	return err == nil && relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator))
}

type generationInput struct {
	SchemaVersion    int    `json:"schema_version"`
	SourceRef        string `json:"source_ref"`
	ImmutableLocator string `json:"immutable_locator"`
	Digest           string `json:"digest"`
	ByteSize         int64  `json:"byte_size"`
	RetrievedAt      string `json:"retrieved_at"`
	UpstreamCommit   string `json:"upstream_commit,omitempty"`
	Qualification    string `json:"qualification"`
}

func GenerateInputs(records []Record) ([]byte, error) {
	inputs := make([]generationInput, 0, len(records))
	for _, record := range records {
		locator, err := normalizeLocator(record.ImmutableLocator)
		if err != nil {
			return nil, fmt.Errorf("%s immutable_locator: %w", record.SourceRef, err)
		}
		inputs = append(inputs, generationInput{
			SchemaVersion:    record.SchemaVersion,
			SourceRef:        record.SourceRef,
			ImmutableLocator: locator,
			Digest:           record.Content.Digest,
			ByteSize:         record.Content.ByteSize,
			RetrievedAt:      record.RetrievedAt.UTC().Format(time.RFC3339),
			UpstreamCommit:   strings.ToLower(record.Upstream.Commit),
			Qualification:    record.Qualification.State,
		})
	}
	sort.Slice(inputs, func(i, j int) bool {
		return inputs[i].SourceRef < inputs[j].SourceRef
	})
	var output bytes.Buffer
	encoder := json.NewEncoder(&output)
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(inputs); err != nil {
		return nil, fmt.Errorf("encode deterministic generation inputs: %w", err)
	}
	return output.Bytes(), nil
}

func LoadRecords(ledgerPath, schemaPath string) ([]Record, error) {
	schema, err := compileSchema(schemaPath)
	if err != nil {
		return nil, err
	}
	ledger, err := readLedger(ledgerPath, schema)
	if err != nil {
		return nil, err
	}
	return ledger.records, nil
}
