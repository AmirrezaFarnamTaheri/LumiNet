// Package preservationledger validates LumiNet's preservation ledger and
// repository changes that JSON Schema cannot express.
package preservationledger

import (
	"bytes"
	"context"
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

	"github.com/santhosh-tekuri/jsonschema/v6"
)

type Status string

const (
	StatusInventory     Status = "inventory"
	StatusCharacterized Status = "characterized"
	StatusMigrating     Status = "migrating"
	StatusVerified      Status = "verified"
	StatusQuarantined   Status = "quarantined"
	StatusHistorical    Status = "historical"
)

type Disposition string

const (
	DispositionCanonicalize     Disposition = "canonicalize"
	DispositionCompose          Disposition = "compose"
	DispositionExtractPrimitive Disposition = "extract-primitive"
	DispositionRetainSpecialty  Disposition = "retain-specialization"
	DispositionQuarantine       Disposition = "quarantine"
)

type PeerState string

const (
	PeerLive       PeerState = "live"
	PeerHistorical PeerState = "historical"
)

type Ledger struct {
	SchemaVersion int          `json:"schema_version"`
	Sources       []Source     `json:"sources"`
	PathPolicies  PathPolicies `json:"path_policies"`
	Families      []Family     `json:"families"`
}

type Source struct {
	SourceRef    string `json:"source_ref"`
	Kind         string `json:"kind"`
	Locator      string `json:"locator"`
	ImmutableRef string `json:"immutable_ref,omitempty"`
}

type PathPolicies struct {
	GeneratedRoots   []string     `json:"generated_roots"`
	GeneratedOutputs []PathPolicy `json:"generated_outputs"`
	TemporaryOutputs []PathPolicy `json:"temporary_outputs"`
}

type PathPolicy struct {
	PolicyID string `json:"policy_id"`
	Pattern  string `json:"pattern"`
}

type Family struct {
	FamilyID           string      `json:"family_id"`
	Status             Status      `json:"status"`
	Disposition        Disposition `json:"disposition"`
	CanonicalPeerID    string      `json:"canonical_peer_id,omitempty"`
	Peers              []Peer      `json:"peers"`
	DeletionPredicate  string      `json:"deletion_predicate"`
	FieldDefaultMatrix []MatrixRow `json:"field_default_matrix,omitempty"`
}

type MatrixRow struct {
	Field      string            `json:"field"`
	PeerValues map[string]string `json:"peer_values"`
	Decision   string            `json:"decision"`
}

type Peer struct {
	PeerID               string      `json:"peer_id"`
	SourceRef            string      `json:"source_ref"`
	Path                 string      `json:"path"`
	State                PeerState   `json:"state"`
	Role                 string      `json:"role"`
	PreservedDetails     []string    `json:"preserved_details"`
	Consumers            []string    `json:"consumers"`
	VerificationEvidence []string    `json:"verification_evidence"`
	Disposition          Disposition `json:"disposition"`
	Provenance           Provenance  `json:"provenance"`
}

type Provenance struct {
	ImmutableRef string   `json:"immutable_ref,omitempty"`
	Evidence     []string `json:"evidence"`
}

type ChangeKind string

const (
	ChangeAdd             ChangeKind = "add"
	ChangeModify          ChangeKind = "modify"
	ChangeRename          ChangeKind = "rename"
	ChangeDelete          ChangeKind = "delete"
	ChangeUntracked       ChangeKind = "untracked"
	ChangeGeneratedOutput ChangeKind = "generated-output"
)

type Change struct {
	Kind             ChangeKind `json:"kind"`
	Path             string     `json:"path"`
	OldPath          string     `json:"old_path,omitempty"`
	ExecutionCreated bool       `json:"execution_created,omitempty"`
}

type Mode string

const (
	ModeLocal Mode = "local"
	ModeCI    Mode = "ci"
)

type Options struct {
	LedgerPath       string
	SchemaPath       string
	RepositoryRoot   string
	BaseSHA          string
	ChangesPath      string
	Mode             Mode
	IncludeUntracked bool
}

type Result struct {
	Families int
	Peers    int
	Changes  int
}

var stableIDPattern = regexp.MustCompile(`^[a-z][a-z0-9]*(?::[a-z0-9][a-z0-9-]*)+$`)

func Run(ctx context.Context, opts Options) (Result, error) {
	opts = withCanonicalPaths(opts)
	if opts.Mode == "" {
		opts.Mode = ModeLocal
	}
	if opts.Mode != ModeLocal && opts.Mode != ModeCI {
		return Result{}, fmt.Errorf("mode must be %q or %q", ModeLocal, ModeCI)
	}
	raw, err := os.ReadFile(opts.LedgerPath)
	if err != nil {
		return Result{}, fmt.Errorf("read ledger: %w", err)
	}
	if err := ValidateSchema(opts.SchemaPath, raw); err != nil {
		return Result{}, err
	}
	var ledger Ledger
	if err := json.Unmarshal(raw, &ledger); err != nil {
		return Result{}, fmt.Errorf("decode validated ledger: %w", err)
	}
	if err := ValidateLedgerSemantics(&ledger, opts.RepositoryRoot, opts.BaseSHA); err != nil {
		return Result{}, err
	}

	var changes []Change
	switch {
	case opts.ChangesPath != "":
		changes, err = LoadChanges(opts.ChangesPath)
	case opts.BaseSHA != "":
		changes, err = GitChanges(ctx, opts.RepositoryRoot, opts.BaseSHA, opts.IncludeUntracked || opts.Mode == ModeCI)
	}
	if err != nil {
		return Result{}, err
	}
	if err := ValidateChanges(&ledger, changes, opts.Mode); err != nil {
		return Result{}, err
	}
	peers := 0
	for _, family := range ledger.Families {
		peers += len(family.Peers)
	}
	return Result{Families: len(ledger.Families), Peers: peers, Changes: len(changes)}, nil
}

func withCanonicalPaths(opts Options) Options {
	if opts.RepositoryRoot == "" {
		opts.RepositoryRoot = "."
	}
	if opts.LedgerPath == "" {
		opts.LedgerPath = filepath.Join(opts.RepositoryRoot, "governance", "conductor", "preservation-ledger", "families.v1.json")
	}
	if opts.SchemaPath == "" {
		opts.SchemaPath = filepath.Join(opts.RepositoryRoot, "governance", "conductor", "preservation-ledger", "schema-v1.json")
	}
	return opts
}

func ValidateSchema(schemaPath string, document []byte) error {
	schemaRaw, err := os.ReadFile(schemaPath)
	if err != nil {
		return fmt.Errorf("read schema: %w", err)
	}
	var schemaDocument any
	if err := json.Unmarshal(schemaRaw, &schemaDocument); err != nil {
		return fmt.Errorf("parse Draft 2020-12 schema: %w", err)
	}
	compiler := jsonschema.NewCompiler()
	const schemaURL = "https://luminet.invalid/preservation-ledger/schema-v1.json"
	if err := compiler.AddResource(schemaURL, schemaDocument); err != nil {
		return fmt.Errorf("load Draft 2020-12 schema: %w", err)
	}
	schema, err := compiler.Compile(schemaURL)
	if err != nil {
		return fmt.Errorf("compile Draft 2020-12 schema: %w", err)
	}
	var value any
	decoder := json.NewDecoder(bytes.NewReader(document))
	decoder.UseNumber()
	if err := decoder.Decode(&value); err != nil {
		return fmt.Errorf("parse ledger JSON: %w", err)
	}
	if err := schema.Validate(value); err != nil {
		return fmt.Errorf("schema validation: %w", err)
	}
	return nil
}

func ValidateLedgerSemantics(ledger *Ledger, repositoryRoot, baseSHA string) error {
	var problems []string
	if ledger.SchemaVersion != 1 {
		problems = append(problems, fmt.Sprintf("unsupported schema_version %d", ledger.SchemaVersion))
	}

	sourceRefs := make(map[string]struct{}, len(ledger.Sources))
	for _, source := range ledger.Sources {
		if !stableIDPattern.MatchString(source.SourceRef) {
			problems = append(problems, fmt.Sprintf("invalid stable source_ref %q", source.SourceRef))
		}
		if _, exists := sourceRefs[source.SourceRef]; exists {
			problems = append(problems, fmt.Sprintf("duplicate source_ref %q", source.SourceRef))
		}
		sourceRefs[source.SourceRef] = struct{}{}
	}

	familyIDs := make(map[string]struct{}, len(ledger.Families))
	peerIDs := make(map[string]struct{})
	for fi := range ledger.Families {
		family := &ledger.Families[fi]
		if !stableIDPattern.MatchString(family.FamilyID) {
			problems = append(problems, fmt.Sprintf("invalid stable family_id %q", family.FamilyID))
		}
		if _, exists := familyIDs[family.FamilyID]; exists {
			problems = append(problems, fmt.Sprintf("duplicate family_id %q", family.FamilyID))
		}
		familyIDs[family.FamilyID] = struct{}{}
		if !validStatus(family.Status) {
			problems = append(problems, fmt.Sprintf("family %q has unknown status %q", family.FamilyID, family.Status))
		}
		if !validDisposition(family.Disposition) {
			problems = append(problems, fmt.Sprintf("family %q has unknown disposition %q", family.FamilyID, family.Disposition))
		}
		if family.CanonicalPeerID == "" && family.Status != StatusHistorical && family.Status != StatusQuarantined {
			problems = append(problems, fmt.Sprintf("family %q lacks canonical_peer_id without historical/quarantined status", family.FamilyID))
		}
		familyPeerIDs := make(map[string]struct{}, len(family.Peers))
		for pi := range family.Peers {
			peer := &family.Peers[pi]
			if !stableIDPattern.MatchString(peer.PeerID) {
				problems = append(problems, fmt.Sprintf("family %q has invalid stable peer_id %q", family.FamilyID, peer.PeerID))
			}
			if _, exists := peerIDs[peer.PeerID]; exists {
				problems = append(problems, fmt.Sprintf("duplicate peer_id %q", peer.PeerID))
			}
			peerIDs[peer.PeerID] = struct{}{}
			familyPeerIDs[peer.PeerID] = struct{}{}
			if _, exists := sourceRefs[peer.SourceRef]; !exists {
				problems = append(problems, fmt.Sprintf("peer %q references unknown source_ref %q", peer.PeerID, peer.SourceRef))
			}
			normalized, err := NormalizeRepositoryPath(peer.Path)
			if err != nil {
				problems = append(problems, fmt.Sprintf("peer %q path: %v", peer.PeerID, err))
			} else if normalized != peer.Path {
				problems = append(problems, fmt.Sprintf("peer %q path %q is not normalized (want %q)", peer.PeerID, peer.Path, normalized))
			} else if err := validatePeerPresence(peer, repositoryRoot, baseSHA); err != nil {
				problems = append(problems, err.Error())
			}
			if !validDisposition(peer.Disposition) {
				problems = append(problems, fmt.Sprintf("peer %q has unknown disposition %q", peer.PeerID, peer.Disposition))
			}
		}
		if family.CanonicalPeerID != "" {
			if _, exists := familyPeerIDs[family.CanonicalPeerID]; !exists {
				problems = append(problems, fmt.Sprintf("family %q canonical_peer_id %q is not one of its peers", family.FamilyID, family.CanonicalPeerID))
			}
		}
	}
	if len(problems) > 0 {
		sort.Strings(problems)
		return errors.New(strings.Join(problems, "\n"))
	}
	return nil
}

func validatePeerPresence(peer *Peer, repositoryRoot, baseSHA string) error {
	if peer.State == PeerHistorical {
		if peer.Disposition != DispositionQuarantine {
			return fmt.Errorf("historical peer %q must use quarantine disposition", peer.PeerID)
		}
		if strings.TrimSpace(peer.Provenance.ImmutableRef) == "" {
			return fmt.Errorf("historical peer %q lacks immutable provenance", peer.PeerID)
		}
		return nil
	}
	if peer.State != PeerLive {
		return fmt.Errorf("peer %q has unknown state %q", peer.PeerID, peer.State)
	}
	if repositoryRoot == "" {
		return nil
	}
	absolute := filepath.Join(repositoryRoot, filepath.FromSlash(peer.Path))
	if _, err := os.Stat(absolute); err == nil {
		return nil
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("inspect live peer %q: %w", peer.PeerID, err)
	}
	for _, revision := range []string{baseSHA, "HEAD"} {
		if revision != "" && gitPathExists(repositoryRoot, revision, peer.Path) {
			return nil
		}
	}
	return fmt.Errorf("live peer %q path %q is absent from the worktree and repository history", peer.PeerID, peer.Path)
}

func gitPathExists(root, revision, name string) bool {
	cmd := exec.Command("git", "-C", root, "cat-file", "-e", revision+":"+name)
	return cmd.Run() == nil
}

func validStatus(status Status) bool {
	switch status {
	case StatusInventory, StatusCharacterized, StatusMigrating, StatusVerified, StatusQuarantined, StatusHistorical:
		return true
	default:
		return false
	}
}

func validDisposition(disposition Disposition) bool {
	switch disposition {
	case DispositionCanonicalize, DispositionCompose, DispositionExtractPrimitive, DispositionRetainSpecialty, DispositionQuarantine:
		return true
	default:
		return false
	}
}

func NormalizeRepositoryPath(input string) (string, error) {
	input = strings.ReplaceAll(strings.TrimSpace(input), `\`, "/")
	if input == "" {
		return "", errors.New("must not be empty")
	}
	if strings.HasPrefix(input, "/") || regexp.MustCompile(`^[A-Za-z]:/`).MatchString(input) {
		return "", fmt.Errorf("%q must be repository-relative", input)
	}
	clean := path.Clean(input)
	clean = strings.TrimPrefix(clean, "./")
	if clean == "." || clean == ".." || strings.HasPrefix(clean, "../") {
		return "", fmt.Errorf("%q escapes the repository", input)
	}
	return clean, nil
}

func LoadChanges(filename string) ([]Change, error) {
	var reader io.Reader
	if filename == "-" {
		reader = os.Stdin
	} else {
		file, err := os.Open(filename)
		if err != nil {
			return nil, fmt.Errorf("open changes override: %w", err)
		}
		defer file.Close()
		reader = file
	}
	var envelope struct {
		Changes []Change `json:"changes"`
	}
	decoder := json.NewDecoder(reader)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&envelope); err != nil {
		return nil, fmt.Errorf("decode changes override: %w", err)
	}
	if err := validateChangeRecords(envelope.Changes); err != nil {
		return nil, fmt.Errorf("validate changes override: %w", err)
	}
	return envelope.Changes, nil
}

func GitChanges(ctx context.Context, repositoryRoot, baseSHA string, includeUntracked bool) ([]Change, error) {
	if strings.TrimSpace(baseSHA) == "" {
		return nil, errors.New("base SHA must not be empty")
	}
	cmd := exec.CommandContext(ctx, "git", "-C", repositoryRoot, "diff", "--name-status", "-z", "--find-renames", baseSHA, "--")
	raw, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("git diff from base %q: %w", baseSHA, err)
	}
	changes, err := ParseNameStatus(raw)
	if err != nil {
		return nil, err
	}
	if includeUntracked {
		cmd = exec.CommandContext(ctx, "git", "-C", repositoryRoot, "ls-files", "--others", "--exclude-standard", "-z")
		raw, err = cmd.Output()
		if err != nil {
			return nil, fmt.Errorf("list untracked files: %w", err)
		}
		for _, item := range bytes.Split(raw, []byte{0}) {
			if len(item) != 0 {
				changes = append(changes, Change{Kind: ChangeUntracked, Path: string(item)})
			}
		}
	}
	sort.Slice(changes, func(i, j int) bool {
		if changes[i].Path == changes[j].Path {
			return changes[i].Kind < changes[j].Kind
		}
		return changes[i].Path < changes[j].Path
	})
	return changes, nil
}

func ParseNameStatus(raw []byte) ([]Change, error) {
	fields := bytes.Split(raw, []byte{0})
	var changes []Change
	for i := 0; i < len(fields) && len(fields[i]) > 0; {
		status := string(fields[i])
		i++
		if i >= len(fields) {
			return nil, fmt.Errorf("malformed git name-status output after %q", status)
		}
		switch status[0] {
		case 'A':
			changes = append(changes, Change{Kind: ChangeAdd, Path: string(fields[i])})
			i++
		case 'M', 'T', 'C':
			changes = append(changes, Change{Kind: ChangeModify, Path: string(fields[i])})
			i++
		case 'D':
			changes = append(changes, Change{Kind: ChangeDelete, Path: string(fields[i])})
			i++
		case 'R':
			if i+1 >= len(fields) {
				return nil, fmt.Errorf("malformed rename in git name-status output")
			}
			changes = append(changes, Change{Kind: ChangeRename, OldPath: string(fields[i]), Path: string(fields[i+1])})
			i += 2
		default:
			return nil, fmt.Errorf("unsupported git status %q", status)
		}
	}
	return changes, nil
}

func ValidateChanges(ledger *Ledger, changes []Change, mode Mode) error {
	if err := validateChangeRecords(changes); err != nil {
		return err
	}
	var problems []string
	peerFamilyStatus := make(map[string]Status)
	for _, family := range ledger.Families {
		for _, peer := range family.Peers {
			peerFamilyStatus[peer.Path] = family.Status
		}
	}
	for _, raw := range changes {
		change := raw
		normalized, err := NormalizeRepositoryPath(change.Path)
		if err != nil {
			problems = append(problems, fmt.Sprintf("%s path: %v", change.Kind, err))
			continue
		}
		change.Path = normalized
		if change.OldPath != "" {
			change.OldPath, err = NormalizeRepositoryPath(change.OldPath)
			if err != nil {
				problems = append(problems, fmt.Sprintf("%s old_path: %v", change.Kind, err))
				continue
			}
		}

		generated := matchesAnyPolicy(change.Path, ledger.PathPolicies.GeneratedOutputs)
		inGeneratedRoot := matchesAnyRoot(change.Path, ledger.PathPolicies.GeneratedRoots)
		temporary := matchesAnyPolicy(change.Path, ledger.PathPolicies.TemporaryOutputs)
		if inGeneratedRoot && !generated {
			problems = append(problems, fmt.Sprintf("unlisted generated variant %q", change.Path))
			continue
		}
		if change.Kind == ChangeDelete || change.Kind == ChangeRename {
			if change.Kind == ChangeDelete && change.ExecutionCreated && temporary {
				continue
			}
			target := change.Path
			if change.Kind == ChangeRename {
				target = change.OldPath
			}
			problems = append(problems, fmt.Sprintf("%s of pre-existing path %q is forbidden", change.Kind, target))
			continue
		}
		if generated {
			continue
		}
		if change.Kind == ChangeModify && protectedPathStatus(change.Path, peerFamilyStatus) == StatusInventory {
			problems = append(problems, fmt.Sprintf("uncharacterized modification of inventory peer %q is forbidden", change.Path))
			continue
		}
		if change.Kind == ChangeUntracked && mode == ModeCI {
			problems = append(problems, fmt.Sprintf("untracked path %q is forbidden in CI mode", change.Path))
		}
	}
	if len(problems) > 0 {
		sort.Strings(problems)
		return errors.New(strings.Join(problems, "\n"))
	}
	return nil
}

func validateChangeRecords(changes []Change) error {
	var problems []string
	for index, change := range changes {
		switch change.Kind {
		case ChangeAdd, ChangeModify, ChangeRename, ChangeDelete, ChangeUntracked:
		default:
			problems = append(problems, fmt.Sprintf("change %d has invalid kind %q", index, change.Kind))
			continue
		}
		if strings.TrimSpace(change.Path) == "" {
			problems = append(problems, fmt.Sprintf("change %d kind %q lacks path", index, change.Kind))
		}
		if change.Kind == ChangeRename {
			if strings.TrimSpace(change.OldPath) == "" {
				problems = append(problems, fmt.Sprintf("change %d rename lacks old_path", index))
			}
		} else if change.OldPath != "" {
			problems = append(problems, fmt.Sprintf("change %d kind %q must not set old_path", index, change.Kind))
		}
		if change.ExecutionCreated && change.Kind != ChangeDelete {
			problems = append(problems, fmt.Sprintf("change %d kind %q cannot be execution-created", index, change.Kind))
		}
	}
	if len(problems) > 0 {
		sort.Strings(problems)
		return errors.New(strings.Join(problems, "\n"))
	}
	return nil
}

func protectedPathStatus(name string, statuses map[string]Status) Status {
	var result Status
	longest := 0
	for peerPath, status := range statuses {
		if (name == peerPath || strings.HasPrefix(name, strings.TrimSuffix(peerPath, "/")+"/")) && len(peerPath) > longest {
			result = status
			longest = len(peerPath)
		}
	}
	return result
}

func matchesAnyRoot(name string, roots []string) bool {
	for _, root := range roots {
		root = strings.TrimSuffix(strings.ReplaceAll(root, `\`, "/"), "/") + "/"
		if strings.HasPrefix(name, root) {
			return true
		}
	}
	return false
}

func matchesAnyPolicy(name string, policies []PathPolicy) bool {
	for _, policy := range policies {
		if matchPolicy(name, policy.Pattern) {
			return true
		}
	}
	return false
}

func matchPolicy(name, pattern string) bool {
	pattern = strings.ReplaceAll(pattern, `\`, "/")
	if strings.HasSuffix(pattern, "/**") {
		return strings.HasPrefix(name, strings.TrimSuffix(pattern, "**"))
	}
	ok, err := path.Match(pattern, name)
	return err == nil && ok
}
