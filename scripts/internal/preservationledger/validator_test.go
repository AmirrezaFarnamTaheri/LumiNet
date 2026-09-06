package preservationledger

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestRepositoryLedgerPassesSchemaAndSemanticValidation(t *testing.T) {
	repositoryRoot := filepath.Clean(filepath.Join("..", "..", ".."))
	if _, err := os.Stat(filepath.Join(repositoryRoot, ".git")); err != nil {
		t.Skip("repository-history validation requires a Git checkout")
	}
	result, err := Run(context.Background(), Options{
		LedgerPath:     filepath.Join(repositoryRoot, "governance", "conductor", "preservation-ledger", "families.v1.json"),
		SchemaPath:     filepath.Join(repositoryRoot, "governance", "conductor", "preservation-ledger", "schema-v1.json"),
		RepositoryRoot: repositoryRoot,
		Mode:           ModeLocal,
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Families != 21 {
		t.Fatalf("family count = %d, want 21", result.Families)
	}
}

func TestOptionsUseCanonicalRepositoryPaths(t *testing.T) {
	root := t.TempDir()
	opts := withCanonicalPaths(Options{RepositoryRoot: root})
	if got, want := opts.LedgerPath, filepath.Join(root, "governance", "conductor", "preservation-ledger", "families.v1.json"); got != want {
		t.Fatalf("LedgerPath = %q, want %q", got, want)
	}
	if got, want := opts.SchemaPath, filepath.Join(root, "governance", "conductor", "preservation-ledger", "schema-v1.json"); got != want {
		t.Fatalf("SchemaPath = %q, want %q", got, want)
	}
}

func TestNormalizeRepositoryPath(t *testing.T) {
	t.Parallel()
	for _, input := range []string{
		`server\internal\proxy\peer.go`,
		`./server/internal/proxy/peer.go`,
		`server/internal/./proxy/peer.go`,
	} {
		got, err := NormalizeRepositoryPath(input)
		if err != nil {
			t.Fatalf("NormalizeRepositoryPath(%q): %v", input, err)
		}
		if got != "server/internal/proxy/peer.go" {
			t.Fatalf("NormalizeRepositoryPath(%q) = %q", input, got)
		}
	}
	for _, input := range []string{"", "../peer.go", "/peer.go", `C:\peer.go`} {
		if _, err := NormalizeRepositoryPath(input); err == nil {
			t.Fatalf("NormalizeRepositoryPath(%q) unexpectedly succeeded", input)
		}
	}
}

func TestValidateChangesProtectsEveryPreExistingPath(t *testing.T) {
	t.Parallel()
	l := testLedger()
	for _, change := range []Change{
		{Kind: ChangeDelete, Path: "unlisted/old.go"},
		{Kind: ChangeRename, OldPath: "tracked/peer.go", Path: "tracked/renamed.go"},
		{Kind: ChangeDelete, Path: "tracked/peer.go"},
	} {
		err := ValidateChanges(l, []Change{change}, ModeCI)
		if err == nil || !strings.Contains(err.Error(), "pre-existing") {
			t.Fatalf("change %#v: expected pre-existing path rejection, got %v", change, err)
		}
	}
}

func TestValidateChangesBlocksUncharacterizedPeerMigration(t *testing.T) {
	t.Parallel()
	l := testLedger()
	l.Families[0].Status = StatusInventory
	change := Change{Kind: ChangeModify, Path: "tracked/peer.go"}
	if err := ValidateChanges(l, []Change{change}, ModeCI); err == nil || !strings.Contains(err.Error(), "uncharacterized") {
		t.Fatalf("inventory peer modification was not rejected: %v", err)
	}
	l.Families[0].Status = StatusCharacterized
	if err := ValidateChanges(l, []Change{change}, ModeCI); err != nil {
		t.Fatalf("characterized peer modification rejected: %v", err)
	}
}

func TestValidateChangesTemporaryOutputPolicy(t *testing.T) {
	t.Parallel()
	l := testLedger()
	allowed := Change{
		Kind:             ChangeDelete,
		Path:             "tmp/preservation-ledger/run-1.json",
		ExecutionCreated: true,
	}
	if err := ValidateChanges(l, []Change{allowed}, ModeCI); err != nil {
		t.Fatalf("explicit execution-created temporary output rejected: %v", err)
	}
	allowed.ExecutionCreated = false
	if err := ValidateChanges(l, []Change{allowed}, ModeCI); err == nil {
		t.Fatal("pre-existing temporary-looking output unexpectedly allowed")
	}
}

func TestValidateChangesGeneratedAndUntrackedModes(t *testing.T) {
	t.Parallel()
	l := testLedger()
	if err := ValidateChanges(l, []Change{{
		Kind: ChangeUntracked, Path: "generated/variants/unknown.go",
	}}, ModeLocal); err == nil || !strings.Contains(err.Error(), "unlisted generated") {
		t.Fatalf("unlisted generated variant: got %v", err)
	}
	if err := ValidateChanges(l, []Change{{
		Kind: ChangeUntracked, Path: "notes/local.txt",
	}}, ModeLocal); err != nil {
		t.Fatalf("local untracked file rejected: %v", err)
	}
	if err := ValidateChanges(l, []Change{{
		Kind: ChangeUntracked, Path: "notes/local.txt",
	}}, ModeCI); err == nil || !strings.Contains(err.Error(), "untracked") {
		t.Fatalf("CI untracked file: got %v", err)
	}
	if err := ValidateChanges(l, []Change{{
		Kind: ChangeUntracked, Path: "generated/approved/report.json",
	}}, ModeCI); err != nil {
		t.Fatalf("policy-listed generated output rejected: %v", err)
	}
}

func TestLoadChangesRejectsRelabeledDelete(t *testing.T) {
	t.Parallel()
	filename := filepath.Join(t.TempDir(), "changes.json")
	raw := `{"changes":[{"kind":"not-a-git-status","old_path":"tracked/peer.go","path":"tracked/renamed.go"}]}`
	if err := os.WriteFile(filename, []byte(raw), 0o600); err != nil {
		t.Fatal(err)
	}
	changes, err := LoadChanges(filename)
	if err == nil || !strings.Contains(err.Error(), `invalid kind "not-a-git-status"`) {
		t.Fatalf("relabeled delete/rename override was not rejected: changes=%#v err=%v", changes, err)
	}
}

func TestValidateChangesRejectsMalformedRecordsFromCallers(t *testing.T) {
	t.Parallel()
	tests := []Change{
		{Kind: ChangeKind("not-a-git-status"), OldPath: "tracked/peer.go", Path: "tracked/renamed.go"},
		{Kind: ChangeRename, Path: "tracked/renamed.go"},
		{Kind: ChangeModify, OldPath: "tracked/peer.go", Path: "tracked/peer.go"},
		{Kind: ChangeAdd, Path: "new.go", ExecutionCreated: true},
	}
	for _, change := range tests {
		if err := ValidateChanges(testLedger(), []Change{change}, ModeCI); err == nil {
			t.Fatalf("malformed change %#v unexpectedly accepted", change)
		}
	}
}

func TestValidateLedgerSemanticRules(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	writeFile(t, root, "tracked/peer.go")
	l := testLedger()
	if err := ValidateLedgerSemantics(l, root, ""); err != nil {
		t.Fatalf("valid ledger rejected: %v", err)
	}

	duplicate := cloneLedger(t, l)
	duplicate.Families = append(duplicate.Families, duplicate.Families[0])
	if err := ValidateLedgerSemantics(duplicate, root, ""); err == nil || !strings.Contains(err.Error(), "duplicate family_id") {
		t.Fatalf("duplicate family ID: got %v", err)
	}

	unknownDisposition := cloneLedger(t, l)
	unknownDisposition.Families[0].Disposition = "delete"
	if err := ValidateLedgerSemantics(unknownDisposition, root, ""); err == nil || !strings.Contains(err.Error(), "disposition") {
		t.Fatalf("unknown disposition: got %v", err)
	}

	unknownStatus := cloneLedger(t, l)
	unknownStatus.Families[0].Status = "done"
	if err := ValidateLedgerSemantics(unknownStatus, root, ""); err == nil || !strings.Contains(err.Error(), "status") {
		t.Fatalf("unknown status: got %v", err)
	}

	duplicatePeer := cloneLedger(t, l)
	duplicatePeer.Families[0].Peers = append(duplicatePeer.Families[0].Peers, duplicatePeer.Families[0].Peers[0])
	if err := ValidateLedgerSemantics(duplicatePeer, root, ""); err == nil || !strings.Contains(err.Error(), "duplicate peer_id") {
		t.Fatalf("duplicate peer ID: got %v", err)
	}

	duplicateSource := cloneLedger(t, l)
	duplicateSource.Sources = append(duplicateSource.Sources, duplicateSource.Sources[0])
	if err := ValidateLedgerSemantics(duplicateSource, root, ""); err == nil || !strings.Contains(err.Error(), "duplicate source_ref") {
		t.Fatalf("duplicate source ID: got %v", err)
	}
}

func TestMissingHistoricalSourceRequiresImmutableQuarantine(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	l := testLedger()
	p := &l.Families[0].Peers[0]
	p.State = PeerHistorical
	p.Disposition = DispositionQuarantine
	p.Provenance.ImmutableRef = "sha256:0123456789abcdef"
	if err := ValidateLedgerSemantics(l, root, ""); err != nil {
		t.Fatalf("complete historical source rejected: %v", err)
	}

	p.Provenance.ImmutableRef = ""
	if err := ValidateLedgerSemantics(l, root, ""); err == nil || !strings.Contains(err.Error(), "immutable") {
		t.Fatalf("historical source without immutable provenance: got %v", err)
	}
}

func TestParseNameStatusIncludesAllClassifications(t *testing.T) {
	t.Parallel()
	raw := []byte("A\x00a.go\x00M\x00m.go\x00D\x00d.go\x00R100\x00old.go\x00new.go\x00")
	got, err := ParseNameStatus(raw)
	if err != nil {
		t.Fatal(err)
	}
	want := []ChangeKind{ChangeAdd, ChangeModify, ChangeDelete, ChangeRename}
	if len(got) != len(want) {
		t.Fatalf("got %d changes, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i].Kind != want[i] {
			t.Fatalf("change %d kind = %q, want %q", i, got[i].Kind, want[i])
		}
	}
}

func TestGitChangesRejectsCurrentDeletedTrackedPeer(t *testing.T) {
	root := t.TempDir()
	runGit(t, root, "init", "-q")
	runGit(t, root, "config", "user.email", "ledger-test@invalid.example")
	runGit(t, root, "config", "user.name", "Preservation Ledger Test")
	writeFile(t, root, "tracked/peer.go")
	runGit(t, root, "add", "tracked/peer.go")
	runGit(t, root, "commit", "-q", "-m", "seed")
	base := strings.TrimSpace(runGit(t, root, "rev-parse", "HEAD"))
	if err := os.Remove(filepath.Join(root, "tracked", "peer.go")); err != nil {
		t.Fatal(err)
	}

	changes, err := GitChanges(context.Background(), root, base, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(changes) != 1 || changes[0].Kind != ChangeDelete {
		t.Fatalf("changes = %#v, want one deletion", changes)
	}
	if err := ValidateChanges(testLedger(), changes, ModeCI); err == nil || !strings.Contains(err.Error(), "pre-existing") {
		t.Fatalf("deleted tracked peer was not rejected: %v", err)
	}
}

func testLedger() *Ledger {
	return &Ledger{
		SchemaVersion: 1,
		Sources: []Source{{
			SourceRef: "src:repo", Kind: "repository", Locator: ".",
		}},
		PathPolicies: PathPolicies{
			GeneratedRoots: []string{"generated/"},
			GeneratedOutputs: []PathPolicy{{
				PolicyID: "generated-report", Pattern: "generated/approved/**",
			}},
			TemporaryOutputs: []PathPolicy{{
				PolicyID: "validator-temp", Pattern: "tmp/preservation-ledger/**",
			}},
		},
		Families: []Family{{
			FamilyID:          "family:test",
			Status:            StatusCharacterized,
			Disposition:       DispositionCanonicalize,
			CanonicalPeerID:   "peer:test",
			DeletionPredicate: "Retirement is outside this program.",
			Peers: []Peer{{
				PeerID: "peer:test", SourceRef: "src:repo", Path: "tracked/peer.go",
				State: PeerLive, Role: "test peer",
				PreservedDetails:     []string{"behavior"},
				Consumers:            []string{},
				VerificationEvidence: []string{"go test ./..."},
				Disposition:          DispositionCanonicalize,
				Provenance:           Provenance{Evidence: []string{"repository path"}},
			}},
		}},
	}
}

func cloneLedger(t *testing.T, in *Ledger) *Ledger {
	t.Helper()
	raw, err := json.Marshal(in)
	if err != nil {
		t.Fatal(err)
	}
	var out Ledger
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatal(err)
	}
	return &out
}

func writeFile(t *testing.T, root, name string) {
	t.Helper()
	path := filepath.Join(root, filepath.FromSlash(name))
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("test"), 0o600); err != nil {
		t.Fatal(err)
	}
}

func runGit(t *testing.T, root string, args ...string) string {
	t.Helper()
	command := exec.Command("git", append([]string{"-C", root}, args...)...)
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, output)
	}
	return string(output)
}
