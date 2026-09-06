package provenanceledger

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestValidateRepositoryLedger(t *testing.T) {
	root := repositoryRoot(t)
	result, err := Validate(Options{
		RepositoryRoot: root,
		BaseLedgerPath: filepath.Join(root, "governance", "conductor", "provenance-ledger", "sources.v1.jsonl"),
	})
	if err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
	if result.Records == 0 {
		t.Fatal("Validate() records = 0, want bootstrap record")
	}
}

func TestValidateRequiresTrustedAppendOnlyBaseline(t *testing.T) {
	fixture := newFixture(t, []byte("immutable snapshot"))
	fixture.writeLedger(t, []Record{fixture.record})
	opts := fixture.options()
	opts.BaseLedgerPath = ""

	_, err := Validate(opts)
	if err == nil || !strings.Contains(err.Error(), "trusted append-only baseline") {
		t.Fatalf("Validate() error = %v, want trusted baseline requirement", err)
	}
}

func TestValidateDerivesApprovedGitBaselineAndRejectsAlteredLine(t *testing.T) {
	fixture := newFixture(t, []byte("immutable snapshot"))
	fixture.writeLedger(t, []Record{fixture.record})
	runGit(t, fixture.root, "init")
	runGit(t, fixture.root, "config", "user.name", "Provenance Test")
	runGit(t, fixture.root, "config", "user.email", "provenance-test@invalid.example")
	runGit(t, fixture.root, "add", ".")
	runGit(t, fixture.root, "commit", "-m", "approved provenance baseline")

	opts := fixture.options()
	opts.BaseLedgerPath = ""
	opts.BaseRef = "HEAD"
	if _, err := Validate(opts); err != nil {
		t.Fatalf("Validate() approved git baseline error = %v", err)
	}

	altered := fixture.record
	altered.DisplayName = "Altered Source"
	fixture.writeLedger(t, []Record{altered})
	_, err := Validate(opts)
	if err == nil || !strings.Contains(err.Error(), "append-only violation") {
		t.Fatalf("Validate() altered line error = %v, want append-only violation", err)
	}
}

func TestValidateResolvesEveryPreservationSourceRef(t *testing.T) {
	fixture := newFixture(t, []byte("immutable snapshot"))
	fixture.writeLedger(t, []Record{fixture.record})

	t.Run("invented declared source", func(t *testing.T) {
		fixture.writePreservation(t, "source:invented", fixture.record.SourceRef)
		_, err := Validate(fixture.options())
		if err == nil || !strings.Contains(err.Error(), `preservation source_ref "source:invented"`) {
			t.Fatalf("Validate() error = %v, want unresolved declared source", err)
		}
	})

	t.Run("invented peer source", func(t *testing.T) {
		fixture.writePreservation(t, fixture.record.SourceRef, "source:missing-peer-source")
		_, err := Validate(fixture.options())
		if err == nil || !strings.Contains(err.Error(), `peer source_ref "source:missing-peer-source"`) {
			t.Fatalf("Validate() error = %v, want unresolved peer source", err)
		}
	})
}

func TestValidateDetectsAlteredSnapshotAndMetadataMismatch(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*Record)
		write  []byte
		want   string
	}{
		{
			name:  "altered snapshot digest",
			write: []byte("altered-snap-shot!"),
			want:  "digest mismatch",
		},
		{
			name: "declared digest",
			mutate: func(record *Record) {
				record.Content.Digest = strings.Repeat("0", 64)
			},
			want: "digest mismatch",
		},
		{
			name: "declared byte size",
			mutate: func(record *Record) {
				record.Content.ByteSize++
			},
			want: "byte_size mismatch",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newFixture(t, []byte("immutable snapshot"))
			record := fixture.record
			if test.mutate != nil {
				test.mutate(&record)
			}
			fixture.writeLedger(t, []Record{record})
			if test.write != nil {
				if err := os.WriteFile(fixture.snapshotPath, test.write, 0o600); err != nil {
					t.Fatal(err)
				}
			}

			_, err := Validate(fixture.options())
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("Validate() error = %v, want containing %q", err, test.want)
			}
		})
	}
}

func TestValidateRequiresRetrievableImmutableSource(t *testing.T) {
	fixture := newFixture(t, []byte("immutable snapshot"))
	fixture.record.ImmutableLocator = "raw\\snapshots\\missing.snapshot"
	fixture.writeLedger(t, []Record{fixture.record})

	_, err := Validate(fixture.options())
	if err == nil || !strings.Contains(err.Error(), "immutable_locator") {
		t.Fatalf("Validate() error = %v, want missing immutable_locator", err)
	}
}

func TestValidateRejectsEmptyBootstrapLedger(t *testing.T) {
	fixture := newFixture(t, []byte("immutable snapshot"))
	fixture.writeLedger(t, nil)
	_, err := Validate(fixture.options())
	if err == nil || !strings.Contains(err.Error(), "at least one source record") {
		t.Fatalf("Validate() error = %v, want empty ledger rejection", err)
	}
}

func TestValidateEnforcesUniqueAndAppendOnlyRecords(t *testing.T) {
	fixture := newFixture(t, []byte("immutable snapshot"))
	second := fixture.record
	second.SourceRef = "source:second"
	second.DisplayName = fixture.record.DisplayName
	second.ImmutableLocator = "raw/snapshots/second.snapshot"
	secondBytes := []byte("second snapshot")
	second.Content = contentFor(secondBytes)
	if err := os.WriteFile(filepath.Join(fixture.root, filepath.FromSlash(second.ImmutableLocator)), secondBytes, 0o600); err != nil {
		t.Fatal(err)
	}

	t.Run("duplicate source_ref", func(t *testing.T) {
		fixture.writeLedger(t, []Record{fixture.record, fixture.record})
		_, err := Validate(fixture.options())
		if err == nil || !strings.Contains(err.Error(), "duplicate source_ref") {
			t.Fatalf("Validate() error = %v, want duplicate source_ref", err)
		}
	})

	basePath := filepath.Join(fixture.root, "base.jsonl")
	writeJSONL(t, basePath, []Record{fixture.record})

	t.Run("append succeeds with duplicate display name", func(t *testing.T) {
		fixture.writeLedger(t, []Record{fixture.record, second})
		opts := fixture.options()
		opts.BaseLedgerPath = basePath
		if _, err := Validate(opts); err != nil {
			t.Fatalf("Validate() error = %v", err)
		}
	})

	t.Run("update rejected", func(t *testing.T) {
		updated := fixture.record
		updated.DisplayName = "changed"
		fixture.writeLedger(t, []Record{updated})
		opts := fixture.options()
		opts.BaseLedgerPath = basePath
		_, err := Validate(opts)
		if err == nil || !strings.Contains(err.Error(), "append-only violation") {
			t.Fatalf("Validate() error = %v, want append-only violation", err)
		}
	})

	t.Run("delete rejected", func(t *testing.T) {
		fixture.writeLedger(t, nil)
		opts := fixture.options()
		opts.BaseLedgerPath = basePath
		_, err := Validate(opts)
		if err == nil || !strings.Contains(err.Error(), "append-only violation") {
			t.Fatalf("Validate() error = %v, want append-only violation", err)
		}
	})
}

func TestValidateAllowsQualifiedAbsentUpstreamAndRejectsUnresolvedCommit(t *testing.T) {
	fixture := newFixture(t, []byte("immutable snapshot"))
	fixture.record.Upstream = Upstream{
		Status:   "unavailable",
		Evidence: []string{"source recovered without upstream metadata"},
	}
	fixture.record.Qualification = Qualification{
		State:    "unavailable",
		Evidence: []string{"local bytes remain digest verified"},
	}
	fixture.writeLedger(t, []Record{fixture.record})
	if _, err := Validate(fixture.options()); err != nil {
		t.Fatalf("qualified absent upstream rejected: %v", err)
	}

	fixture.record.Upstream = Upstream{
		Status:   "resolved",
		URL:      "https://example.invalid/repository",
		Evidence: []string{"upstream URL recovered but commit absent"},
	}
	fixture.record.Qualification.State = "qualified"
	fixture.writeLedger(t, []Record{fixture.record})
	_, err := Validate(fixture.options())
	if err == nil || !strings.Contains(err.Error(), "commit") {
		t.Fatalf("Validate() error = %v, want missing commit", err)
	}
}

func TestValidateRequiresForcePushContradictionEvidence(t *testing.T) {
	fixture := newFixture(t, []byte("immutable snapshot"))
	fixture.record.Upstream = Upstream{
		Status:   "force-push-suspected",
		URL:      "https://example.invalid/repository",
		Commit:   strings.Repeat("a", 40),
		Evidence: []string{"recorded commit no longer resolves upstream"},
	}
	fixture.record.Qualification = Qualification{
		State:    "contradictory",
		Evidence: []string{"immutable local snapshot retained"},
	}
	fixture.writeLedger(t, []Record{fixture.record})
	_, err := Validate(fixture.options())
	if err == nil || !strings.Contains(err.Error(), "contradiction_markers") {
		t.Fatalf("Validate() error = %v, want contradiction_markers", err)
	}

	fixture.record.Qualification.ContradictionMarkers = []string{"upstream-history-rewritten"}
	fixture.writeLedger(t, []Record{fixture.record})
	if _, err := Validate(fixture.options()); err != nil {
		t.Fatalf("qualified force-push evidence rejected: %v", err)
	}
}

func TestGenerationInputsAreStableAndNormalizePaths(t *testing.T) {
	fixture := newFixture(t, []byte("immutable snapshot"))
	second := fixture.record
	second.SourceRef = "source:alpha"
	second.ImmutableLocator = "raw\\snapshots\\fixture.snapshot"
	second.DisplayName = "Alpha"

	forward, err := GenerateInputs([]Record{fixture.record, second})
	if err != nil {
		t.Fatal(err)
	}
	reversed, err := GenerateInputs([]Record{second, fixture.record})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(forward, reversed) {
		t.Fatalf("GenerateInputs() unstable:\n%s\n%s", forward, reversed)
	}
	if bytes.Contains(forward, []byte(`raw\\snapshots`)) {
		t.Fatalf("GenerateInputs() did not normalize locator: %s", forward)
	}
	if !bytes.HasSuffix(forward, []byte("\n")) {
		t.Fatal("GenerateInputs() missing final newline")
	}
}

func TestQualificationAndLocatorSemanticEdges(t *testing.T) {
	base := newFixture(t, []byte("immutable snapshot")).record
	for _, test := range []struct {
		name   string
		mutate func(*Record)
		want   string
	}{
		{
			name: "non UTC retrieval",
			mutate: func(record *Record) {
				record.RetrievedAt = record.RetrievedAt.In(time.FixedZone("offset", 60*60))
			},
			want: "UTC",
		},
		{
			name: "resolved without URL",
			mutate: func(record *Record) {
				record.Upstream.Status = "resolved"
				record.Upstream.Commit = strings.Repeat("a", 40)
				record.Qualification.State = "qualified"
			},
			want: "requires url",
		},
		{
			name: "resolved without qualified state",
			mutate: func(record *Record) {
				record.Upstream.Status = "resolved"
				record.Upstream.URL = "https://example.invalid/repository"
				record.Upstream.Commit = strings.Repeat("a", 40)
			},
			want: "requires qualified",
		},
		{
			name: "unsupported upstream",
			mutate: func(record *Record) {
				record.Upstream.Status = "invented"
			},
			want: "unsupported upstream status",
		},
		{
			name: "identified license without SPDX",
			mutate: func(record *Record) {
				record.License.Status = "identified"
			},
			want: "requires spdx_id",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			record := base
			test.mutate(&record)
			err := validateQualification(record)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("validateQualification() error = %v, want containing %q", err, test.want)
			}
		})
	}

	for _, locator := range []string{"", "/absolute", "../escape", `C:\escape`} {
		t.Run("locator "+locator, func(t *testing.T) {
			if _, err := normalizeLocator(locator); err == nil {
				t.Fatalf("normalizeLocator(%q) succeeded, want rejection", locator)
			}
		})
	}
}

func TestLoadRecordsUsesSchemaValidatedJSONL(t *testing.T) {
	fixture := newFixture(t, []byte("immutable snapshot"))
	fixture.writeLedger(t, []Record{fixture.record})
	records, err := LoadRecords(fixture.ledgerPath, fixture.schemaPath)
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 1 || records[0].SourceRef != fixture.record.SourceRef {
		t.Fatalf("LoadRecords() = %#v", records)
	}

	if err := os.WriteFile(fixture.ledgerPath, []byte(`{} {}`+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadRecords(fixture.ledgerPath, fixture.schemaPath); err == nil {
		t.Fatal("LoadRecords() accepted multiple JSON values on one line")
	}
}

type fixture struct {
	root             string
	ledgerPath       string
	schemaPath       string
	baselinePath     string
	preservationPath string
	snapshotPath     string
	record           Record
}

func newFixture(t *testing.T, snapshot []byte) fixture {
	t.Helper()
	root := t.TempDir()
	snapshotPath := filepath.Join(root, "raw", "snapshots", "fixture.snapshot")
	if err := os.MkdirAll(filepath.Dir(snapshotPath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(snapshotPath, snapshot, 0o600); err != nil {
		t.Fatal(err)
	}
	schemaPath := filepath.Join(root, "schema-v1.json")
	rootSchema := filepath.Join(repositoryRoot(t), "governance", "conductor", "provenance-ledger", "schema-v1.json")
	schema, err := os.ReadFile(rootSchema)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(schemaPath, schema, 0o600); err != nil {
		t.Fatal(err)
	}
	baselinePath := filepath.Join(root, "baseline.jsonl")
	if err := os.WriteFile(baselinePath, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	fixture := fixture{
		root:             root,
		ledgerPath:       filepath.Join(root, "sources.v1.jsonl"),
		schemaPath:       schemaPath,
		baselinePath:     baselinePath,
		preservationPath: filepath.Join(root, "preservation.json"),
		snapshotPath:     snapshotPath,
		record: Record{
			SchemaVersion:    1,
			SourceRef:        "source:fixture",
			DisplayName:      "Fixture Source",
			SourceKind:       "historical-artifact",
			ImmutableLocator: "raw/snapshots/fixture.snapshot",
			Content:          contentFor(snapshot),
			RetrievedAt:      time.Date(2026, 7, 29, 0, 0, 0, 0, time.UTC),
			Upstream: Upstream{
				Status:   "unavailable",
				Evidence: []string{"fixture has no upstream"},
			},
			License: License{
				Status:   "unknown",
				Evidence: []string{"fixture license not asserted"},
			},
			Qualification: Qualification{
				State:    "unavailable",
				Evidence: []string{"fixture retains immutable local evidence"},
			},
		},
	}
	fixture.writePreservation(t, fixture.record.SourceRef, fixture.record.SourceRef)
	return fixture
}

func (fixture fixture) options() Options {
	return Options{
		RepositoryRoot:         fixture.root,
		LedgerPath:             fixture.ledgerPath,
		SchemaPath:             fixture.schemaPath,
		BaseLedgerPath:         fixture.baselinePath,
		PreservationLedgerPath: fixture.preservationPath,
	}
}

func (fixture fixture) writeLedger(t *testing.T, records []Record) {
	t.Helper()
	writeJSONL(t, fixture.ledgerPath, records)
}

func (fixture fixture) writePreservation(t *testing.T, declaredSourceRef, peerSourceRef string) {
	t.Helper()
	raw := []byte(`{"sources":[{"source_ref":"` + declaredSourceRef + `"}],"families":[{"family_id":"family:fixture","peers":[{"peer_id":"peer:fixture","source_ref":"` + peerSourceRef + `"}]}]}`)
	if err := os.WriteFile(fixture.preservationPath, raw, 0o600); err != nil {
		t.Fatal(err)
	}
}

func contentFor(raw []byte) Content {
	sum := sha256.Sum256(raw)
	return Content{
		Algorithm: "sha256",
		Digest:    hex.EncodeToString(sum[:]),
		ByteSize:  int64(len(raw)),
	}
}

func writeJSONL(t *testing.T, target string, records []Record) {
	t.Helper()
	var output bytes.Buffer
	for _, record := range records {
		line, err := MarshalRecord(record)
		if err != nil {
			t.Fatal(err)
		}
		output.Write(line)
		output.WriteByte('\n')
	}
	if err := os.WriteFile(target, output.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
}

func repositoryRoot(t *testing.T) string {
	t.Helper()
	current, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	return filepath.Clean(filepath.Join(current, "..", "..", ".."))
}

func runGit(t *testing.T, directory string, args ...string) {
	t.Helper()
	command := exec.Command("git", args...)
	command.Dir = directory
	command.Env = append(os.Environ(), "GIT_OPTIONAL_LOCKS=0")
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, output)
	}
}
