package main

import (
	"flag"
	"fmt"
	"os"

	"luminet.local/scripts/internal/provenanceledger"
)

func main() {
	var opts provenanceledger.Options
	flag.StringVar(&opts.RepositoryRoot, "repo-root", "..", "repository root")
	flag.StringVar(&opts.LedgerPath, "ledger", "", "provenance JSONL ledger override")
	flag.StringVar(&opts.SchemaPath, "schema", "", "Draft 2020-12 source-record schema override")
	flag.StringVar(&opts.PreservationLedgerPath, "preservation-ledger", "", "preservation ledger override used for source_ref resolution")
	flag.StringVar(&opts.BaseLedgerPath, "base-ledger", os.Getenv("PROVENANCE_BASE_LEDGER"), "optional prior JSONL ledger used to enforce append-only history")
	flag.StringVar(&opts.BaseRef, "base-ref", defaultBaseRef(), "trusted git ref used to derive the append-only baseline when -base-ledger is unset")
	flag.Parse()

	result, err := provenanceledger.Validate(opts)
	if err != nil {
		fmt.Fprintf(os.Stderr, "provenance ledger invalid: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf(
		"provenance ledger valid: schema=v1 records=%d snapshots=%d trusted_baseline=%s preservation_refs=resolved\n",
		result.Records,
		result.Snapshots,
		baselineDescription(opts),
	)
}

func defaultBaseRef() string {
	if value := os.Getenv("PROVENANCE_BASE_REF"); value != "" {
		return value
	}
	if os.Getenv("CI") != "" {
		return ""
	}
	return "HEAD"
}

func baselineDescription(opts provenanceledger.Options) string {
	if opts.BaseLedgerPath != "" {
		return "file:" + opts.BaseLedgerPath
	}
	return "git:" + opts.BaseRef
}
