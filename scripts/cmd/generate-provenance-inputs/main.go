package main

import (
	"flag"
	"fmt"
	"os"

	"luminet.local/scripts/internal/provenanceledger"
)

func main() {
	var opts provenanceledger.Options
	var outputPath string
	flag.StringVar(&opts.RepositoryRoot, "repo-root", "..", "repository root")
	flag.StringVar(&opts.LedgerPath, "ledger", "", "provenance JSONL ledger override")
	flag.StringVar(&opts.SchemaPath, "schema", "", "Draft 2020-12 source-record schema override")
	flag.StringVar(&opts.PreservationLedgerPath, "preservation-ledger", "", "preservation ledger override used for source_ref resolution")
	flag.StringVar(&opts.BaseLedgerPath, "base-ledger", os.Getenv("PROVENANCE_BASE_LEDGER"), "optional prior JSONL ledger used to enforce append-only history")
	flag.StringVar(&opts.BaseRef, "base-ref", defaultBaseRef(), "trusted git ref used to derive the append-only baseline when -base-ledger is unset")
	flag.StringVar(&outputPath, "out", "-", "output path, or - for stdout")
	flag.Parse()

	result, err := provenanceledger.Validate(opts)
	if err != nil {
		fmt.Fprintf(os.Stderr, "provenance generation blocked: %v\n", err)
		os.Exit(1)
	}
	output, err := provenanceledger.GenerateInputs(result.ValidatedRecords)
	if err != nil {
		fmt.Fprintf(os.Stderr, "provenance generation blocked: %v\n", err)
		os.Exit(1)
	}
	if outputPath == "-" {
		if _, err := os.Stdout.Write(output); err != nil {
			fmt.Fprintf(os.Stderr, "write provenance generation inputs: %v\n", err)
			os.Exit(1)
		}
		return
	}
	if err := os.WriteFile(outputPath, output, 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "write provenance generation inputs: %v\n", err)
		os.Exit(1)
	}
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
