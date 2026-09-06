package main

import (
	"context"
	"flag"
	"fmt"
	"os"

	"luminet.local/scripts/internal/preservationledger"
)

func main() {
	var opts preservationledger.Options
	flag.StringVar(&opts.LedgerPath, "ledger", "", "preservation ledger override")
	flag.StringVar(&opts.SchemaPath, "schema", "", "Draft 2020-12 schema override")
	flag.StringVar(&opts.RepositoryRoot, "repo-root", "..", "repository root")
	flag.StringVar(&opts.BaseSHA, "base-sha", os.Getenv("PRESERVATION_BASE_SHA"), "deterministic git diff base SHA")
	flag.StringVar(&opts.ChangesPath, "changes", "", "JSON change override path, or - for stdin")
	mode := flag.String("mode", defaultEnvironmentValue("PRESERVATION_MODE", "local"), "untracked-file policy: local or ci")
	flag.BoolVar(&opts.IncludeUntracked, "include-untracked", false, "include untracked files in a base-SHA diff")
	flag.Parse()
	opts.Mode = preservationledger.Mode(*mode)

	result, err := preservationledger.Run(context.Background(), opts)
	if err != nil {
		fmt.Fprintf(os.Stderr, "preservation ledger invalid: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf(
		"preservation ledger valid: schema=v1 families=%d peers=%d changes=%d mode=%s\n",
		result.Families,
		result.Peers,
		result.Changes,
		opts.Mode,
	)
}

func defaultEnvironmentValue(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}
