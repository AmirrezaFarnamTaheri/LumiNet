// Command validate-abi-manifest checks that the versioned ABI manifest is an
// exact declaration of the Rust FFI authority before bindings are generated.
package main

import (
	"flag"
	"fmt"
	"os"

	"luminet.local/scripts/internal/abimanifest"
)

func main() {
	var opts abimanifest.Options
	flag.StringVar(&opts.RepositoryRoot, "repo-root", "..", "repository root")
	flag.StringVar(&opts.ManifestPath, "manifest", "", "ABI manifest override")
	flag.StringVar(&opts.EnvelopePath, "envelope", "", "Rust FFI envelope authority override")
	flag.StringVar(&opts.VersionPath, "version", "", "Rust FFI version authority override")
	flag.Parse()

	result, err := abimanifest.Validate(opts)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ABI manifest invalid: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("ABI manifest valid: abi_major=%d operations=%d Rust authority=matched\n", result.ABIMajor, result.Operations)
}
