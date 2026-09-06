//go:build ignore

// Standalone repository gate, invoked via `go run scripts/checks/check_go_target_selection.go`.
// The ignore tag keeps this file out of module-level `go build`/`go vet`/package
// resolution; explicitly listed files bypass build constraints, so the Makefile
// invocation above is unaffected.
package main

import (
	"fmt"
	"go/ast"
	"go/build"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
)

type target struct {
	goos, goarch string
	cgo          bool
}

func main() {
	targets := []target{
		{"linux", "amd64", true}, {"linux", "amd64", false},
		{"windows", "amd64", true}, {"windows", "amd64", false},
		{"darwin", "amd64", true}, {"darwin", "arm64", true}, {"darwin", "arm64", false},
	}
	dirs := []string{"src/apps/daemon/internal/platform/system", "src/apps/daemon/internal/runtime/proxy", "src/apps/daemon/cmd/watchdog"}
	errors := 0
	for _, t := range targets {
		for _, dir := range dirs {
			errors += checkDir(t, dir)
		}
	}
	fmt.Printf("go-target-selection targets=%d errors=%d\n", len(targets), errors)
	if errors != 0 {
		os.Exit(1)
	}
}

func checkDir(t target, dir string) int {
	ctxt := build.Default
	ctxt.GOOS, ctxt.GOARCH, ctxt.CgoEnabled = t.goos, t.goarch, t.cgo
	pkg, err := ctxt.ImportDir(dir, build.IgnoreVendor)
	if err != nil {
		if _, ok := err.(*build.NoGoError); ok {
			return 0
		}
		fmt.Printf("ERROR %s/%s cgo=%v %s: select: %v\n", t.goos, t.goarch, t.cgo, dir, err)
		return 1
	}
	files := append(append([]string{}, pkg.GoFiles...), pkg.CgoFiles...)
	sort.Strings(files)
	seen := map[string]string{}
	errCount := 0
	for _, name := range files {
		path := filepath.Join(dir, name)
		f, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
		if err != nil {
			fmt.Printf("ERROR %s: parse %v\n", path, err)
			errCount++
			continue
		}
		for _, decl := range f.Decls {
			switch d := decl.(type) {
			case *ast.FuncDecl:
				if d.Recv == nil && d.Name.Name != "init" {
					errCount += addDecl(seen, d.Name.Name, path, t)
				}
			case *ast.GenDecl:
				for _, spec := range d.Specs {
					switch s := spec.(type) {
					case *ast.TypeSpec:
						errCount += addDecl(seen, s.Name.Name, path, t)
					case *ast.ValueSpec:
						for _, n := range s.Names {
							errCount += addDecl(seen, n.Name, path, t)
						}
					}
				}
			}
		}
	}
	return errCount
}

func addDecl(seen map[string]string, name, path string, t target) int {
	if name == "_" {
		return 0
	}
	if prev, ok := seen[name]; ok {
		fmt.Printf("ERROR %s/%s cgo=%v duplicate %s: %s and %s\n", t.goos, t.goarch, t.cgo, name, prev, path)
		return 1
	}
	seen[name] = path
	return 0
}
