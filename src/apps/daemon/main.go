// Package main is the entry point for the LumiNet server application.
// It delegates all command handling to the cmd package via cobra.
package main

import (
	"github.com/maybeknott/luminet/cmd"
	"github.com/maybeknott/luminet/controlui"
)

func main() {
	cmd.WebDist = controlui.Dist()
	cmd.Execute()
}
