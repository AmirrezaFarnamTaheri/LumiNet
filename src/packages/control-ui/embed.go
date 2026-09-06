// Package controlui owns the single authored and embedded LumiNet control UI.
package controlui

import (
	"embed"
	"io/fs"
)

//go:embed all:dist
var content embed.FS

// Dist returns the embedded bundle rooted at dist/. In a source checkout this is
// a fail-closed bootstrap; CI/release frontend builds replace dist/ with the
// current production bundle before daemon/desktop packaging.
func Dist() fs.FS {
	root, err := fs.Sub(content, "dist")
	if err != nil {
		panic("control UI embed invariant violated: " + err.Error())
	}
	return root
}
