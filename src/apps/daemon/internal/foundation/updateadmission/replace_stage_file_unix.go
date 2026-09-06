//go:build !windows

package updateadmission

import "os"

// replacePublishedStagedFile uses rename-overwrite semantics on Unix so an
// existing verified staging path is never removed before its replacement is
// ready. Together with file fsync before rename and directory fsync after it,
// this avoids an avoidable crash window where the publication path is absent.
func replacePublishedStagedFile(source, target string) error {
	return os.Rename(source, target)
}
