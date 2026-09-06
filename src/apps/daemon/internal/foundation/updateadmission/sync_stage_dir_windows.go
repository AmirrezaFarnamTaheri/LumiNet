//go:build windows

package updateadmission

// Windows does not expose the same portable directory-fsync contract through
// os.File. Staged file contents are flushed before os.Rename; keep this
// platform limitation explicit instead of pretending directory durability was
// verified.
func syncStageDirectory(string) error { return nil }
