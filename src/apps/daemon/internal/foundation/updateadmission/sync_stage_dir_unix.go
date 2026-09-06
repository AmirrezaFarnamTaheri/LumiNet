//go:build !windows

package updateadmission

import "os"

// syncStageDirectory makes a published rename durable on filesystems that
// require the containing directory entry to be flushed separately from the
// file contents.
func syncStageDirectory(path string) error {
	dir, err := os.Open(path)
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}
