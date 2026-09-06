//go:build windows

package updateadmission

import "os"

// os.Rename cannot portably replace an existing file on Windows. Keep the
// platform-specific remove-and-rename fallback isolated here; callers still
// reject non-regular targets before reaching this helper.
func replacePublishedStagedFile(source, target string) error {
	if err := os.Remove(target); err != nil && !os.IsNotExist(err) {
		return err
	}
	return os.Rename(source, target)
}
