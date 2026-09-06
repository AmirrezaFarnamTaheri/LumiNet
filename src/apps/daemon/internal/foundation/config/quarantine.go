package config

import (
	"fmt"
	"os"
)

// quarantineCorruptConfig atomically moves a structurally invalid active
// configuration out of the authoritative path without overwriting earlier
// forensic evidence. The caller still fails closed; this helper only preserves
// damaged bytes and prevents a later default write from destroying them.
const maxCorruptConfigQuarantines = 1024

func quarantineCorruptConfig(path string) (string, error) {
	if path == "" {
		return "", fmt.Errorf("config path is empty")
	}
	target := ""
	for suffix := 0; suffix < maxCorruptConfigQuarantines; suffix++ {
		candidate := path + ".corrupt"
		if suffix > 0 {
			candidate = fmt.Sprintf("%s.corrupt.%d", path, suffix)
		}
		_, err := os.Lstat(candidate)
		if os.IsNotExist(err) {
			target = candidate
			break
		}
		if err != nil {
			return "", fmt.Errorf("inspect quarantine target: %w", err)
		}
	}
	if target == "" {
		return "", fmt.Errorf("corrupt config quarantine exhausted %d names", maxCorruptConfigQuarantines)
	}
	if err := os.Rename(path, target); err != nil {
		return "", fmt.Errorf("move corrupt config: %w", err)
	}
	return target, nil
}
