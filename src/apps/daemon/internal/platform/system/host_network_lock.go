package system

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

type hostLockOwner struct {
	PID   int    `json:"pid"`
	Token string `json:"token"`
}

type hostNetworkLock struct {
	dir   string
	owner hostLockOwner
}

func acquireHostNetworkLock(stateDir string) (*hostNetworkLock, error) {
	lockDir := filepath.Join(stateDir, ".host-network.lock")
	owner := hostLockOwner{PID: os.Getpid(), Token: randomHostLockToken()}
	for attempt := 0; attempt < 4; attempt++ {
		if err := os.Mkdir(lockDir, 0o700); err == nil {
			data, _ := json.Marshal(owner)
			if err := os.WriteFile(filepath.Join(lockDir, "owner.json"), data, 0o600); err != nil {
				_ = os.RemoveAll(lockDir)
				return nil, fmt.Errorf("write host-network lock owner: %w", err)
			}
			return &hostNetworkLock{dir: lockDir, owner: owner}, nil
		} else if !os.IsExist(err) {
			return nil, fmt.Errorf("acquire host-network lock: %w", err)
		}

		data, err := os.ReadFile(filepath.Join(lockDir, "owner.json"))
		if err != nil {
			return nil, fmt.Errorf("host-network lock exists without readable owner: %w", err)
		}
		var existing hostLockOwner
		if err := json.Unmarshal(data, &existing); err != nil || existing.PID <= 0 || existing.Token == "" {
			return nil, fmt.Errorf("host-network lock has invalid owner metadata")
		}
		if hostProcessAlive(existing.PID) {
			return nil, fmt.Errorf("host-network mutation already owned by pid %d", existing.PID)
		}

		// Rename the stale lock before deleting it so a concurrently-created new
		// lock at the canonical path can never be removed by this process.
		stale := lockDir + ".stale-" + owner.Token
		if err := os.Rename(lockDir, stale); err != nil {
			continue
		}
		_ = os.RemoveAll(stale)
	}
	return nil, fmt.Errorf("could not acquire host-network mutation lock")
}

func (l *hostNetworkLock) Release() error {
	if l == nil {
		return nil
	}
	data, err := os.ReadFile(filepath.Join(l.dir, "owner.json"))
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	var current hostLockOwner
	if err := json.Unmarshal(data, &current); err != nil {
		return err
	}
	if current.PID != l.owner.PID || current.Token != l.owner.Token {
		return fmt.Errorf("host-network lock ownership changed before release")
	}
	return os.RemoveAll(l.dir)
}

func randomHostLockToken() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return fmt.Sprintf("%d", os.Getpid())
	}
	return hex.EncodeToString(b[:])
}
