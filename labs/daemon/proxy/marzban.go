// Package proxy implements outbound protocols and obfuscation mechanisms.
// Ported from: Marzban
// Target path: server/internal/proxy/marzban.go

package proxy

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"sync"
)

// MarzbanUser represents a user profile within the Marzban panel.
type MarzbanUser struct {
	Username  string `json:"username"`
	IsAdmin   bool   `json:"is_admin"`
	UsedBytes int64  `json:"used_bytes"`
	MaxBytes  int64  `json:"max_bytes"`
}

// MarzbanManager coordinates user profiles, traffic accounting, and Xray core stats queries.
type MarzbanManager struct {
	mu    sync.RWMutex
	users map[string]*MarzbanUser
}

// NewMarzbanManager instantiates a new MarzbanManager.
func NewMarzbanManager() *MarzbanManager {
	return &MarzbanManager{
		users: make(map[string]*MarzbanUser),
	}
}

// 1. SyncUsersWithXray queries Xray's statistics server and updates local usage tracking.
func (m *MarzbanManager) SyncUsersWithXray(ctx context.Context, stats map[string]int64) {
	m.mu.Lock()
	defer m.mu.Unlock()

	for username, bytesUsed := range stats {
		if user, exists := m.users[username]; exists {
			user.UsedBytes += bytesUsed
			if user.MaxBytes > 0 && user.UsedBytes >= user.MaxBytes {
				log.Printf("MarzbanManager: User %s exceeded traffic limit", username)
			}
		}
	}
}

// 2. CreateUser registers a new user under Marzban management.
func (m *MarzbanManager) CreateUser(username string, maxBytes int64) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.users[username]; exists {
		return fmt.Errorf("user %s already exists", username)
	}

	m.users[username] = &MarzbanUser{
		Username:  username,
		IsAdmin:   false,
		UsedBytes: 0,
		MaxBytes:  maxBytes,
	}

	log.Printf("MarzbanManager: Created user profile %s (Limit: %d bytes)", username, maxBytes)
	return nil
}

// 3. DeleteUser removes a user from Marzban manager.
func (m *MarzbanManager) DeleteUser(username string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.users[username]; !exists {
		return fmt.Errorf("user %s not found", username)
	}

	delete(m.users, username)
	return nil
}

// 4. GetUser retrieves user by name.
func (m *MarzbanManager) GetUser(username string) (*MarzbanUser, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	user, exists := m.users[username]
	if !exists {
		return nil, fmt.Errorf("user %s not found", username)
	}
	return user, nil
}

// 5. GetUserCount returns total count of registered users.
func (m *MarzbanManager) GetUserCount() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.users)
}

// 6. ResetUserStats clears used bytes count.
func (m *MarzbanManager) ResetUserStats(username string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	user, exists := m.users[username]
	if !exists {
		return fmt.Errorf("user %s not found", username)
	}

	user.UsedBytes = 0
	return nil
}

// 7. GetUsers returns list of registered user names.
func (m *MarzbanManager) GetUsers() []string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var list []string
	for k := range m.users {
		list = append(list, k)
	}
	return list
}

// 8. ClearUsers resets users configurations database.
func (m *MarzbanManager) ClearUsers() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.users = make(map[string]*MarzbanUser)
}

// 9. AddAdminUser registers a new admin account.
func (m *MarzbanManager) AddAdminUser(username string, maxBytes int64) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.users[username]; exists {
		return fmt.Errorf("user %s already exists", username)
	}

	m.users[username] = &MarzbanUser{
		Username:  username,
		IsAdmin:   true,
		UsedBytes: 0,
		MaxBytes:  maxBytes,
	}
	return nil
}

// 10. IsUserAdmin checks user privilege configuration parameters.
func (m *MarzbanManager) IsUserAdmin(username string) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()

	user, exists := m.users[username]
	if !exists {
		return false
	}
	return user.IsAdmin
}

// 11. CheckExceededUsers scans for users exceeding traffic limits.
func (m *MarzbanManager) CheckExceededUsers() []string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var list []string
	for k, u := range m.users {
		if u.MaxBytes > 0 && u.UsedBytes >= u.MaxBytes {
			list = append(list, k)
		}
	}
	return list
}

// 12. ExtendUserLimitBytes adds byte limit quotas.
func (m *MarzbanManager) ExtendUserLimitBytes(username string, delta int64) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	user, exists := m.users[username]
	if !exists {
		return fmt.Errorf("user %s not found", username)
	}

	user.MaxBytes += delta
	return nil
}

// 13. SetUserStatus is a diagnostic placeholder.
func (m *MarzbanManager) SetUserStatus(username string, enabled bool) {
	// Diagnostic stub
}

// 14. ExportUsersJSON saves users database to JSON configurations.
func (m *MarzbanManager) ExportUsersJSON(filePath string) error {
	m.mu.RLock()
	defer m.mu.RUnlock()

	data, err := json.MarshalIndent(m.users, "", "  ")
	if err != nil {
		return err
	}
	return ioutil.WriteFile(filePath, data, 0644)
}

// 15. ImportUsersJSON loads users database from JSON configurations.
func (m *MarzbanManager) ImportUsersJSON(filePath string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	data, err := ioutil.ReadFile(filePath)
	if err != nil {
		return err
	}

	var list map[string]*MarzbanUser
	if err := json.Unmarshal(data, &list); err != nil {
		return err
	}

	m.users = list
	return nil
}
