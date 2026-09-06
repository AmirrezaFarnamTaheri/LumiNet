package proxy

import (
	"strings"
	"sync"
)

// AndroidVPNExclusionManager manages package-based routing exclusions for Android VPN service.
type AndroidVPNExclusionManager struct {
	mu          sync.RWMutex
	excludeList map[string]bool
}

// NewAndroidVPNExclusionManager creates a new exclude manager.
func NewAndroidVPNExclusionManager() *AndroidVPNExclusionManager {
	return &AndroidVPNExclusionManager{
		excludeList: make(map[string]bool),
	}
}

// SetExcludedPackages updates the package names to exclude from VPN routing.
func (m *AndroidVPNExclusionManager) SetExcludedPackages(packages []string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.excludeList = make(map[string]bool)
	for _, pkg := range packages {
		pkg = strings.TrimSpace(pkg)
		if pkg != "" {
			m.excludeList[pkg] = true
		}
	}
}

// IsPackageExcluded checks if the package should bypass VPN routing.
func (m *AndroidVPNExclusionManager) IsPackageExcluded(packageName string) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()

	return m.excludeList[packageName]
}

// GetExcludeList returns all currently excluded packages as a slice.
func (m *AndroidVPNExclusionManager) GetExcludeList() []string {
	m.mu.RLock()
	defer m.mu.RUnlock()

	list := make([]string, 0, len(m.excludeList))
	for pkg := range m.excludeList {
		list = append(list, pkg)
	}
	return list
}
