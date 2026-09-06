//go:build windows

package system

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"unsafe"

	"github.com/maybeknott/luminet/internal/util"
	"golang.org/x/sys/windows/registry"
)

var (
	modwininetw = syscall.NewLazyDLL("wininet.dll")
	procInternetSetOptionW = modwininetw.NewProc("InternetSetOptionW")
)

const (
	wininet_option_per_connection_option = 75
	wininet_option_settings_changed       = 39
	wininet_option_refresh                = 37

	wininet_per_conn_flags        = 1
	wininet_per_conn_proxy_server = 2
	wininet_per_conn_proxy_bypass = 3

	wininet_proxy_type_direct = 0x00000001
	wininet_proxy_type_proxy  = 0x00000002
)

type internetPerConnOptionList struct {
	dwSize        uint32
	szConnection  *uint16
	dwOptionCount uint32
	dwOptionError uint32
	options       uintptr
}

type internetPerConnOption struct {
	dwOption uint32
	value    internetPortUnion
}

type internetPortUnion struct {
	value uintptr
}

// SysProxyWinInet handles Windows system-wide proxy settings.
type SysProxyWinInet struct{}

// NewSysProxyWinInet creates a new SysProxyWinInet.
func NewSysProxyWinInet() *SysProxyWinInet {
	return &SysProxyWinInet{}
}

// SetSystemProxy configures the system-wide proxy using WinINet options.
func (s *SysProxyWinInet) SetSystemProxy(proxyServer string, bypass string) error {
	options := make([]internetPerConnOption, 3)
	
	options[0].dwOption = wininet_per_conn_flags
	options[0].value.value = uintptr(wininet_proxy_type_direct | wininet_proxy_type_proxy)

	options[1].dwOption = wininet_per_conn_proxy_server
	options[1].value.value = uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(proxyServer)))

	options[2].dwOption = wininet_per_conn_proxy_bypass
	options[2].value.value = uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(bypass)))

	list := internetPerConnOptionList{
		dwSize:        uint32(unsafe.Sizeof(internetPerConnOptionList{})),
		szConnection:  nil,
		dwOptionCount: 3,
		options:       uintptr(unsafe.Pointer(&options[0])),
	}

	r1, _, err := procInternetSetOptionW.Call(
		0,
		wininet_option_per_connection_option,
		uintptr(unsafe.Pointer(&list)),
		uintptr(list.dwSize),
	)
	if r1 == 0 {
		return s.fallbackRegistryProxy(proxyServer, bypass, err)
	}

	procInternetSetOptionW.Call(0, wininet_option_settings_changed, 0, 0)
	procInternetSetOptionW.Call(0, wininet_option_refresh, 0, 0)

	return nil
}

func (s *SysProxyWinInet) fallbackRegistryProxy(server string, bypass string, fallbackErr error) error {
	k, err := registry.OpenKey(registry.CURRENT_USER, `Software\Microsoft\Windows\CurrentVersion\Internet Settings`, registry.SET_VALUE)
	if err != nil {
		return fmt.Errorf("wininet option failed: %v (registry fallback open failed: %v)", fallbackErr, err)
	}
	defer k.Close()

	if err := k.SetDWordValue("ProxyEnable", 1); err != nil {
		return err
	}
	if err := k.SetStringValue("ProxyServer", server); err != nil {
		return err
	}
	if err := k.SetStringValue("ProxyOverride", bypass); err != nil {
		return err
	}

	procInternetSetOptionW.Call(0, wininet_option_settings_changed, 0, 0)
	procInternetSetOptionW.Call(0, wininet_option_refresh, 0, 0)

	return nil
}

// RefreshDialupConnections simulates RAS iteration.
func (s *SysProxyWinInet) RefreshDialupConnections() error {
	return nil
}

type sysproxyBackup struct {
	ProxyEnable   uint32 `json:"proxy_enable"`
	ProxyServer   string `json:"proxy_server"`
	ProxyOverride string `json:"proxy_override"`
	HasBackup     bool   `json:"has_backup"`
}

func getBackupFilePath() string {
	dir, err := util.AppDataDir()
	if err != nil {
		return ""
	}
	return filepath.Join(dir, "sysproxy_backup.json")
}

func backupSystemProxy() {
	filePath := getBackupFilePath()
	if filePath == "" {
		return
	}
	if _, err := os.Stat(filePath); err == nil {
		return
	}

	k, err := registry.OpenKey(registry.CURRENT_USER, `Software\Microsoft\Windows\CurrentVersion\Internet Settings`, registry.QUERY_VALUE)
	if err != nil {
		return
	}
	defer k.Close()

	var backup sysproxyBackup
	if val, _, err := k.GetIntegerValue("ProxyEnable"); err == nil {
		backup.ProxyEnable = uint32(val)
	}
	if val, _, err := k.GetStringValue("ProxyServer"); err == nil {
		backup.ProxyServer = val
	}
	if val, _, err := k.GetStringValue("ProxyOverride"); err == nil {
		backup.ProxyOverride = val
	}
	backup.HasBackup = true

	data, err := json.MarshalIndent(backup, "", "  ")
	if err == nil {
		_ = os.WriteFile(filePath, data, 0600)
	}
}

func restoreSystemProxy() error {
	filePath := getBackupFilePath()
	if filePath == "" {
		return nil
	}

	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil
	}

	var backup sysproxyBackup
	if err := json.Unmarshal(data, &backup); err != nil {
		return err
	}

	_ = os.Remove(filePath)

	k, err := registry.OpenKey(registry.CURRENT_USER, `Software\Microsoft\Windows\CurrentVersion\Internet Settings`, registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer k.Close()

	if backup.HasBackup {
		if err := k.SetDWordValue("ProxyEnable", uint32(backup.ProxyEnable)); err != nil {
			return err
		}
		if backup.ProxyServer != "" {
			if err := k.SetStringValue("ProxyServer", backup.ProxyServer); err != nil {
				return err
			}
		} else {
			_ = k.DeleteValue("ProxyServer")
		}
		if backup.ProxyOverride != "" {
			if err := k.SetStringValue("ProxyOverride", backup.ProxyOverride); err != nil {
				return err
			}
		} else {
			_ = k.DeleteValue("ProxyOverride")
		}
	} else {
		if err := k.SetDWordValue("ProxyEnable", 0); err != nil {
			return err
		}
	}

	procInternetSetOptionW.Call(0, wininet_option_settings_changed, 0, 0)
	procInternetSetOptionW.Call(0, wininet_option_refresh, 0, 0)
	return nil
}

// osSetProxy applies proxy settings on Windows.
func osSetProxy(cfg ProxyConfig) error {
	s := NewSysProxyWinInet()
	proxyAddr := cfg.HTTPProxy
	if proxyAddr == "" {
		proxyAddr = cfg.HTTPSProxy
	}
	if proxyAddr == "" {
		return osClearProxy()
	}
	backupSystemProxy()
	return s.SetSystemProxy(proxyAddr, cfg.NoProxy)
}

// osClearProxy removes the system proxy configuration.
func osClearProxy() error {
	if err := restoreSystemProxy(); err == nil {
		return nil
	}

	k, err := registry.OpenKey(registry.CURRENT_USER, `Software\Microsoft\Windows\CurrentVersion\Internet Settings`, registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer k.Close()

	if err := k.SetDWordValue("ProxyEnable", 0); err != nil {
		return err
	}

	procInternetSetOptionW.Call(0, wininet_option_settings_changed, 0, 0)
	procInternetSetOptionW.Call(0, wininet_option_refresh, 0, 0)
	return nil
}

// osGetProxy reads the current system proxy settings from the registry.
func osGetProxy() (*ProxyConfig, error) {
	k, err := registry.OpenKey(registry.CURRENT_USER, `Software\Microsoft\Windows\CurrentVersion\Internet Settings`, registry.QUERY_VALUE)
	if err != nil {
		return nil, err
	}
	defer k.Close()

	cfg := &ProxyConfig{}

	if server, _, err := k.GetStringValue("ProxyServer"); err == nil {
		cfg.HTTPProxy = server
	}

	if enabled, _, err := k.GetIntegerValue("ProxyEnable"); err == nil {
		cfg.Enabled = enabled == 1
	}

	return cfg, nil
}


