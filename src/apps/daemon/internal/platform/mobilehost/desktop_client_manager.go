package mobilehost

import (
	"errors"
	"fmt"
)

type SystemProxyMode string

const (
	ProxyModeDirect SystemProxyMode = "direct"
	ProxyModePac    SystemProxyMode = "pac"
	ProxyModeGlobal SystemProxyMode = "global"
	ProxyModeManual SystemProxyMode = "manual"
)

type DesktopStatus struct {
	Mode          SystemProxyMode `json:"mode"`
	ActiveProfile string          `json:"active_profile"`
	HttpPort      uint16          `json:"http_port"`
	Socks5Port    uint16          `json:"socks5_port"`
	IsConnected   bool            `json:"is_connected"`
	PacURL        string          `json:"pac_url,omitempty"`
}

type DesktopClientManager struct {
	mode          SystemProxyMode
	activeProfile string
	httpPort      uint16
	socks5Port    uint16
	isConnected   bool
	pacURL        string
}

func NewDesktopClientManager(httpPort, socks5Port uint16) *DesktopClientManager {
	return &DesktopClientManager{
		mode:          ProxyModeDirect,
		activeProfile: "default",
		httpPort:      httpPort,
		socks5Port:    socks5Port,
		isConnected:   false,
	}
}

func (d *DesktopClientManager) SetProxyMode(mode SystemProxyMode, pacURL string) error {
	if mode == ProxyModePac && pacURL == "" && d.pacURL == "" {
		return errors.New("PAC mode requires a valid PAC URL")
	}
	d.mode = mode
	if pacURL != "" {
		d.pacURL = pacURL
	}
	return nil
}

func (d *DesktopClientManager) SwitchProfile(profile string) {
	d.activeProfile = profile
}

func (d *DesktopClientManager) SetConnected(connected bool) {
	d.isConnected = connected
}

func (d *DesktopClientManager) GetStatus() DesktopStatus {
	return DesktopStatus{
		Mode:          d.mode,
		ActiveProfile: d.activeProfile,
		HttpPort:      d.httpPort,
		Socks5Port:    d.socks5Port,
		IsConnected:   d.isConnected,
		PacURL:        d.pacURL,
	}
}

func (d *DesktopClientManager) HandleIPCCommand(cmd string, payload map[string]interface{}) (map[string]interface{}, error) {
	switch cmd {
	case "get_status":
		st := d.GetStatus()
		return map[string]interface{}{
			"mode":           st.Mode,
			"active_profile": st.ActiveProfile,
			"http_port":      st.HttpPort,
			"socks5_port":    st.Socks5Port,
			"is_connected":   st.IsConnected,
			"pac_url":        st.PacURL,
		}, nil
	case "set_mode":
		mStr, ok := payload["mode"].(string)
		if !ok {
			return nil, errors.New("missing mode string")
		}
		pURL, _ := payload["pac_url"].(string)
		if err := d.SetProxyMode(SystemProxyMode(mStr), pURL); err != nil {
			return nil, err
		}
		return map[string]interface{}{"success": true}, nil
	case "switch_profile":
		prof, ok := payload["profile"].(string)
		if !ok {
			return nil, errors.New("missing profile string")
		}
		d.SwitchProfile(prof)
		return map[string]interface{}{"success": true, "profile": prof}, nil
	default:
		return nil, fmt.Errorf("unknown IPC command: %s", cmd)
	}
}
