package diagnostics

import (
	"fmt"
	"net"
	"net/url"
	"regexp"
	"sort"
	"strings"
)

const maxNativeMessageBytes = 1 << 20

var chromeExtensionIDPattern = regexp.MustCompile(`^[a-p]{32}$`)

type BrowserProxyHandoffPlanRequest struct {
	ProfileID           string   `json:"profile_id"`
	ProxyURL            string   `json:"proxy_url"`
	Permissions         []string `json:"permissions"`
	NativeMessageBytes  int      `json:"native_message_bytes"`
	NativeHostInstalled bool     `json:"native_host_installed"`
	Offline             bool     `json:"offline,omitempty"`
	BrowserFamily       string   `json:"browser_family,omitempty"`
	ExtensionID         string   `json:"extension_id,omitempty"`
}

type BrowserNativeHostManifestPlan struct {
	Name              string   `json:"name"`
	Description       string   `json:"description"`
	AllowedOrigins    []string `json:"allowed_origins,omitempty"`
	AllowedExtensions []string `json:"allowed_extensions,omitempty"`
}

type BrowserProxyHandoffPlan struct {
	State               string                        `json:"state"`
	ProfileID           string                        `json:"profile_id"`
	BrowserFamily       string                        `json:"browser_family"`
	ExtensionID         string                        `json:"extension_id,omitempty"`
	ProxyHost           string                        `json:"proxy_host"`
	ProxyPort           string                        `json:"proxy_port"`
	MissingPermissions  []string                      `json:"missing_permissions"`
	MessageLimitBytes   int                           `json:"message_limit_bytes"`
	NativeHost          BrowserNativeHostManifestPlan `json:"native_host"`
	NativeCommands      []string                      `json:"native_commands"`
	ProxyBypass         []string                      `json:"proxy_bypass"`
	ReconnectBackoffMS  []int                         `json:"reconnect_backoff_ms"`
	RegistersHost       bool                          `json:"registers_host"`
	ChangesBrowserProxy bool                          `json:"changes_browser_proxy"`
	Invariants          []string                      `json:"invariants"`
}

func BuildBrowserProxyHandoffPlan(req BrowserProxyHandoffPlanRequest) (BrowserProxyHandoffPlan, error) {
	profile := strings.TrimSpace(req.ProfileID)
	if profile == "" || len(profile) > 128 {
		return BrowserProxyHandoffPlan{}, fmt.Errorf("browser profile_id must be 1..128 bytes")
	}
	if req.NativeMessageBytes < 0 || req.NativeMessageBytes > maxNativeMessageBytes {
		return BrowserProxyHandoffPlan{}, fmt.Errorf("native message exceeds %d-byte limit", maxNativeMessageBytes)
	}
	u, err := url.Parse(strings.TrimSpace(req.ProxyURL))
	if err != nil || (u.Scheme != "http" && u.Scheme != "socks5") {
		return BrowserProxyHandoffPlan{}, fmt.Errorf("proxy_url must be http:// or socks5://")
	}
	if u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return BrowserProxyHandoffPlan{}, fmt.Errorf("proxy_url must contain only scheme, loopback host, and explicit port")
	}
	host := u.Hostname()
	port := u.Port()
	if host == "" || port == "" {
		return BrowserProxyHandoffPlan{}, fmt.Errorf("proxy_url requires explicit loopback host and port")
	}
	ip := net.ParseIP(host)
	if !(strings.EqualFold(host, "localhost") || (ip != nil && ip.IsLoopback())) {
		return BrowserProxyHandoffPlan{}, fmt.Errorf("browser native proxy destination must be loopback-only")
	}

	browser := strings.ToLower(strings.TrimSpace(req.BrowserFamily))
	if browser == "" {
		browser = "generic"
	}
	if browser != "generic" && browser != "chrome" && browser != "firefox" {
		return BrowserProxyHandoffPlan{}, fmt.Errorf("browser_family must be generic, chrome, or firefox")
	}
	extensionID := strings.TrimSpace(req.ExtensionID)
	identityComplete := true
	manifest := BrowserNativeHostManifestPlan{Name: "com.luminet.browser", Description: "LumiNet browser companion native messaging host"}
	switch browser {
	case "chrome":
		if extensionID == "" {
			identityComplete = false
		} else if !chromeExtensionIDPattern.MatchString(extensionID) {
			return BrowserProxyHandoffPlan{}, fmt.Errorf("chrome extension_id must be 32 characters in the a-p alphabet")
		} else {
			manifest.AllowedOrigins = []string{"chrome-extension://" + extensionID + "/"}
		}
	case "firefox":
		if extensionID == "" {
			identityComplete = false
		} else if !validFirefoxExtensionID(extensionID) {
			return BrowserProxyHandoffPlan{}, fmt.Errorf("firefox extension_id must be a bounded add-on ID without whitespace or path separators")
		} else {
			manifest.AllowedExtensions = []string{extensionID}
		}
	}

	required := []string{"nativeMessaging", "proxy", "storage"}
	have := map[string]bool{}
	for _, p := range req.Permissions {
		have[strings.TrimSpace(p)] = true
	}
	var missing []string
	for _, p := range required {
		if !have[p] {
			missing = append(missing, p)
		}
	}
	sort.Strings(missing)
	state := "ready"
	if !req.NativeHostInstalled {
		state = "install-required"
	} else if !identityComplete {
		state = "identity-incomplete"
	} else if req.Offline {
		state = "offline"
	} else if len(missing) > 0 {
		state = "permission-incomplete"
	}
	return BrowserProxyHandoffPlan{
		State:              state,
		ProfileID:          profile,
		BrowserFamily:      browser,
		ExtensionID:        extensionID,
		ProxyHost:          host,
		ProxyPort:          port,
		MissingPermissions: missing,
		MessageLimitBytes:  maxNativeMessageBytes,
		NativeHost:         manifest,
		NativeCommands:     []string{"init", "get-status", "up", "down"},
		ProxyBypass:        []string{"localhost", "127.0.0.0/8", "::1"},
		ReconnectBackoffMS: []int{1000, 2000, 4000, 8000},
		Invariants: []string{
			"proxy ownership is isolated to the declared browser profile",
			"native messaging payloads are bounded to one megabyte",
			"the browser proxy destination is loopback-only",
			"browser-specific native-host identity is explicit before a ready handoff",
			"native command vocabulary is bounded to init, get-status, up, and down",
			"reconnect advice is bounded exponential backoff and does not create an autonomous retry loop",
			"native-host installation, identity-incomplete, offline, permission-incomplete, and ready states remain distinct",
			"the planner registers no native host and changes no browser proxy setting",
		},
	}, nil
}

func validFirefoxExtensionID(value string) bool {
	if len(value) > 128 || strings.ContainsAny(value, " \t\r\n/\\") {
		return false
	}
	return strings.Contains(value, "@") || (strings.HasPrefix(value, "{") && strings.HasSuffix(value, "}"))
}
