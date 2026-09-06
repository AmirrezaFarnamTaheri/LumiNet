package main

import (
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	controlsession "github.com/maybeknott/luminet/contracts/session"
	"github.com/maybeknott/luminet/controlui"
	"github.com/wailsapp/wails/v3/pkg/application"
)

type AppBridge struct {
	sessionPath string
}

func newAppBridge() *AppBridge {
	return &AppBridge{sessionPath: defaultSessionPath()}
}

type SessionConfig struct {
	APIURL string `json:"api_url"`
	APIKey string `json:"api_key"`
}

const defaultAPIURL = "http://127.0.0.1:8470"

func defaultSessionPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".luminet", "session.json")
}

func normalizeAPIURL(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		raw = defaultAPIURL
	}
	return controlsession.NormalizeAPIURL(raw)
}

func loadSessionConfig(sessionPath string, lookupEnv func(string) (string, bool)) (SessionConfig, error) {
	cfg := SessionConfig{APIURL: defaultAPIURL}
	if sessionPath != "" {
		discovered, err := controlsession.ReadFile(sessionPath)
		switch {
		case err == nil:
			cfg.APIURL = discovered.APIURL
			cfg.APIKey = discovered.APIKey
		case errors.Is(err, os.ErrNotExist):
			// No local daemon discovery file; environment/defaults may still apply.
		default:
			return SessionConfig{}, fmt.Errorf("read session config: %w", err)
		}
	}

	if value, ok := lookupEnv("LUMINET_API_URL"); ok && strings.TrimSpace(value) != "" {
		cfg.APIURL = value
	}
	if value, ok := lookupEnv("LUMINET_API_KEY"); ok {
		cfg.APIKey = value
	}
	normalizedURL, err := normalizeAPIURL(cfg.APIURL)
	if err != nil {
		return SessionConfig{}, err
	}
	cfg.APIURL = normalizedURL
	return cfg, nil
}

func (b *AppBridge) GetSessionConfig() (SessionConfig, error) {
	return loadSessionConfig(b.sessionPath, os.LookupEnv)
}

func main() {
	bridge := newAppBridge()
	assets := controlui.Dist()

	app := application.New(application.Options{
		Name:        "LumiNet Control Console",
		Description: "Local control panel for proxy, routing and diagnostics",
		Services: []application.Service{
			application.NewService(bridge),
		},
		Assets: application.AssetOptions{
			Handler: application.AssetFileServerFS(assets),
		},
	})

	app.Window.NewWithOptions(application.WebviewWindowOptions{
		Title:  "LumiNet Cockpit",
		Width:  1280,
		Height: 800,
		URL:    "/",
	})

	if err := app.Run(); err != nil {
		log.Fatal(err)
	}
}
