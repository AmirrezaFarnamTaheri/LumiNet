package session

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const (
	CurrentVersion    = 1
	maxSessionBytes   = 64 << 10
	mutationLockWait  = 5 * time.Second
	mutationLockStale = 30 * time.Second
	mutationLockPoll  = 10 * time.Millisecond
)

type Descriptor struct {
	Version    int    `json:"version"`
	InstanceID string `json:"instance_id"`
	APIURL     string `json:"api_url"`
	APIKey     string `json:"api_key,omitempty"`
}

type wireDescriptor struct {
	Version    *int            `json:"version"`
	InstanceID string          `json:"instance_id"`
	APIURL     string          `json:"api_url"`
	APIKey     string          `json:"api_key"`
	Port       json.RawMessage `json:"port"`
}

func NormalizeAPIURL(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", errors.New("API URL is required")
	}
	parsed, err := url.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("parse API URL: %w", err)
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return "", errors.New("API URL scheme must be http or https")
	}
	if parsed.Host == "" || parsed.Hostname() == "" {
		return "", errors.New("API URL must include a host")
	}
	if parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return "", errors.New("API URL must not include credentials, query parameters, or fragments")
	}
	parsed.Path = strings.TrimRight(parsed.Path, "/")
	return strings.TrimRight(parsed.String(), "/"), nil
}

func Parse(data []byte) (Descriptor, error) {
	if len(data) == 0 || len(data) > maxSessionBytes {
		return Descriptor{}, errors.New("session descriptor has invalid size")
	}
	var wire wireDescriptor
	decoder := json.NewDecoder(bytes.NewReader(data))
	if err := decoder.Decode(&wire); err != nil {
		return Descriptor{}, fmt.Errorf("decode session descriptor: %w", err)
	}
	if err := ensureJSONEOF(decoder); err != nil {
		return Descriptor{}, err
	}

	apiURL := strings.TrimSpace(wire.APIURL)
	if apiURL == "" && len(wire.Port) != 0 && string(wire.Port) != "null" {
		port, err := parsePort(wire.Port)
		if err != nil {
			return Descriptor{}, err
		}
		apiURL = "http://127.0.0.1:" + strconv.Itoa(port)
	}
	normalized, err := NormalizeAPIURL(apiURL)
	if err != nil {
		return Descriptor{}, err
	}
	if !isLoopbackURL(normalized) {
		return Descriptor{}, errors.New("session discovery endpoint must be loopback")
	}

	d := Descriptor{APIURL: normalized, APIKey: wire.APIKey, InstanceID: strings.TrimSpace(wire.InstanceID)}
	if wire.Version == nil {
		return d, nil
	}
	if *wire.Version != CurrentVersion {
		return Descriptor{}, fmt.Errorf("unsupported session descriptor version %d", *wire.Version)
	}
	d.Version = *wire.Version
	if d.InstanceID == "" {
		return Descriptor{}, errors.New("canonical session descriptor requires instance_id")
	}
	return d, nil
}

func ReadFile(path string) (Descriptor, error) {
	before, err := os.Lstat(path)
	if err != nil {
		return Descriptor{}, fmt.Errorf("stat session descriptor: %w", err)
	}
	if before.Mode()&os.ModeSymlink != 0 {
		return Descriptor{}, errors.New("session descriptor must not be a symlink")
	}
	if !before.Mode().IsRegular() {
		return Descriptor{}, errors.New("session descriptor must be a regular file")
	}
	if before.Size() > maxSessionBytes {
		return Descriptor{}, errors.New("session descriptor is too large")
	}

	f, err := os.Open(path)
	if err != nil {
		return Descriptor{}, fmt.Errorf("open session descriptor: %w", err)
	}
	defer f.Close()
	after, err := f.Stat()
	if err != nil {
		return Descriptor{}, fmt.Errorf("stat opened session descriptor: %w", err)
	}
	if !os.SameFile(before, after) {
		return Descriptor{}, errors.New("session descriptor changed while opening")
	}
	data, err := io.ReadAll(io.LimitReader(f, maxSessionBytes+1))
	if err != nil {
		return Descriptor{}, fmt.Errorf("read session descriptor: %w", err)
	}
	if len(data) > maxSessionBytes {
		return Descriptor{}, errors.New("session descriptor is too large")
	}
	return Parse(data)
}

func WriteFileAtomic(path string, d Descriptor) error {
	if d.Version != CurrentVersion {
		return fmt.Errorf("canonical session descriptor version must be %d", CurrentVersion)
	}
	if strings.TrimSpace(d.InstanceID) == "" {
		return errors.New("canonical session descriptor requires instance_id")
	}
	normalized, err := NormalizeAPIURL(d.APIURL)
	if err != nil {
		return err
	}
	if !isLoopbackURL(normalized) {
		return errors.New("session discovery endpoint must be loopback")
	}
	d.APIURL = normalized
	d.InstanceID = strings.TrimSpace(d.InstanceID)

	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create session directory: %w", err)
	}
	return withMutationLock(path, func() error {
		return writeFileAtomicUnlocked(path, dir, d)
	})
}

func writeFileAtomicUnlocked(path, dir string, d Descriptor) error {
	tmp, err := os.CreateTemp(dir, ".session-*.tmp")
	if err != nil {
		return fmt.Errorf("create temporary session descriptor: %w", err)
	}
	tmpPath := tmp.Name()
	keep := false
	defer func() {
		_ = tmp.Close()
		if !keep {
			_ = os.Remove(tmpPath)
		}
	}()
	if err := tmp.Chmod(0o600); err != nil {
		return fmt.Errorf("secure temporary session descriptor: %w", err)
	}
	encoder := json.NewEncoder(tmp)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(d); err != nil {
		return fmt.Errorf("encode session descriptor: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		return fmt.Errorf("sync session descriptor: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close session descriptor: %w", err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return fmt.Errorf("publish session descriptor: %w", err)
	}
	keep = true
	if err := os.Chmod(path, 0o600); err != nil {
		return fmt.Errorf("secure published session descriptor: %w", err)
	}
	return nil
}

func RemoveIfOwned(path, instanceID string) error {
	instanceID = strings.TrimSpace(instanceID)
	if instanceID == "" {
		return errors.New("instance_id is required for session cleanup")
	}
	if _, err := os.Lstat(path); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("stat session descriptor before cleanup: %w", err)
	}
	return withMutationLock(path, func() error {
		d, err := ReadFile(path)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				return nil
			}
			return err
		}
		if d.Version != CurrentVersion || d.InstanceID != instanceID {
			return nil
		}
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("remove owned session descriptor: %w", err)
		}
		return nil
	})
}

func withMutationLock(path string, fn func() error) error {
	lockPath := path + ".lock"
	deadline := time.Now().Add(mutationLockWait)
	for {
		err := os.Mkdir(lockPath, 0o700)
		if err == nil {
			defer func() { _ = os.Remove(lockPath) }()
			return fn()
		}
		if !errors.Is(err, os.ErrExist) {
			return fmt.Errorf("acquire session mutation lock: %w", err)
		}

		info, statErr := os.Lstat(lockPath)
		if statErr != nil {
			if errors.Is(statErr, os.ErrNotExist) {
				continue
			}
			return fmt.Errorf("inspect session mutation lock: %w", statErr)
		}
		if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return errors.New("session mutation lock must be a directory, not a symlink or file")
		}

		now := time.Now()
		if now.Sub(info.ModTime()) >= mutationLockStale {
			if removeErr := os.Remove(lockPath); removeErr == nil || errors.Is(removeErr, os.ErrNotExist) {
				continue
			}
		}
		if !now.Before(deadline) {
			return errors.New("timed out waiting for session mutation lock")
		}
		time.Sleep(mutationLockPoll)
	}
}

func parsePort(raw json.RawMessage) (int, error) {
	var text string
	if err := json.Unmarshal(raw, &text); err != nil {
		var number json.Number
		if errNumber := json.Unmarshal(raw, &number); errNumber != nil {
			return 0, errors.New("legacy session port must be a string or number")
		}
		text = number.String()
	}
	port, err := strconv.Atoi(strings.TrimSpace(text))
	if err != nil || port < 1 || port > 65535 {
		return 0, errors.New("legacy session port must be between 1 and 65535")
	}
	return port, nil
}

func ensureJSONEOF(decoder *json.Decoder) error {
	var extra any
	if err := decoder.Decode(&extra); err == io.EOF {
		return nil
	} else if err != nil {
		return fmt.Errorf("decode trailing session data: %w", err)
	}
	return errors.New("session descriptor contains multiple JSON values")
}

func isLoopbackURL(raw string) bool {
	parsed, err := url.Parse(raw)
	if err != nil {
		return false
	}
	host := strings.TrimSuffix(strings.ToLower(parsed.Hostname()), ".")
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
