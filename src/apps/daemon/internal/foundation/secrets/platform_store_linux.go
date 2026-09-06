//go:build linux

package secrets

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"sync"

	"github.com/godbus/dbus/v5"
)

const (
	secretServiceName = "org.freedesktop.secrets"
	secretServicePath = dbus.ObjectPath("/org/freedesktop/secrets")
	defaultCollection = dbus.ObjectPath("/org/freedesktop/secrets/aliases/default")
	secretServiceApp  = "luminet"
)

// SecretServiceStore stores secrets in the login-session Secret Service. It
// intentionally never falls back to a file store: a missing or locked service
// is an actionable production configuration error, not permission to weaken
// the secret boundary.
type SecretServiceStore struct {
	mu   sync.Mutex
	conn *dbus.Conn
}

type secretServiceSecret struct {
	Session     dbus.ObjectPath
	Parameters  []byte
	Value       []byte
	ContentType string
}

func newPlatformStore() (NativeStore, error) {
	conn, err := dbus.ConnectSessionBus()
	if err != nil {
		return nil, fmt.Errorf("%w: connect to the user session bus: %v", ErrNativeStoreUnavailable, err)
	}
	store := &SecretServiceStore{conn: conn}
	if err := store.probe(context.Background()); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("%w: %v", ErrNativeStoreUnavailable, err)
	}
	return store, nil
}

func (*SecretServiceStore) ProviderName() string { return "secretservice" }
func (*SecretServiceStore) Native() bool         { return true }

func (s *SecretServiceStore) Put(ctx context.Context, ref string, value []byte) error {
	if err := validNativeRef(ref); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	session, err := s.openPlainSession(ctx)
	if err != nil {
		return err
	}
	defer s.closeSession(session)
	properties := map[string]dbus.Variant{
		"org.freedesktop.Secret.Item.Label":      dbus.MakeVariant("LumiNet " + ref),
		"org.freedesktop.Secret.Item.Attributes": dbus.MakeVariant(s.attributes(ref)),
	}
	secret := secretServiceSecret{Session: session, Value: append([]byte(nil), value...), ContentType: "application/octet-stream"}
	var item, prompt dbus.ObjectPath
	call := s.conn.Object(secretServiceName, defaultCollection).CallWithContext(ctx, "org.freedesktop.Secret.Collection.CreateItem", 0, properties, secret, true)
	if err := call.Store(&item, &prompt); err != nil {
		return fmt.Errorf("secrets/secretservice: store %q: %w", ref, err)
	}
	return noInteractivePrompt("store", prompt)
}

func (s *SecretServiceStore) Get(ctx context.Context, ref string) ([]byte, error) {
	item, err := s.findItem(ctx, ref)
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	session, err := s.openPlainSession(ctx)
	if err != nil {
		return nil, err
	}
	defer s.closeSession(session)
	var secret secretServiceSecret
	call := s.conn.Object(secretServiceName, item).CallWithContext(ctx, "org.freedesktop.Secret.Item.GetSecret", 0, session)
	if err := call.Store(&secret); err != nil {
		return nil, fmt.Errorf("secrets/secretservice: retrieve %q: %w", ref, err)
	}
	return append([]byte(nil), secret.Value...), nil
}

func (s *SecretServiceStore) Delete(ctx context.Context, ref string) error {
	item, err := s.findItem(ctx, ref)
	if err != nil {
		if errors.As(err, new(ErrNotFound)) {
			return nil
		}
		return err
	}
	var prompt dbus.ObjectPath
	call := s.conn.Object(secretServiceName, item).CallWithContext(ctx, "org.freedesktop.Secret.Item.Delete", 0)
	if err := call.Store(&prompt); err != nil {
		return fmt.Errorf("secrets/secretservice: delete %q: %w", ref, err)
	}
	return noInteractivePrompt("delete", prompt)
}

func (s *SecretServiceStore) List(ctx context.Context) ([]string, error) {
	unlocked, locked, err := s.search(ctx, map[string]string{"application": secretServiceApp})
	if err != nil {
		return nil, err
	}
	if len(locked) != 0 {
		return nil, fmt.Errorf("secrets/secretservice: collection is locked; interactive unlocking is not supported")
	}
	refs := make([]string, 0, len(unlocked))
	for _, item := range unlocked {
		var attrs map[string]string
		call := s.conn.Object(secretServiceName, item).CallWithContext(ctx, "org.freedesktop.DBus.Properties.Get", 0, "org.freedesktop.Secret.Item", "Attributes")
		var raw dbus.Variant
		if err := call.Store(&raw); err != nil {
			return nil, fmt.Errorf("secrets/secretservice: inspect item: %w", err)
		}
		attrs, _ = raw.Value().(map[string]string)
		if ref := attrs["luminet.ref"]; ref != "" {
			refs = append(refs, ref)
		}
	}
	sort.Strings(refs)
	return refs, nil
}

func (s *SecretServiceStore) probe(ctx context.Context) error {
	_, _, err := s.search(ctx, map[string]string{"application": secretServiceApp})
	return err
}

func (s *SecretServiceStore) findItem(ctx context.Context, ref string) (dbus.ObjectPath, error) {
	if err := validNativeRef(ref); err != nil {
		return "", err
	}
	unlocked, locked, err := s.search(ctx, s.attributes(ref))
	if err != nil {
		return "", err
	}
	if len(unlocked) != 0 {
		return unlocked[0], nil
	}
	if len(locked) != 0 {
		return "", fmt.Errorf("secrets/secretservice: secret %q is locked; interactive unlocking is not supported", ref)
	}
	return "", ErrNotFound{Ref: ref}
}

func (s *SecretServiceStore) search(ctx context.Context, attrs map[string]string) ([]dbus.ObjectPath, []dbus.ObjectPath, error) {
	var unlocked, locked []dbus.ObjectPath
	call := s.conn.Object(secretServiceName, secretServicePath).CallWithContext(ctx, "org.freedesktop.Secret.Service.SearchItems", 0, attrs)
	if err := call.Store(&unlocked, &locked); err != nil {
		return nil, nil, fmt.Errorf("secrets/secretservice: search: %w", err)
	}
	return unlocked, locked, nil
}

func (s *SecretServiceStore) openPlainSession(ctx context.Context) (dbus.ObjectPath, error) {
	var output dbus.Variant
	var session dbus.ObjectPath
	call := s.conn.Object(secretServiceName, secretServicePath).CallWithContext(ctx, "org.freedesktop.Secret.Service.OpenSession", 0, "plain", dbus.MakeVariant(""))
	if err := call.Store(&output, &session); err != nil {
		return "", fmt.Errorf("secrets/secretservice: open session: %w", err)
	}
	return session, nil
}

func (s *SecretServiceStore) closeSession(session dbus.ObjectPath) {
	_ = s.conn.Object(secretServiceName, session).Call("org.freedesktop.Secret.Session.Close", 0).Err
}

func (*SecretServiceStore) attributes(ref string) map[string]string {
	return map[string]string{"application": secretServiceApp, "luminet.ref": ref}
}

func noInteractivePrompt(operation string, prompt dbus.ObjectPath) error {
	if prompt == "/" {
		return nil
	}
	return fmt.Errorf("secrets/secretservice: %s requires interactive prompt %q", operation, prompt)
}
