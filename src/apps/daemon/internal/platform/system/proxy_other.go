//go:build !windows && !linux && !darwin

package system

import (
	"context"
	"errors"
)

func SetSystemProxy(context.Context, *ProxySettings) error {
	return errors.New("system proxy configuration is not supported on this platform")
}
func GetSystemProxy(context.Context) (*ProxySettings, error) {
	return nil, errors.New("system proxy configuration is not supported on this platform")
}
func GetProxySettings(ctx context.Context) (*ProxySettings, error) { return GetSystemProxy(ctx) }
func SetProxySettings(ctx context.Context, settings ProxySettings) error {
	return SetSystemProxy(ctx, &settings)
}
func DisableSystemProxy(context.Context) error { return nil }
func DisableProxy(ctx context.Context) error   { return DisableSystemProxy(ctx) }
