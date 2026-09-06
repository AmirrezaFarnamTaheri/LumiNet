// Package captcha — stub for builds without the captcha tag.
//
// This file is compiled when the "captcha" build tag is NOT set.
// It provides the Solver interface definition and a disabled stub so
// callers can type-check without needing the real implementation.

//go:build !captcha

package captcha

import (
	"context"
	"errors"
)

var ErrPluginDisabled = errors.New("captcha: plugin not enabled (rebuild with -tags captcha)")

// Solver is the 2Captcha plugin interface (stub declarations only).
type Solver interface {
	SolveHCaptcha(ctx context.Context, siteKey, pageURL string) (string, error)
	SolveRecaptchaV2(ctx context.Context, siteKey, pageURL string) (string, error)
}

// DisabledPlugin is a Solver that always returns ErrPluginDisabled.
type DisabledPlugin struct{}

func NewPlugin(_ string) *DisabledPlugin { return &DisabledPlugin{} }

func (d *DisabledPlugin) SolveHCaptcha(_ context.Context, _, _ string) (string, error) {
	return "", ErrPluginDisabled
}
func (d *DisabledPlugin) SolveRecaptchaV2(_ context.Context, _, _ string) (string, error) {
	return "", ErrPluginDisabled
}
