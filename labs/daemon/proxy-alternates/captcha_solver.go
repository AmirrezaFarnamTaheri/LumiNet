package proxy

import "github.com/maybeknott/luminet/internal/captcha"

type CaptchaSolver = captcha.CaptchaSolver

var NewCaptchaSolver = captcha.NewCaptchaSolver
var ExtractSiteKey = captcha.ExtractSiteKey
