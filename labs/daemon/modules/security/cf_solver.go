// Package security provides anti-bot solvers, stealth scraping, and secure credential handling for LumiNet.
// Ported from: Scrapling (Anti-Bot Scraper & Stealth Fingerprints)
// Target path: server/internal/security/cf_solver.go
package security

import (
	"fmt"
	"math/rand"
	"time"
)

// CloudflareSolver implements anti-bot fingerprint rotation and stealth browser script injection.
type CloudflareSolver struct {
	userAgents []string
}

// NewCloudflareSolver creates a new CloudflareSolver instance.
func NewCloudflareSolver() *CloudflareSolver {
	return &CloudflareSolver{
		userAgents: []string{
			"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
			"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
			"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
		},
	}
}

// GetRandomUserAgent returns a clean, non-headless browser User-Agent string.
func (s *CloudflareSolver) GetRandomUserAgent() string {
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	return s.userAgents[r.Intn(len(s.userAgents))]
}

// GenerateStealthInjectionJS creates a Javascript script designed to be injected into
// headless browser instances (Playwright/Chrome) to spoof navigator, canvas, and WebGL
// properties, evading bot detection engines like Cloudflare or Akamai.
func (s *CloudflareSolver) GenerateStealthInjectionJS() string {
	return fmt.Sprintf(`
		// 1. Spoof Navigator parameters
		Object.defineProperty(navigator, 'webdriver', { get: () => undefined });
		Object.defineProperty(navigator, 'languages', { get: () => ['en-US', 'en'] });
		Object.defineProperty(navigator, 'hardwareConcurrency', { get: () => 8 });
		Object.defineProperty(navigator, 'plugins', { get: () => [1, 2, 3, 4, 5] });

		// 2. Hide Canvas fingerprinting attempts
		const originalGetContext = HTMLCanvasElement.prototype.getContext;
		HTMLCanvasElement.prototype.getContext = function (type, contextAttributes) {
			if (type === 'webgl' || type === 'experimental-webgl') {
				// Block WebGL parameter extraction
				return null;
			}
			return originalGetContext.apply(this, [type, contextAttributes]);
		};

		// 3. Block WebRTC local IP leakage
		if (window.RTCPeerConnection) {
			const originalCreateOffer = RTCPeerConnection.prototype.createOffer;
			RTCPeerConnection.prototype.createOffer = function (...args) {
				return Promise.reject(new Error("WebRTC blocked for privacy"));
			};
		}
	`)
}
