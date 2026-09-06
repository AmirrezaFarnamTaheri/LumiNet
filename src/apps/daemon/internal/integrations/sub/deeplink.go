package sub

import (
	"errors"
	"fmt"
	"net/url"
	"strings"
	"unicode/utf8"
)

const (
	maxDeepLinkLength     = 4096
	maxDeepLinkNameLength = 96
)

// DeepLinkImport is a non-authoritative subscription import proposal parsed
// from a luminet://import URI. Parsing never fetches, persists, activates, or
// refreshes the referenced subscription; callers must surface the proposal for
// explicit operator confirmation through the canonical profile owner.
type DeepLinkImport struct {
	URL  string `json:"url"`
	Name string `json:"name"`
}

// ParseDeepLinkImport validates the narrow LumiNet subscription deep-link
// contract. Only luminet://import is accepted and the embedded subscription
// source must satisfy the same HTTPS/credential policy as managed profiles.
func ParseDeepLinkImport(raw string) (DeepLinkImport, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return DeepLinkImport{}, errors.New("deep link is required")
	}
	if len(raw) > maxDeepLinkLength {
		return DeepLinkImport{}, fmt.Errorf("deep link exceeds %d bytes", maxDeepLinkLength)
	}
	parsed, err := url.Parse(raw)
	if err != nil {
		return DeepLinkImport{}, fmt.Errorf("parse deep link: %w", err)
	}
	if !strings.EqualFold(parsed.Scheme, "luminet") || !strings.EqualFold(parsed.Host, "import") || parsed.Path != "" {
		return DeepLinkImport{}, errors.New("deep link must use luminet://import")
	}
	if parsed.Fragment != "" || parsed.User != nil {
		return DeepLinkImport{}, errors.New("deep link fragments and authority credentials are not allowed")
	}
	query := parsed.Query()
	if len(query) > 2 {
		return DeepLinkImport{}, errors.New("deep link contains unsupported parameters")
	}
	for key := range query {
		if key != "url" && key != "name" {
			return DeepLinkImport{}, fmt.Errorf("unsupported deep-link parameter %q", key)
		}
		if len(query[key]) != 1 {
			return DeepLinkImport{}, fmt.Errorf("deep-link parameter %q must appear exactly once", key)
		}
	}
	source := strings.TrimSpace(query.Get("url"))
	if source == "" {
		return DeepLinkImport{}, errors.New("deep link requires url")
	}
	if err := ValidateProfileSourceURL(source); err != nil {
		return DeepLinkImport{}, fmt.Errorf("subscription URL: %w", err)
	}
	sourceURL, err := url.Parse(source)
	if err != nil {
		return DeepLinkImport{}, fmt.Errorf("subscription URL: %w", err)
	}
	if sourceURL.User != nil {
		return DeepLinkImport{}, errors.New("subscription URL must not embed credentials")
	}
	name := strings.TrimSpace(query.Get("name"))
	if name == "" {
		name = sourceURL.Hostname()
	}
	if !utf8.ValidString(name) {
		return DeepLinkImport{}, errors.New("profile name must be valid UTF-8")
	}
	if len(name) > maxDeepLinkNameLength {
		return DeepLinkImport{}, fmt.Errorf("profile name exceeds %d bytes", maxDeepLinkNameLength)
	}
	if strings.ContainsAny(name, "\r\n\x00") {
		return DeepLinkImport{}, errors.New("profile name contains control characters")
	}
	return DeepLinkImport{URL: source, Name: name}, nil
}
