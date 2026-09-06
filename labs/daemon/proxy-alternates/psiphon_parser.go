package proxy

import (
	"io"

	"github.com/maybeknott/luminet/internal/scanner"
)

// PsiphonNoticeParser is the scanner-owned parser exposed through the proxy
// package for compatibility with existing route integrations.
type PsiphonNoticeParser = scanner.PsiphonNoticeParser

// NewPsiphonNoticeParser creates the canonical Psiphon notice parser.
func NewPsiphonNoticeParser(routeID string) *PsiphonNoticeParser {
	return scanner.NewPsiphonNoticeParser(routeID)
}

// ParsePsiphonNoticeStream delegates parsing to the canonical scanner service.
func ParsePsiphonNoticeStream(routeID string, reader io.Reader) (ProviderRouteReadiness, error) {
	return scanner.ParsePsiphonNoticeStream(routeID, reader)
}
