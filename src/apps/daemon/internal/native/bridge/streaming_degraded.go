//go:build !cgo || android || ios

package bridge

// StartStream returns ErrNativeCoreUnavailable on platforms without CGO or where
// the native CGO streaming core is unavailable.
func StartStream(op uint16, payload []byte) (<-chan StreamEvent, func(), error) {
	return nil, func() {}, ErrNativeCoreUnavailable
}
