//go:build !cgo || android || ios

package bridge

// NegotiateVersion fails closed when the native core is not linked. Keeping the
// function in every build makes capability discovery compile without treating
// the degraded adapter as a native ABI implementation.
func NegotiateVersion() (string, error) {
	return "", ErrNativeCoreUnavailable
}
