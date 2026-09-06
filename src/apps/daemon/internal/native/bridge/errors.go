package bridge

import "errors"

// ErrNativeCoreUnavailable marks operations that require the linked LumiCore
// implementation and have no behaviorally equivalent pure-Go fallback.
var ErrNativeCoreUnavailable = errors.New("native core unavailable in this build")
