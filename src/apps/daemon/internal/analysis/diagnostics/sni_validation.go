package diagnostics

import "github.com/maybeknott/luminet/internal/networking/tlsdecoy"

const maxSniSpoofLength = tlsdecoy.MaxSNIBytes

func validSNI(s string) bool { return tlsdecoy.ValidSNI(s) }
