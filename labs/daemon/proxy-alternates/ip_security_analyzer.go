package proxy

import "github.com/maybeknott/luminet/internal/ipsecurity"

type IPSecurityReport = ipsecurity.IPSecurityReport
type IPSecurityAnalyzer = ipsecurity.IPSecurityAnalyzer

func NewIPSecurityAnalyzer() *IPSecurityAnalyzer { return ipsecurity.NewIPSecurityAnalyzer() }
