package proxy

import "github.com/maybeknott/luminet/internal/smartdns"

type SmartDNSRouter = smartdns.SmartDNSRouter

func NewSmartDNSRouter() *SmartDNSRouter { return smartdns.NewSmartDNSRouter() }
