package scan

import (
	"github.com/maybeknott/luminet/internal/scanner"
)

type ScanTarget = scanner.ScanTarget
type HostResult = scanner.HostResult
type SubnetScanner = scanner.SubnetScanner

var NewSubnetScanner = scanner.NewSubnetScanner
var NewSubnetScannerWithExecutor = scanner.NewSubnetScannerWithExecutor
