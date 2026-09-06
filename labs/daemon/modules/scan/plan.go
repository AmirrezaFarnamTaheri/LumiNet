// Package scan — backward-compatibility facade forwarding to internal/scanner.
package scan

import (
	"github.com/maybeknott/luminet/internal/scanner"
)

const DefaultMaxTargets = scanner.DefaultMaxTargets

type PortSpec = scanner.PortSpec
var CommonPorts = scanner.CommonPorts
var NmapTop1000Ports = scanner.NmapTop1000Ports

type Target = scanner.Target
type PlanConfig = scanner.PlanConfig
type ScanPlan = scanner.ScanPlan

var BuildPlan = scanner.BuildPlan
var DeduplicatePorts = scanner.DeduplicatePorts
var ParsePortRange = scanner.ParsePortRange
var ExpandCIDRMax = scanner.ExpandCIDRMax
var SampleCIDR = scanner.SampleCIDR
