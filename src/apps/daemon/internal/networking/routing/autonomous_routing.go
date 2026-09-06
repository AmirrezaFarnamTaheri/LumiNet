package routing

import (
	"strings"
)

type RoutingAction string

const (
	ActionDirect RoutingAction = "DIRECT"
	ActionProxy  RoutingAction = "PROXY"
	ActionBlock   RoutingAction = "BLOCK"
)

type AutonomousCoordinator struct {
	pac         *PacScriptCompiler
	autoProxy   *AutoProxyMatcher
	defaultNode string
}

func NewAutonomousCoordinator(defaultNode string) *AutonomousCoordinator {
	return &AutonomousCoordinator{
		pac:         NewPacScriptCompiler(defaultNode),
		autoProxy:   NewAutoProxyMatcher(),
		defaultNode: defaultNode,
	}
}

func (a *AutonomousCoordinator) Pac() *PacScriptCompiler {
	return a.pac
}

func (a *AutonomousCoordinator) AutoProxy() *AutoProxyMatcher {
	return a.autoProxy
}

func (a *AutonomousCoordinator) Evaluate(target string) (RoutingAction, string) {
	// Tier 1: AutoProxy rules
	if verdict, ok := a.autoProxy.Match(target); ok {
		if verdict == VerdictDirect {
			return ActionDirect, ""
		}
		return ActionProxy, a.defaultNode
	}

	// Tier 2: PAC domain matching
	res := a.pac.EvaluateDomain(target)
	if res == "DIRECT" {
		return ActionDirect, ""
	}
	if strings.HasPrefix(res, "PROXY ") {
		return ActionProxy, strings.TrimPrefix(res, "PROXY ")
	}

	return ActionProxy, a.defaultNode
}
