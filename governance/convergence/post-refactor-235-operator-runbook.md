# Post-refactor-235 operator runbook

Use Operations -> Convergence policy lab for individual planners or Network Evidence Bundle for a composed read-only view. Treat every returned action/status as evidence/planning, not authorization to mutate network/runtime state. Resolve degraded/unknown components through the authoritative runtime/config owners. Never convert unknown evidence to pass, silently resolve rule conflicts, or activate imported donor configuration without normal admission.
