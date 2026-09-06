# Post-refactor-223 operator runbook

## Transport and DNS evidence

Use Operations planners for DNS tunnel reliability, transport truth and DNS transport integrity. These surfaces are advisory/read-only. Treat `durable` as the only connected transport-truth verdict; investigate advertised/measured geography mismatches rather than rewriting either datum.

## Subscription node management

Open Profiles → Manage nodes only after a successful refresh. Hidden nodes remain visible in management view but are excluded from normal resolution/activation. Hiding all nodes is refused. Activating a node starts one explicit local SOCKS runtime and does not change the system proxy. Stop requires the exact active profile/node owner.

## Host proxy recovery

Normal evasion stop first restores the exact pre-LumiNet proxy and only then tears down the compatibility bridge. If release fails, do not force a replacement route; the durable host-network session remains available for recovery.

## Provisioning

DNS preflight must establish provider/public NS agreement and no conflicting delegated child before mutation. VPS layout publication refuses unmanaged non-empty `/opt/3xui`, validates a staged Compose generation, atomically switches `current`, and restores the prior generation on launch failure.
