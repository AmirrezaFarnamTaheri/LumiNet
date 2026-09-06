export const navigationItems = [
  { path: '/', label: 'Dashboard', keywords: ['overview', 'status', 'metrics', 'ping'] },
  { path: '/health', label: 'Health', keywords: ['doctor', 'readiness', 'diagnostics', 'bundle', 'timeline'] },
  { path: '/rules', label: 'Rules & Routing', keywords: ['rules', 'routes', 'policy'] },
  { path: '/dns', label: 'DNS & Security', keywords: ['dns', 'resolver', 'security', 'blocklist', 'dns leak', 'clean ip', 'resolver health', 'poisoning', 'injection', 'udp tcp dns'] },
  { path: '/logs', label: 'Logs', keywords: ['logs', 'events', 'console'] },
  { path: '/connections', label: 'Connections', keywords: ['flows', 'network', 'sessions', 'traffic'] },
  { path: '/capabilities', label: 'Capabilities', keywords: ['coverage', 'runtime', 'availability'] },
  { path: '/operations', label: 'Operations', keywords: ['doctor', 'engines', 'diagnostics', 'updates', 'planner', 'warp scanner', 'endpoint rank', 'transport truth', 'fec', 'arq', 'packet loss', 'egress country'] },
  { path: '/profiles', label: 'Profiles', keywords: ['subscriptions', 'profiles', 'import', 'export', 'subscription node', 'local socks', 'hidden node', 'provider feed', 'subscription health', 'certificate failure'] },
  { path: '/cockpit', label: '3D Cockpit', keywords: ['3d', 'globe', 'cockpit', 'latency', 'cables', 'middlebox', 'webgl', 'map', 'interconnect'] },
  { path: '/settings', label: 'Settings', keywords: ['configuration', 'preferences', 'kill switch', 'fail closed', 'auto reconnect', 'last working edge', 'system proxy', 'keep connected', 'route recovery'] },
] as const;

export type NavigationItem = (typeof navigationItems)[number];
export type NavigationPath = NavigationItem['path'];
