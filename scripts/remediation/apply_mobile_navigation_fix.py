#!/usr/bin/env python3
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[2]
REL = "src/packages/control-ui/src/AppLayout.tsx"
EXPECTED = "39dce8955c620fd6df1a9c2c82f79695efb73d38"
actual = subprocess.check_output(["git", "hash-object", REL], cwd=ROOT, text=True).strip()
if actual != EXPECTED:
    raise SystemExit(f"{REL} drifted: expected {EXPECTED}, got {actual}")
path = ROOT / REL
source = path.read_text(encoding="utf-8")

def replace_once(old: str, new: str, label: str) -> None:
    global source
    count = source.count(old)
    if count != 1:
        raise SystemExit(f"{label}: expected one match, got {count}")
    source = source.replace(old, new, 1)

replace_once(
    "import { navigationItems, navigationSections, type NavigationPath } from './navigation';",
    "import { navigationItems, navigationSections, type NavigationPath, type NavigationSection } from './navigation';",
    "navigation type import",
)
replace_once(
    '''const buildVersion = import.meta.env.VITE_APP_VERSION?.trim() || 'development';''',
    '''const buildVersion = import.meta.env.VITE_APP_VERSION?.trim() || 'development';

const mobileSectionDestination: Record<NavigationSection, NavigationPath> = {
  Overview: '/',
  Observe: '/connections',
  'Network policy': '/rules',
  Operations: '/operations',
  System: '/settings',
};

const mobileSectionLabel: Record<NavigationSection, string> = {
  Overview: 'Overview',
  Observe: 'Observe',
  'Network policy': 'Network',
  Operations: 'Operate',
  System: 'System',
};''',
    "mobile section maps",
)
replace_once(
    '''  const groupedNavigation = useMemo(
    () => navigationSections.map((section) => ({
      section,
      items: navigationItems.filter((item) => item.section === section),
    })),
    [],
  );''',
    '''  const groupedNavigation = useMemo(
    () => navigationSections.map((section) => ({
      section,
      items: navigationItems.filter((item) => item.section === section),
    })),
    [],
  );
  const activeSection = useMemo(
    () => navigationItems.find((item) => location.pathname === item.path || (item.path !== '/' && location.pathname.startsWith(item.path)))?.section ?? 'Overview',
    [location.pathname],
  );''',
    "active mobile section",
)
replace_once(
    '''  return (
    <div className="flex min-h-screen w-full flex-col overflow-hidden bg-bg-primary text-text-primary md:h-screen md:flex-row">
      <nav aria-label="Primary" className="border-b border-border-color bg-bg-secondary md:flex md:w-64 md:flex-col md:border-b-0 md:border-r">
        <div className="flex items-center justify-between gap-4 border-b border-border-color p-4 md:block">''',
    '''  return (
    <div className="flex min-h-screen w-full flex-col overflow-hidden bg-bg-primary text-text-primary md:h-screen md:flex-row">
      <header className="flex items-center justify-between gap-3 border-b border-border-color bg-bg-secondary p-3 md:hidden">
        <div className="min-w-0">
          <h1 className="m-0 text-lg font-display text-cyan">LumiNet</h1>
          <p className="mono m-0 mt-0.5 flex items-center gap-2 text-[10px] text-text-muted" aria-label={`Telemetry ${connection.label.toLowerCase()}`}>
            <span className={`inline-block h-2 w-2 rounded-full ${connection.dot}`} aria-hidden="true" />
            {connection.label}
          </p>
        </div>
        <button
          type="button"
          onClick={() => setCommandPaletteOpen(true)}
          className="flex min-h-11 items-center gap-2 rounded-md border border-border-color px-3 text-xs text-text-secondary"
          aria-label="Open command palette"
        >
          <Search size={15} aria-hidden="true" /> Find
        </button>
      </header>

      <nav aria-label="Primary" className="hidden bg-bg-secondary md:flex md:w-64 md:flex-col md:border-r md:border-border-color">
        <div className="border-b border-border-color p-4">''',
    "mobile header and desktop nav boundary",
)
replace_once(
    '''          <button
            type="button"
            onClick={() => setCommandPaletteOpen(true)}
            className="flex min-h-10 items-center gap-2 rounded-md border border-border-color px-3 text-xs text-text-secondary md:hidden"
            aria-label="Open command palette"
          >
            <Search size={15} aria-hidden="true" /> Find
          </button>
        </div>

        <div className="overflow-x-auto py-2 md:flex-1 md:overflow-y-auto md:py-4">
          <div className="flex min-w-max gap-4 px-2 md:block md:min-w-0 md:space-y-5">''',
    '''        </div>

        <div className="flex-1 overflow-y-auto py-4">
          <div className="space-y-5 px-2">''',
    "desktop nav only body",
)
replace_once(
    '''              <section key={section} aria-labelledby={`nav-${section.replace(/\s+/g, '-').toLowerCase()}`} className="min-w-max md:min-w-0">''',
    '''              <section key={section} aria-labelledby={`nav-${section.replace(/\s+/g, '-').toLowerCase()}`}>''',
    "desktop section class",
)
replace_once(
    '''                <ul className="m-0 flex list-none gap-1 md:block md:space-y-1">''',
    '''                <ul className="m-0 list-none space-y-1">''',
    "desktop nav list",
)
replace_once(
    '''      <main className="min-w-0 flex-1 overflow-y-auto bg-bg-primary p-4 md:p-8">
        <Outlet />
      </main>
      <CommandPalette open={commandPaletteOpen} onOpenChange={setCommandPaletteOpen} />''',
    '''      <main className="min-w-0 flex-1 overflow-y-auto bg-bg-primary p-4 pb-24 md:p-8">
        <Outlet />
      </main>

      <nav aria-label="Primary mobile" className="fixed inset-x-0 bottom-0 z-40 border-t border-border-color bg-bg-secondary/95 px-1 pb-[env(safe-area-inset-bottom)] backdrop-blur md:hidden">
        <ul className="m-0 grid list-none grid-cols-5 gap-0.5 py-1">
          {navigationSections.map((section) => {
            const path = mobileSectionDestination[section];
            const Icon = iconByPath[path];
            const active = activeSection === section;
            return (
              <li key={section}>
                <Link
                  to={path}
                  aria-current={active ? 'page' : undefined}
                  className={`flex min-h-14 flex-col items-center justify-center gap-1 rounded-md px-1 py-1 text-[10px] font-medium outline-none transition-colors ${active ? 'bg-accent/10 text-accent' : 'text-text-muted hover:bg-bg-tertiary/60 hover:text-text-primary focus-visible:ring-2 focus-visible:ring-accent'}`}
                >
                  <Icon size={18} aria-hidden="true" />
                  <span>{mobileSectionLabel[section]}</span>
                </Link>
              </li>
            );
          })}
        </ul>
      </nav>
      <CommandPalette open={commandPaletteOpen} onOpenChange={setCommandPaletteOpen} />''',
    "mobile bottom navigation",
)

path.write_text(source, encoding="utf-8")
print("mobile navigation converged to MASTER.md bottom-tab authority")
