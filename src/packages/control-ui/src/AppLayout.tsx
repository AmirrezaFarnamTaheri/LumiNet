import { useEffect, useMemo, useState } from 'react';
import {
  Activity,
  Boxes,
  Gauge,
  HeartPulse,
  LayoutDashboard,
  List,
  Network,
  RadioTower,
  Search,
  Settings,
  Shield,
  type LucideIcon,
} from 'lucide-react';
import { Link, Outlet, useLocation } from 'react-router-dom';
import { CommandPalette } from './CommandPalette';
import { navigationItems, navigationSections, type NavigationPath } from './navigation';
import { useAppearance } from './hooks/useAppearance';
import { useSystemStore, type TelemetryConnectionState } from './store/systemStore';

const connectionPresentation: Record<TelemetryConnectionState, { label: string; dot: string }> = {
  stopped: { label: 'OFFLINE', dot: 'bg-text-muted' },
  connecting: { label: 'CONNECTING', dot: 'bg-warning' },
  authenticating: { label: 'AUTHENTICATING', dot: 'bg-warning' },
  connected: { label: 'LIVE', dot: 'bg-success' },
  retrying: { label: 'RETRYING', dot: 'bg-warning' },
};

const iconByPath: Record<NavigationPath, LucideIcon> = {
  '/': LayoutDashboard,
  '/health': HeartPulse,
  '/rules': Activity,
  '/dns': Shield,
  '/logs': List,
  '/connections': Network,
  '/capabilities': Boxes,
  '/operations': Gauge,
  '/profiles': RadioTower,
  '/settings': Settings,
};

const buildVersion = import.meta.env.VITE_APP_VERSION?.trim() || 'development';

export function AppLayout() {
  const connectionState = useSystemStore((state) => state.connectionState);
  const location = useLocation();
  const connection = connectionPresentation[connectionState];
  const [commandPaletteOpen, setCommandPaletteOpen] = useState(false);
  const [isMac, setIsMac] = useState(false);
  useAppearance();

  useEffect(() => {
    setIsMac(/Mac|iPhone|iPad|iPod/.test(navigator.platform || navigator.userAgent));
    const onKeyDown = (event: KeyboardEvent) => {
      if ((event.metaKey || event.ctrlKey) && event.key.toLowerCase() === 'k') {
        event.preventDefault();
        setCommandPaletteOpen((open) => !open);
      }
    };
    window.addEventListener('keydown', onKeyDown);
    return () => window.removeEventListener('keydown', onKeyDown);
  }, []);

  const groupedNavigation = useMemo(
    () => navigationSections.map((section) => ({
      section,
      items: navigationItems.filter((item) => item.section === section),
    })),
    [],
  );

  return (
    <div className="flex min-h-screen w-full flex-col overflow-hidden bg-bg-primary text-text-primary md:h-screen md:flex-row">
      <nav aria-label="Primary" className="border-b border-border-color bg-bg-secondary md:flex md:w-64 md:flex-col md:border-b-0 md:border-r">
        <div className="flex items-center justify-between gap-4 border-b border-border-color p-4 md:block">
          <div className="flex items-center justify-between gap-3">
            <h1 className="m-0 text-xl font-display text-cyan">LumiNet</h1>
            <button
              type="button"
              onClick={() => setCommandPaletteOpen(true)}
              className="hidden items-center gap-1.5 rounded-md border border-border-color px-2 py-1 text-[11px] text-text-muted transition-colors hover:border-accent/40 hover:text-text-primary md:flex"
              aria-label="Open command palette"
              title={`Open command palette (${isMac ? 'Command' : 'Ctrl'} + K)`}
            >
              <Search size={12} aria-hidden="true" />
              <span className="mono">{isMac ? '⌘K' : 'Ctrl K'}</span>
            </button>
          </div>
          <p className="mono m-0 flex items-center gap-2 text-xs text-text-muted md:mt-1" aria-label={`Telemetry ${connection.label.toLowerCase()}`}>
            <span className={`inline-block h-2 w-2 rounded-full ${connection.dot}`} aria-hidden="true" />
            {connection.label}
          </p>
          <button
            type="button"
            onClick={() => setCommandPaletteOpen(true)}
            className="flex min-h-10 items-center gap-2 rounded-md border border-border-color px-3 text-xs text-text-secondary md:hidden"
            aria-label="Open command palette"
          >
            <Search size={15} aria-hidden="true" /> Find
          </button>
        </div>

        <div className="overflow-x-auto py-2 md:flex-1 md:overflow-y-auto md:py-4">
          <div className="flex min-w-max gap-4 px-2 md:block md:min-w-0 md:space-y-5">
            {groupedNavigation.map(({ section, items }) => (
              <section key={section} aria-labelledby={`nav-${section.replace(/\s+/g, '-').toLowerCase()}`} className="min-w-max md:min-w-0">
                <h2 id={`nav-${section.replace(/\s+/g, '-').toLowerCase()}`} className="px-3 pb-1 text-[10px] font-semibold uppercase tracking-[0.14em] text-text-muted">
                  {section}
                </h2>
                <ul className="m-0 flex list-none gap-1 md:block md:space-y-1">
                  {items.map((item) => {
                    const isActive = location.pathname === item.path || (item.path !== '/' && location.pathname.startsWith(item.path));
                    const Icon = iconByPath[item.path];
                    return (
                      <li key={item.path}>
                        <Link
                          to={item.path}
                          aria-current={isActive ? 'page' : undefined}
                          className={`flex min-h-11 items-center gap-3 rounded-md px-3 py-2 text-sm font-medium outline-none transition-colors ${
                            isActive ? 'bg-accent/10 text-accent' : 'text-text-secondary hover:bg-white/5 hover:text-text-primary focus-visible:ring-2 focus-visible:ring-accent'
                          }`}
                        >
                          <Icon size={18} className={isActive ? 'text-accent' : 'text-text-muted'} aria-hidden="true" />
                          {item.label}
                        </Link>
                      </li>
                    );
                  })}
                </ul>
              </section>
            ))}
          </div>
        </div>

        <div className="mono hidden border-t border-border-color p-4 text-xs text-text-muted md:block">
          build {buildVersion}
        </div>
      </nav>

      <main className="min-w-0 flex-1 overflow-y-auto bg-bg-primary p-4 md:p-8">
        <Outlet />
      </main>
      <CommandPalette open={commandPaletteOpen} onOpenChange={setCommandPaletteOpen} />
    </div>
  );
}
