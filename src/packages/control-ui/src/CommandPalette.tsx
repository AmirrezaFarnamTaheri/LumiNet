import { Command, Search, X } from 'lucide-react';
import { useEffect, useMemo, useRef, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { fuzzyMatch } from './lib/fuzzy';
import { navigationItems, type NavigationItem, type NavigationPath } from './navigation';

const RECENTS_KEY = 'luminet.command-palette.recents.v1';
const MAX_RECENTS = 5;

interface CommandPaletteProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
}

interface RankedCommand {
  item: NavigationItem;
  score: number;
  recentIndex: number;
}

function readRecents(): NavigationPath[] {
  try {
    const raw = window.localStorage.getItem(RECENTS_KEY);
    if (!raw) return [];
    const parsed: unknown = JSON.parse(raw);
    if (!Array.isArray(parsed)) return [];
    const allowed = new Set<string>(navigationItems.map((item) => item.path));
    return parsed
      .filter((value): value is NavigationPath => typeof value === 'string' && allowed.has(value))
      .slice(0, MAX_RECENTS);
  } catch {
    return [];
  }
}

function writeRecents(paths: NavigationPath[]) {
  try {
    window.localStorage.setItem(RECENTS_KEY, JSON.stringify(paths.slice(0, MAX_RECENTS)));
  } catch {
    // Local storage is an optional preference cache, never product authority.
  }
}

export function CommandPalette({ open, onOpenChange }: CommandPaletteProps) {
  const navigate = useNavigate();
  const dialogRef = useRef<HTMLElement>(null);
  const inputRef = useRef<HTMLInputElement>(null);
  const previousFocusRef = useRef<HTMLElement | null>(null);
  const [query, setQuery] = useState('');
  const [activeIndex, setActiveIndex] = useState(0);
  const [recents, setRecents] = useState<NavigationPath[]>(() => (typeof window === 'undefined' ? [] : readRecents()));

  const commands = useMemo(() => {
    const normalizedQuery = query.trim();
    const ranked: RankedCommand[] = [];
    for (const item of navigationItems) {
      const searchable = `${item.label} ${item.keywords.join(' ')}`;
      const match = fuzzyMatch(searchable, normalizedQuery);
      if (!match.matched) continue;
      const recentIndex = recents.indexOf(item.path);
      ranked.push({
        item,
        score: match.score + (normalizedQuery === '' && recentIndex >= 0 ? 100 - recentIndex : 0),
        recentIndex,
      });
    }
    return ranked.sort((left, right) => {
      if (left.score !== right.score) return right.score - left.score;
      if (left.recentIndex !== right.recentIndex) {
        if (left.recentIndex < 0) return 1;
        if (right.recentIndex < 0) return -1;
        return left.recentIndex - right.recentIndex;
      }
      return left.item.label.localeCompare(right.item.label);
    });
  }, [query, recents]);

  useEffect(() => {
    if (!open) return;
    previousFocusRef.current = document.activeElement instanceof HTMLElement ? document.activeElement : null;
    setQuery('');
    setActiveIndex(0);
    const previousOverflow = document.body.style.overflow;
    document.body.style.overflow = 'hidden';
    const frame = window.requestAnimationFrame(() => inputRef.current?.focus());
    return () => {
      window.cancelAnimationFrame(frame);
      document.body.style.overflow = previousOverflow;
      previousFocusRef.current?.focus();
      previousFocusRef.current = null;
    };
  }, [open]);

  useEffect(() => {
    setActiveIndex((current) => Math.min(current, Math.max(0, commands.length - 1)));
  }, [commands.length]);

  if (!open) return null;

  function choose(item: NavigationItem) {
    const next = [item.path, ...recents.filter((path) => path !== item.path)].slice(0, MAX_RECENTS) as NavigationPath[];
    setRecents(next);
    writeRecents(next);
    onOpenChange(false);
    navigate(item.path);
  }

  return (
    <div
      className="fixed inset-0 z-50 flex items-start justify-center bg-black/60 px-4 pt-[12vh] backdrop-blur-sm"
      onMouseDown={(event) => {
        if (event.currentTarget === event.target) onOpenChange(false);
      }}
    >
      <section
        ref={dialogRef}
        role="dialog"
        aria-modal="true"
        aria-labelledby="command-palette-title"
        className="w-full max-w-xl overflow-hidden rounded-xl border border-border-color bg-bg-secondary shadow-2xl"
        onKeyDown={(event) => {
          if (event.key === 'Tab') {
            const focusable = dialogRef.current?.querySelectorAll<HTMLElement>('button:not([disabled]), input:not([disabled]), [href], [tabindex]:not([tabindex="-1"])');
            if (focusable && focusable.length > 0) {
              const first = focusable[0];
              const last = focusable[focusable.length - 1];
              if (first === undefined || last === undefined) return;
              if (event.shiftKey && document.activeElement === first) {
                event.preventDefault();
                last.focus();
              } else if (!event.shiftKey && document.activeElement === last) {
                event.preventDefault();
                first.focus();
              }
            }
          } else if (event.key === 'Escape') {
            event.preventDefault();
            onOpenChange(false);
          } else if (event.key === 'ArrowDown') {
            event.preventDefault();
            setActiveIndex((index) => commands.length === 0 ? 0 : (index + 1) % commands.length);
          } else if (event.key === 'ArrowUp') {
            event.preventDefault();
            setActiveIndex((index) => commands.length === 0 ? 0 : (index - 1 + commands.length) % commands.length);
          } else if (event.key === 'Enter' && commands[activeIndex]) {
            event.preventDefault();
            choose(commands[activeIndex].item);
          }
        }}
      >
        <h2 id="command-palette-title" className="sr-only">Navigate LumiNet</h2>
        <div className="flex items-center gap-3 border-b border-border-color px-4">
          <Search size={18} className="shrink-0 text-text-muted" aria-hidden="true" />
          <input
            ref={inputRef}
            value={query}
            onChange={(event) => {
              setQuery(event.target.value);
              setActiveIndex(0);
            }}
            aria-label="Search LumiNet commands"
            aria-controls="command-palette-results"
            aria-activedescendant={commands[activeIndex] ? `command-${activeIndex}` : undefined}
            className="min-h-14 flex-1 border-0 bg-transparent text-sm text-text-primary outline-none placeholder:text-text-muted"
            placeholder="Go to a page…"
            autoComplete="off"
            spellCheck={false}
          />
          <button type="button" className="rounded p-1.5 text-text-muted hover:bg-white/5 hover:text-text-primary" onClick={() => onOpenChange(false)} aria-label="Close command palette">
            <X size={17} aria-hidden="true" />
          </button>
        </div>

        <ul id="command-palette-results" role="listbox" aria-label="Navigation results" className="m-0 max-h-[55vh] list-none overflow-y-auto p-2">
          {commands.length === 0 ? (
            <li className="px-3 py-8 text-center text-sm text-text-muted">No matching LumiNet destination.</li>
          ) : commands.map(({ item, recentIndex }, index) => (
            <li key={item.path} role="option" aria-selected={index === activeIndex} id={`command-${index}`}>
              <button
                type="button"
                onMouseEnter={() => setActiveIndex(index)}
                onClick={() => choose(item)}
                className={`flex min-h-11 w-full items-center justify-between gap-4 rounded-md px-3 py-2 text-left text-sm transition-colors ${
                  index === activeIndex ? 'bg-accent/12 text-accent' : 'text-text-secondary hover:bg-white/5 hover:text-text-primary'
                }`}
              >
                <span className="flex items-center gap-3"><Command size={15} aria-hidden="true" />{item.label}</span>
                <span className="mono text-[10px] text-text-muted">{recentIndex >= 0 ? `RECENT ${recentIndex + 1}` : item.path}</span>
              </button>
            </li>
          ))}
        </ul>
        <footer className="flex flex-wrap gap-x-4 gap-y-1 border-t border-border-color px-4 py-2 text-[11px] text-text-muted">
          <span><kbd className="mono">↑↓</kbd> select</span>
          <span><kbd className="mono">Enter</kbd> open</span>
          <span><kbd className="mono">Esc</kbd> close</span>
          <span>Recents stay on this device only.</span>
        </footer>
      </section>
    </div>
  );
}
