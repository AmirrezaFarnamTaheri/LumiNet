export type AppearancePreference = 'system' | 'dark' | 'light';
export type ResolvedAppearance = 'dark' | 'light';

const APPEARANCE_KEY = 'luminet.appearance.v1';
const SYSTEM_DARK_QUERY = '(prefers-color-scheme: dark)';
const listeners = new Set<() => void>();
let initialized = false;
let preference: AppearancePreference = 'system';

function isAppearancePreference(value: unknown): value is AppearancePreference {
  return value === 'system' || value === 'dark' || value === 'light';
}

function readStoredPreference(): AppearancePreference {
  if (typeof window === 'undefined') return 'system';
  try {
    const value = window.localStorage.getItem(APPEARANCE_KEY);
    return isAppearancePreference(value) ? value : 'system';
  } catch {
    return 'system';
  }
}

function writeStoredPreference(value: AppearancePreference): void {
  if (typeof window === 'undefined') return;
  try {
    window.localStorage.setItem(APPEARANCE_KEY, value);
  } catch {
    // Appearance is a local preference cache, never product authority.
  }
}

export function resolveAppearance(value: AppearancePreference): ResolvedAppearance {
  if (value !== 'system') return value;
  if (typeof window === 'undefined' || typeof window.matchMedia !== 'function') return 'dark';
  return window.matchMedia(SYSTEM_DARK_QUERY).matches ? 'dark' : 'light';
}

function applyResolvedAppearance(): void {
  if (typeof document === 'undefined') return;
  const resolved = resolveAppearance(preference);
  document.documentElement.dataset.theme = resolved;
  document.documentElement.style.colorScheme = resolved;
}

function notify(): void {
  for (const listener of listeners) listener();
}

function syncFromStorage(event: StorageEvent): void {
  if (event.key !== APPEARANCE_KEY) return;
  const next = isAppearancePreference(event.newValue) ? event.newValue : 'system';
  if (next === preference) return;
  preference = next;
  applyResolvedAppearance();
  notify();
}

function syncSystemPreference(event: MediaQueryListEvent): void {
  if (preference !== 'system') return;
  if (typeof document !== 'undefined') {
    const resolved: ResolvedAppearance = event.matches ? 'dark' : 'light';
    document.documentElement.dataset.theme = resolved;
    document.documentElement.style.colorScheme = resolved;
  }
}

export function initializeAppearance(): void {
  if (initialized || typeof window === 'undefined') return;
  initialized = true;
  preference = readStoredPreference();
  applyResolvedAppearance();
  window.addEventListener('storage', syncFromStorage);
  if (typeof window.matchMedia === 'function') {
    window.matchMedia(SYSTEM_DARK_QUERY).addEventListener('change', syncSystemPreference);
  }
}

export function getAppearancePreference(): AppearancePreference {
  return preference;
}

export function setAppearancePreference(value: AppearancePreference): void {
  if (!isAppearancePreference(value)) return;
  initializeAppearance();
  if (preference === value) {
    applyResolvedAppearance();
    return;
  }
  preference = value;
  writeStoredPreference(value);
  applyResolvedAppearance();
  notify();
}

export function subscribeAppearance(listener: () => void): () => void {
  listeners.add(listener);
  return () => listeners.delete(listener);
}
