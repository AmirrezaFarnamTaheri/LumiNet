import { useSyncExternalStore } from "react";

/**
 * Single source of truth for "is the host window focused".
 *
 * Primary feed:
 * 1. Native platform watcher event (`app://focused` emitted by Win32 GetForegroundWindow).
 * 2. Window focus changed event from the application container (`onFocusChanged`).
 * 3. Standard document focus fallback (`document.hasFocus()`).
 *
 * Keeps UI components, animations, and WebGL rendering engines at ~0% CPU when
 * the window is unfocused or minimized in background.
 */
let isFocused = typeof document !== "undefined" ? document.hasFocus() : true;
const listeners = new Set<() => void>();

function setFocus(next: boolean) {
  if (next === isFocused) return;
  isFocused = next;
  listeners.forEach((listener) => listener());
}

if (typeof window !== "undefined") {
  // Try Tauri listener if available
  try {
    // Dynamic import style or global check to keep bundle resilient
    const tauriEvent = (window as unknown as { __TAURI__?: { event?: { listen: (event: string, cb: (e: { payload: boolean }) => void) => void } } })
      .__TAURI__?.event;
    if (tauriEvent?.listen) {
      tauriEvent.listen("app://focused", (e) => setFocus(e.payload));
    }
  } catch {
    // Not running inside native Tauri runtime
  }

  window.addEventListener("focus", () => setFocus(true));
  window.addEventListener("blur", () => setFocus(false));
  document.addEventListener("visibilitychange", () => {
    setFocus(document.visibilityState === "visible");
  });
}

export function useWindowFocused(): boolean {
  return useSyncExternalStore(
    (callback) => {
      listeners.add(callback);
      return () => listeners.delete(callback);
    },
    () => isFocused,
    () => true // SSR fallback
  );
}
