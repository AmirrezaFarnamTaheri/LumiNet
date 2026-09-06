import { useEffect, useSyncExternalStore } from 'react';
import {
  getAppearancePreference,
  initializeAppearance,
  setAppearancePreference,
  subscribeAppearance,
  type AppearancePreference,
} from '../lib/appearance';

export function useAppearance(): [AppearancePreference, (value: AppearancePreference) => void] {
  const value = useSyncExternalStore(subscribeAppearance, getAppearancePreference, (): AppearancePreference => 'system');
  useEffect(() => {
    initializeAppearance();
  }, []);
  return [value, setAppearancePreference];
}
