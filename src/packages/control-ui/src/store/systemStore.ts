import { create } from 'zustand';

export type TelemetryConnectionState =
  | 'stopped'
  | 'connecting'
  | 'authenticating'
  | 'connected'
  | 'retrying';

interface SystemState {
  connectionState: TelemetryConnectionState;
  latency: number | null;
  throughput: { rx: number; tx: number };
  setConnectionState: (state: TelemetryConnectionState) => void;
  updateMetrics: (rx: number, tx: number, latency: number | null) => void;
}

export const useSystemStore = create<SystemState>((set) => ({
  connectionState: 'stopped',
  latency: null,
  throughput: { rx: 0, tx: 0 },

  setConnectionState: (connectionState) => set({ connectionState }),
  updateMetrics: (rx, tx, latency) => set({ throughput: { rx, tx }, latency }),
}));
