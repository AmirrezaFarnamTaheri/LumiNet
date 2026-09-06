import { create } from "zustand";

export type ConnectionStatus =
  | { state: "Idle" }
  | { state: "Launching" }
  | { state: "Connecting" }
  | { state: "Connected"; socks_addr: string; connected_at_ms: number }
  | { state: "Reconnecting"; attempt: number; max_attempts: number }
  | { state: "Disconnecting" }
  | { state: "Error"; message: string; phase: string };

export interface LogLine {
  line: string;
  timestamp: number;
}

const MAX_LOG_LINES = 500;
const BUDGET_REGEX = /budget=(\d+)s/;

interface ConnectionLineageState {
  status: ConnectionStatus;
  logs: LogLine[];
  sidecarError: string | null;
  scanBudgetSecs: number | null;
  attemptId: number;

  setStatus: (status: ConnectionStatus) => void;
  appendLogBatch: (newLogs: LogLine[]) => void;
  setSidecarError: (err: string | null) => void;
  startNewAttempt: () => void;
  clearLogs: () => void;
}

export const useConnectionLineageStore = create<ConnectionLineageState>((set) => ({
  status: { state: "Idle" },
  logs: [],
  sidecarError: null,
  scanBudgetSecs: null,
  attemptId: 0,

  setStatus: (status) =>
    set(() => ({
      status,
      ...(status.state === "Launching" ? { scanBudgetSecs: null } : {}),
      ...(status.state === "Idle" || status.state === "Connected" ? { sidecarError: null } : {}),
    })),

  appendLogBatch: (newLogs) =>
    set((s) => {
      let discoveredBudget: number | null = null;
      for (const entry of newLogs) {
        const match = BUDGET_REGEX.exec(entry.line);
        if (match) {
          discoveredBudget = Number(match[1]);
        }
      }

      return {
        logs: [...s.logs, ...newLogs].slice(-MAX_LOG_LINES),
        ...(discoveredBudget !== null ? { scanBudgetSecs: discoveredBudget } : {}),
      };
    }),

  setSidecarError: (sidecarError) => set({ sidecarError }),

  startNewAttempt: () =>
    set((s) => ({
      logs: [],
      scanBudgetSecs: null,
      sidecarError: null,
      attemptId: s.attemptId + 1,
      status: { state: "Launching" },
    })),

  clearLogs: () => set({ logs: [] }),
}));
