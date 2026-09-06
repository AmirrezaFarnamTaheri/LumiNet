export type SupervisorState = "STOPPED" | "STARTING" | "RUNNING" | "CRASHED";

export class TunnelProcessSupervisorClient {
  private _state: SupervisorState = "STOPPED";
  private _restarts = 0;
  private _currentBackoff: number;

  constructor(
    public readonly maxRestarts = 5,
    public readonly baseBackoffMs = 1000,
    public readonly maxBackoffMs = 30000
  ) {
    this._currentBackoff = baseBackoffMs;
  }

  get state(): SupervisorState { return this._state; }
  get restarts(): number { return this._restarts; }

  recordCrash(): number | null {
    this._state = "CRASHED";
    this._restarts++;
    if (this._restarts > this.maxRestarts) return null;

    const delay = this._currentBackoff;
    this._currentBackoff = Math.min(this._currentBackoff * 2, this.maxBackoffMs);
    return delay;
  }

  markRunning(): void {
    this._state = "RUNNING";
    this._currentBackoff = this.baseBackoffMs;
  }

  reset(): void {
    this._state = "STOPPED";
    this._restarts = 0;
    this._currentBackoff = this.baseBackoffMs;
  }
}
