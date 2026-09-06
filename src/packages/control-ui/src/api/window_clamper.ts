export class WindowClamper {
  constructor(public clampedSize: number = 4, public enabled: boolean = true) {}

  clampWindow(originalWindow: number, isHandshake: boolean): number {
    if (!this.enabled) return originalWindow;
    return isHandshake && originalWindow > this.clampedSize ? this.clampedSize : originalWindow;
  }

  isRstLegitimate(rstSeq: number, lastAckSeq: number, window: number): boolean {
    const diff = rstSeq - lastAckSeq;
    const maxWin = Math.max(window, 4096);
    return diff >= 0 && diff <= maxWin;
  }
}
