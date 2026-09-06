export enum GatewayStatus {
  Online = 'online',
  Degraded = 'degraded',
  Offline = 'offline'
}

export interface GatewayMetric {
  ip: string;
  latencyMs: number;
  packetLoss: number;
  status: GatewayStatus;
}

export class GatewayHealthMonitor {
  private readonly gateways = new Map<string, GatewayMetric>();

  constructor(
    private readonly lossDegraded = 0.20,
    private readonly lossOffline = 0.50
  ) {}

  public registerGateway(ip: string): void {
    this.gateways.set(ip, { ip, latencyMs: 0, packetLoss: 0, status: GatewayStatus.Online });
  }

  public recordProbe(ip: string, latencyMs: number, loss: number): void {
    const gw = this.gateways.get(ip);
    if (!gw) return;
    gw.latencyMs = latencyMs;
    gw.packetLoss = loss;
    if (loss >= this.lossOffline) {
      gw.status = GatewayStatus.Offline;
    } else if (loss >= this.lossDegraded) {
      gw.status = GatewayStatus.Degraded;
    } else {
      gw.status = GatewayStatus.Online;
    }
  }

  public selectActiveGateway(primaryIp: string, backupIp: string): string {
    const primary = this.gateways.get(primaryIp);
    if (primary && primary.status === GatewayStatus.Online) {
      return primaryIp;
    }
    const backup = this.gateways.get(backupIp);
    if (backup && backup.status !== GatewayStatus.Offline) {
      return backupIp;
    }
    return primaryIp;
  }
}
