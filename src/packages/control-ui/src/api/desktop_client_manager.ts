export enum SystemProxyMode {
  Direct = 'direct',
  Pac = 'pac',
  Global = 'global',
  Manual = 'manual',
}

export interface DesktopStatus {
  mode: SystemProxyMode;
  activeProfile: string;
  httpPort: number;
  socks5Port: number;
  isConnected: boolean;
  pacUrl?: string;
}

export class DesktopClientManager {
  private mode: SystemProxyMode = SystemProxyMode.Direct;
  private activeProfile: string = 'default';
  public httpPort: number;
  public socks5Port: number;
  private isConnected: boolean = false;
  private pacUrl?: string;

  constructor(httpPort: number, socks5Port: number) {
    this.httpPort = httpPort;
    this.socks5Port = socks5Port;
  }

  setProxyMode(mode: SystemProxyMode, pacUrl?: string): void {
    if (mode === SystemProxyMode.Pac && !pacUrl && !this.pacUrl) {
      throw new Error('PAC mode requires a valid PAC URL');
    }

    this.mode = mode;
    if (pacUrl) {
      this.pacUrl = pacUrl;
    }
  }

  switchProfile(profileId: string): void {
    this.activeProfile = profileId;
  }

  setConnected(connected: boolean): void {
    this.isConnected = connected;
  }

  getStatus(): DesktopStatus {
    return {
      mode: this.mode,
      activeProfile: this.activeProfile,
      httpPort: this.httpPort,
      socks5Port: this.socks5Port,
      isConnected: this.isConnected,
      pacUrl: this.pacUrl,
    };
  }

  handleIpcCommand(command: string, payload: Record<string, any> = {}): any {
    switch (command) {
      case 'get_status':
        return this.getStatus();
      case 'set_mode': {
        const modeStr = payload.mode;
        if (!modeStr) throw new Error('Missing mode');
        let mode: SystemProxyMode;
        switch (modeStr.toLowerCase()) {
          case 'direct':
            mode = SystemProxyMode.Direct;
            break;
          case 'pac':
            mode = SystemProxyMode.Pac;
            break;
          case 'global':
            mode = SystemProxyMode.Global;
            break;
          case 'manual':
            mode = SystemProxyMode.Manual;
            break;
          default:
            throw new Error('Invalid proxy mode');
        }
        this.setProxyMode(mode, payload.pac_url || payload.pacUrl);
        return { success: true };
      }
      case 'switch_profile': {
        const profile = payload.profile;
        if (!profile) throw new Error('Missing profile');
        this.switchProfile(profile);
        return { success: true, profile };
      }
      default:
        throw new Error(`Unknown command: ${command}`);
    }
  }
}
