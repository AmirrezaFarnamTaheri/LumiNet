/**
 * Relay Core Schema and Validation
 *
 * Types, validation contracts, and serializers for multi-core tunnel engines
 * (Google Apps Script SOCKS5 relay and Google Drive storage proxy).
 */

export type CoreStatus = 'running' | 'stopped' | 'error' | 'starting';

export type CoreType = 'apps_script' | 'drive_storage';

export type LogLevel = 'info' | 'warn' | 'error' | 'oauth';

export interface LogEntry {
  level: LogLevel;
  message: string;
  timestamp: string;
}

export interface AppsScriptConfigData {
  socksHost: string;
  socksPort: number;
  googleHost: string;
  sni: string | string[];
  scriptKeys: string[];
  tunnelKey: string;
  socksUser?: string;
  socksPass?: string;
}

export interface DriveStorageConfigData {
  listenAddr: string;
  storageType: 'google';
  googleFolderId?: string;
  refreshRateMs: number;
  flushRateMs: number;
  transportTarget: string;
  transportSni: string;
  transportHost: string;
  credentialsPath: string;
  tokenPath?: string;
}

export interface CoreDetail {
  id: string;
  name: string;
  description?: string;
  binaryPath: string;
  coreType: CoreType;
  status: CoreStatus;
  pid: number | null;
  createdAt: string;
  updatedAt: string;
  appsScriptConfig?: AppsScriptConfigData;
  driveStorageConfig?: DriveStorageConfigData;
  stats?: {
    totalRequests: number;
    todayRequests: number;
    lastResetAt: string;
  };
}

export interface ValidationError {
  field: string;
  message: string;
}

/**
 * Validates Google Apps Script core configuration.
 */
export function validateAppsScriptConfig(config: Partial<AppsScriptConfigData>): ValidationError[] {
  const errors: ValidationError[] = [];

  if (!config.socksPort || config.socksPort <= 0 || config.socksPort > 65535) {
    errors.push({ field: 'socksPort', message: 'SOCKS port must be between 1 and 65535' });
  }

  if (!config.googleHost || config.googleHost.trim() === '') {
    errors.push({ field: 'googleHost', message: 'Google host is required' });
  }

  if (!config.tunnelKey || config.tunnelKey.trim() === '') {
    errors.push({ field: 'tunnelKey', message: 'Tunnel key is required' });
  }

  if (!config.scriptKeys || config.scriptKeys.length === 0) {
    errors.push({ field: 'scriptKeys', message: 'At least one deployment script key is required' });
  }

  return errors;
}

/**
 * Validates Google Drive storage core configuration.
 */
export function validateDriveStorageConfig(config: Partial<DriveStorageConfigData>): ValidationError[] {
  const errors: ValidationError[] = [];

  if (!config.listenAddr || !config.listenAddr.includes(':')) {
    errors.push({ field: 'listenAddr', message: 'Valid listen address (host:port) is required' });
  }

  if (!config.credentialsPath || config.credentialsPath.trim() === '') {
    errors.push({ field: 'credentialsPath', message: 'Path to OAuth2 credentials.json is required' });
  }

  if (!config.transportTarget || !config.transportTarget.includes(':')) {
    errors.push({ field: 'transportTarget', message: 'Valid transport target (IP:port) is required' });
  }

  if (!config.transportSni || config.transportSni.trim() === '') {
    errors.push({ field: 'transportSni', message: 'Transport SNI is required' });
  }

  return errors;
}

/**
 * Parses raw JSON string into SOCKS SNI field (string or array).
 */
export function parseSniValue(raw: string): string | string[] {
  try {
    const parsed = JSON.parse(raw);
    if (Array.isArray(parsed)) {
      return parsed.map((s) => String(s).trim()).filter(Boolean);
    }
    return String(parsed).trim();
  } catch {
    return raw.trim();
  }
}
