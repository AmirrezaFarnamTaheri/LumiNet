import type { Decoder } from './contracts';

const DEFAULT_API_URL = 'http://127.0.0.1:8470';

interface ControlSession {
  apiUrl: string;
  apiKey: string;
  source: 'wails' | 'environment' | 'default';
}

interface WebSocketSession {
  token: string;
}

interface RawSessionConfig {
  api_url?: unknown;
  api_key?: unknown;
  apiUrl?: unknown;
  apiKey?: unknown;
}

interface AppBridgeBinding {
  GetSessionConfig?: () => Promise<RawSessionConfig>;
}

declare global {
  interface Window {
    go?: {
      main?: {
        AppBridge?: AppBridgeBinding;
      };
    };
  }
}

function wailsBridge(): AppBridgeBinding | undefined {
  return typeof window === 'undefined' ? undefined : window.go?.main?.AppBridge;
}

function stringValue(value: unknown): string {
  return typeof value === 'string' ? value.trim() : '';
}

async function responseError(response: Response): Promise<Error> {
  let detail = '';
  try {
    const payload: unknown = await response.clone().json();
    if (typeof payload === 'object' && payload !== null && 'error' in payload) {
      detail = stringValue(payload.error);
    }
  } catch {
    detail = stringValue(await response.text());
  }
  const suffix = detail ? `: ${detail}` : '';
  return new Error(`LumiNet request failed with status ${response.status}${suffix}`);
}

function normalizeAPIURL(raw: string): string {
  const candidate = raw.trim() || DEFAULT_API_URL;
  const parsed = new URL(candidate);
  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    throw new Error('LumiNet API URL must use HTTP or HTTPS');
  }
  if (parsed.username || parsed.password || parsed.search || parsed.hash) {
    throw new Error('LumiNet API URL must not contain credentials, query parameters, or fragments');
  }
  parsed.pathname = parsed.pathname.replace(/\/+$/, '');
  return parsed.toString().replace(/\/$/, '');
}

async function loadSession(): Promise<ControlSession> {
  const bridge = wailsBridge();
  if (bridge?.GetSessionConfig) {
    try {
      const raw = await bridge.GetSessionConfig();
      return {
        apiUrl: normalizeAPIURL(stringValue(raw.api_url ?? raw.apiUrl)),
        apiKey: stringValue(raw.api_key ?? raw.apiKey),
        source: 'wails',
      };
    } catch (error) {
      throw new Error('Desktop session discovery failed; refusing direct HTTP fallback.', { cause: error });
    }
  }

  const environmentURL = stringValue(import.meta.env.VITE_LUMINET_API_URL);
  return {
    apiUrl: normalizeAPIURL(environmentURL),
    apiKey: stringValue(import.meta.env.VITE_LUMINET_API_KEY),
    source: environmentURL ? 'environment' : 'default',
  };
}

class ControlTransport {
  private sessionPromise: Promise<ControlSession> | undefined;

  session(): Promise<ControlSession> {
    this.sessionPromise ??= loadSession();
    return this.sessionPromise;
  }

  async request(path: string, init: RequestInit = {}): Promise<Response> {
    const session = await this.session();
    const headers = new Headers(init.headers);
    if (session.apiKey && !headers.has('X-API-Key')) {
      headers.set('X-API-Key', session.apiKey);
    }
    return fetch(this.endpoint(session.apiUrl, path), {
      ...init,
      headers,
    });
  }

  async json<T>(path: string, decode: Decoder<T>, init: RequestInit = {}): Promise<T> {
    const response = await this.request(path, init);
    if (!response.ok) {
      throw await responseError(response);
    }
    const payload: unknown = await response.json();
    return decode(payload);
  }

  async websocketURL(path: string): Promise<string> {
    const session = await this.session();
    const endpoint = new URL(this.endpoint(session.apiUrl, path));
    endpoint.protocol = endpoint.protocol === 'https:' ? 'wss:' : 'ws:';
    return endpoint.toString();
  }

  async websocketSession(): Promise<WebSocketSession> {
    const response = await this.request('/api/session/ws', { method: 'POST' });
    if (!response.ok) {
      throw await responseError(response);
    }
    const payload: unknown = await response.json();
    if (typeof payload !== 'object' || payload === null || !('token' in payload) || typeof payload.token !== 'string' || payload.token === '') {
      throw new Error('WebSocket session response did not include a token');
    }
    return { token: payload.token };
  }

  async executeDiagnosticRun(
    kind: string,
    target: string,
    options: Readonly<Record<string, string>> = {},
  ): Promise<string> {
    const response = await this.request('/api/diagnostics', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ type: kind, target, options }),
    });
    if (!response.ok) {
      throw await responseError(response);
    }
    const payload: unknown = await response.json();
    if (
      typeof payload !== 'object'
      || payload === null
      || !('id' in payload)
      || typeof payload.id !== 'string'
      || payload.id === ''
    ) {
      throw new Error('Diagnostic response did not include an id');
    }
    return payload.id;
  }

  private endpoint(apiUrl: string, path: string): string {
    const normalizedPath = path.startsWith('/') ? path : `/${path}`;
    return `${apiUrl}${normalizedPath}`;
  }
}

export const controlTransport = new ControlTransport();
