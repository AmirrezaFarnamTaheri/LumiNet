import { useSystemStore, type TelemetryConnectionState } from '../store/systemStore';
import { controlTransport } from './ControlTransport';
import { parseTelemetryEvent, type TelemetryEvent } from './contracts';

const RECONNECT_DELAYS_MS = [1000, 2000, 5000, 10000, 30000] as const;
let ws: WebSocket | null = null;
let reconnectTimer: ReturnType<typeof setTimeout> | null = null;
let shouldReconnect = false;
let connecting = false;
let reconnectAttempt = 0;

type TelemetryCallback = (payload: TelemetryEvent) => void;
const subscribers = new Set<TelemetryCallback>();

function setConnectionState(state: TelemetryConnectionState) {
  useSystemStore.getState().setConnectionState(state);
}

function scheduleReconnect() {
  if (!shouldReconnect || reconnectTimer !== null) return;
  const delayIndex = Math.min(reconnectAttempt, RECONNECT_DELAYS_MS.length - 1);
  const delay = RECONNECT_DELAYS_MS[delayIndex];
  reconnectAttempt += 1;
  setConnectionState('retrying');
  reconnectTimer = setTimeout(() => {
    reconnectTimer = null;
    void TelemetryService.connect();
  }, delay);
}

function publish(payload: TelemetryEvent) {
  subscribers.forEach((callback) => {
    try {
      callback(payload);
    } catch (error) {
      console.error('[TelemetryService] Subscriber callback failed', error);
    }
  });
}

export const TelemetryService = {
  subscribe(callback: TelemetryCallback) {
    subscribers.add(callback);
    return () => {
      subscribers.delete(callback);
    };
  },

  async connect() {
    shouldReconnect = true;
    if (connecting || (ws && ws.readyState !== WebSocket.CLOSED)) return;

    connecting = true;
    setConnectionState('connecting');
    let socket: WebSocket;
    let websocketSession: { token: string };
    try {
      const [socketURL, session] = await Promise.all([
        controlTransport.websocketURL('/ws'),
        controlTransport.websocketSession(),
      ]);
      websocketSession = session;
      if (!shouldReconnect) return;
      socket = new WebSocket(socketURL);
    } catch (error) {
      console.error('[TelemetryService] Could not open telemetry connection:', error);
      scheduleReconnect();
      return;
    } finally {
      connecting = false;
    }
    ws = socket;

    socket.onopen = () => {
      setConnectionState('authenticating');
      socket.send(JSON.stringify({ action: 'authenticate', token: websocketSession.token }));
    };

    socket.onmessage = (message) => {
      try {
        const raw: unknown = JSON.parse(String(message.data));
        const payload = parseTelemetryEvent(raw);
        reconnectAttempt = 0;
        setConnectionState('connected');
        publish(payload);

        if (payload.type === 'METRICS_UPDATE') {
          useSystemStore.getState().updateMetrics(
            payload.data.rx,
            payload.data.tx,
            payload.data.latency,
          );
        }
      } catch (error) {
        console.error('[TelemetryService] Rejected invalid telemetry frame', error);
      }
    };

    socket.onclose = () => {
      if (ws === socket) {
        ws = null;
      }
      scheduleReconnect();
    };

    socket.onerror = (error) => {
      console.error('[TelemetryService] WebSocket error observed:', error);
      socket.close();
    };
  },

  disconnect() {
    shouldReconnect = false;
    reconnectAttempt = 0;
    if (reconnectTimer !== null) {
      clearTimeout(reconnectTimer);
      reconnectTimer = null;
    }
    if (ws) {
      ws.close();
      ws = null;
    }
    setConnectionState('stopped');
  },
};
