export interface TransportTraceEvent {
  time: number | null;
  category: string;
  name: string;
  detail: string;
}

export interface TransportTraceSummary {
  format: 'qlog' | 'qlog-seq' | 'netlog' | 'generic';
  totalEvents: number;
  retainedEvents: TransportTraceEvent[];
  categories: Array<{ name: string; count: number }>;
  firstTime: number | null;
  lastTime: number | null;
}

const MAX_TRACE_TEXT_BYTES = 8 * 1024 * 1024;
const MAX_TRACE_EVENTS = 100_000;
const MAX_RETAINED_EVENTS = 500;
const MAX_DETAIL_CHARS = 320;

type RecordValue = Record<string, unknown>;

function isRecord(value: unknown): value is RecordValue {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function finiteNumber(value: unknown): number | null {
  if (typeof value === 'number' && Number.isFinite(value)) return value;
  if (typeof value === 'string' && value.trim() !== '') {
    const parsed = Number(value);
    return Number.isFinite(parsed) ? parsed : null;
  }
  return null;
}

function shortDetail(value: unknown): string {
  if (value === undefined || value === null) return '';
  let text: string;
  try {
    text = typeof value === 'string' ? value : JSON.stringify(value);
  } catch {
    text = String(value);
  }
  return text.length > MAX_DETAIL_CHARS ? `${text.slice(0, MAX_DETAIL_CHARS - 1)}…` : text;
}

function eventFromQlog(value: unknown): TransportTraceEvent | null {
  if (Array.isArray(value)) {
    if (value.length < 3) return null;
    return {
      time: finiteNumber(value[0]),
      category: typeof value[1] === 'string' ? value[1] : 'qlog',
      name: typeof value[2] === 'string' ? value[2] : 'event',
      detail: shortDetail(value[3]),
    };
  }
  if (!isRecord(value)) return null;
  const rawName = typeof value.name === 'string' ? value.name : (typeof value.type === 'string' ? value.type : 'event');
  const split = rawName.split(':', 2);
  return {
    time: finiteNumber(value.time ?? value.relative_time ?? value.timestamp),
    category: typeof value.category === 'string' ? value.category : (split.length === 2 ? split[0]! : 'qlog'),
    name: split.length === 2 ? split[1]! : rawName,
    detail: shortDetail(value.data ?? value),
  };
}

function collectQlogObject(root: RecordValue): { format: TransportTraceSummary['format']; events: unknown[] } {
  if (Array.isArray(root.traces)) {
    const events: unknown[] = [];
    outer: for (const rawTrace of root.traces) {
      if (!isRecord(rawTrace) || !Array.isArray(rawTrace.events)) continue;
      for (const event of rawTrace.events) {
        events.push(event);
        if (events.length > MAX_TRACE_EVENTS) break outer;
      }
    }
    return { format: 'qlog', events };
  }
  if (Array.isArray(root.events)) {
    const looksNetlog = isRecord(root.constants) || root.events.some((item) => isRecord(item) && ('source' in item || 'phase' in item));
    return { format: looksNetlog ? 'netlog' : 'generic', events: root.events.slice(0, MAX_TRACE_EVENTS + 1) };
  }
  return { format: 'generic', events: [] };
}

function reverseNumericConstants(root: RecordValue, key: string): Map<number, string> {
  const constants = isRecord(root.constants) ? root.constants : {};
  const values = isRecord(constants[key]) ? constants[key] : {};
  const out = new Map<number, string>();
  for (const [name, raw] of Object.entries(values)) {
    if (typeof raw === 'number' && Number.isFinite(raw)) out.set(raw, name);
  }
  return out;
}

function eventFromNetlog(value: unknown, eventTypes: Map<number, string>, sourceTypes: Map<number, string>, phases: Map<number, string>): TransportTraceEvent | null {
  if (!isRecord(value)) return null;
  const rawType = value.type;
  const typeName = typeof rawType === 'string'
    ? rawType
    : (typeof rawType === 'number' ? eventTypes.get(rawType) ?? `TYPE_${rawType}` : 'event');
  const source = isRecord(value.source) ? value.source : {};
  const sourceType = typeof source.type === 'number' ? sourceTypes.get(source.type) ?? `SOURCE_${source.type}` : 'netlog';
  const rawPhase = value.phase;
  const phaseName = typeof rawPhase === 'number' ? phases.get(rawPhase) : undefined;
  return {
    time: finiteNumber(value.time),
    category: sourceType,
    name: phaseName ? `${typeName} · ${phaseName}` : typeName,
    detail: shortDetail(value.params ?? value),
  };
}

function parseLineSequence(text: string): { format: 'qlog-seq'; events: unknown[] } | null {
  const lines = text.split(/\r?\n/).filter((line) => line.trim() !== '');
  if (lines.length < 2) return null;
  const events: unknown[] = [];
  let parsed = 0;
  for (const line of lines) {
    try {
      const value: unknown = JSON.parse(line);
      parsed++;
      if (isRecord(value) && ('qlog_version' in value || 'qlog_format' in value) && !('name' in value)) continue;
      events.push(value);
      if (events.length > MAX_TRACE_EVENTS) break;
    } catch {
      return null;
    }
  }
  return parsed > 1 ? { format: 'qlog-seq', events } : null;
}

export function parseTransportTrace(text: string): TransportTraceSummary {
  if (new TextEncoder().encode(text).byteLength > MAX_TRACE_TEXT_BYTES) {
    throw new Error(`trace exceeds ${MAX_TRACE_TEXT_BYTES} byte limit`);
  }
  let format: TransportTraceSummary['format'];
  let rawEvents: unknown[];
  try {
    const parsed: unknown = JSON.parse(text);
    if (!isRecord(parsed)) throw new Error('trace root must be a JSON object');
    ({ format, events: rawEvents } = collectQlogObject(parsed));
  } catch (error) {
    const sequence = parseLineSequence(text);
    if (!sequence) {
      throw new Error(`trace is not valid qlog/netlog JSON: ${error instanceof Error ? error.message : 'parse failed'}`);
    }
    format = sequence.format;
    rawEvents = sequence.events;
  }
  if (rawEvents.length > MAX_TRACE_EVENTS) {
    throw new Error(`trace contains more than ${MAX_TRACE_EVENTS} events`);
  }

  const retained: TransportTraceEvent[] = [];
  const counts = new Map<string, number>();
  let totalEvents = 0;
  let firstTime: number | null = null;
  let lastTime: number | null = null;
  let netlogEventTypes = new Map<number, string>();
  let netlogSourceTypes = new Map<number, string>();
  let netlogPhases = new Map<number, string>();
  if (format === 'netlog') {
    try {
      const root = JSON.parse(text) as unknown;
      if (isRecord(root)) {
        netlogEventTypes = reverseNumericConstants(root, 'logEventTypes');
        netlogSourceTypes = reverseNumericConstants(root, 'logSourceType');
        netlogPhases = reverseNumericConstants(root, 'logEventPhase');
      }
    } catch {
      // netlog is JSON-object based, so this only protects future format extensions.
    }
  }
  for (const raw of rawEvents) {
    const event = format === 'netlog'
      ? eventFromNetlog(raw, netlogEventTypes, netlogSourceTypes, netlogPhases)
      : eventFromQlog(raw);
    if (!event) continue;
    totalEvents++;
    counts.set(event.category, (counts.get(event.category) ?? 0) + 1);
    if (event.time !== null) {
      firstTime = firstTime === null ? event.time : Math.min(firstTime, event.time);
      lastTime = lastTime === null ? event.time : Math.max(lastTime, event.time);
    }
    if (retained.length < MAX_RETAINED_EVENTS) retained.push(event);
  }
  return {
    format,
    totalEvents,
    retainedEvents: retained,
    categories: [...counts.entries()].map(([name, count]) => ({ name, count })).sort((a, b) => b.count - a.count || a.name.localeCompare(b.name)),
    firstTime,
    lastTime,
  };
}
