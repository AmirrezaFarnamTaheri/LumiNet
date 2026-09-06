export type ConversionTarget = 'uri-list' | 'base64' | 'luminet-json' | 'clash-meta' | 'sing-box';

export interface ConversionIssue {
  index: number;
  name: string;
  protocol: string;
  severity: 'unsupported' | 'lossy' | 'warning';
  code: string;
  message: string;
}

export interface ConversionReport {
  sourceNodes: number;
  emittedNodes: number;
  unsupported: number;
  lossy: number;
  warnings: number;
  issues: ConversionIssue[];
}

export interface TransformReport {
  inputNodes: number;
  outputNodes: number;
  filtered: number;
  renamed: number;
  deduplicated: number;
  truncated: number;
}

export interface RoundTripIssue {
  index: number;
  code: string;
  message: string;
}

export interface RoundTripReport {
  attempted: boolean;
  compatible: boolean;
  sourceNodes: number;
  reparsedNodes: number;
  exactNodes: number;
  changedNodes: number;
  missingNodes: number;
  extraNodes: number;
  parserError: string;
  issues: RoundTripIssue[];
}

export interface ConversionResult {
  target: ConversionTarget;
  mimeType: string;
  content: string;
  report: ConversionReport;
  transformation?: TransformReport;
  roundTrip?: RoundTripReport;
}

type JsonRecord = Record<string, unknown>;

function record(value: unknown, label: string): JsonRecord {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) throw new Error(`expected ${label} object`);
  return value as JsonRecord;
}
function text(value: unknown, label: string, fallback = ''): string {
  if (value === undefined || value === null) return fallback;
  if (typeof value !== 'string') throw new Error(`expected ${label} string`);
  return value;
}
function integer(value: unknown, label: string): number {
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value < 0) throw new Error(`expected ${label} non-negative safe integer`);
  return value;
}
function boolean(value: unknown, label: string): boolean {
  if (typeof value !== 'boolean') throw new Error(`expected ${label} boolean`);
  return value;
}

export function parseConversionResult(value: unknown): ConversionResult {
  const root = record(value, 'conversion result');
  const target = text(root.target, 'conversion target') as ConversionTarget;
  if (!['uri-list', 'base64', 'luminet-json', 'clash-meta', 'sing-box'].includes(target)) throw new Error('unsupported conversion target in response');
  const rawReport = record(root.report, 'conversion report');
  if (!Array.isArray(rawReport.issues)) throw new Error('invalid conversion issues');
  const issues = rawReport.issues.map((raw, i): ConversionIssue => {
    const issue = record(raw, `conversion issue ${i}`);
    const severity = text(issue.severity, `conversion issue ${i}.severity`);
    if (!['unsupported', 'lossy', 'warning'].includes(severity)) throw new Error('invalid conversion issue severity');
    return {
      index: integer(issue.index, `conversion issue ${i}.index`),
      name: text(issue.name, `conversion issue ${i}.name`),
      protocol: text(issue.protocol, `conversion issue ${i}.protocol`),
      severity: severity as ConversionIssue['severity'],
      code: text(issue.code, `conversion issue ${i}.code`),
      message: text(issue.message, `conversion issue ${i}.message`),
    };
  });
  let transformation: TransformReport | undefined;
  if (root.transformation !== undefined && root.transformation !== null) {
    const rawTransform = record(root.transformation, 'transformation report');
    transformation = {
      inputNodes: integer(rawTransform.input_nodes, 'transformation input_nodes'),
      outputNodes: integer(rawTransform.output_nodes, 'transformation output_nodes'),
      filtered: integer(rawTransform.filtered, 'transformation filtered'),
      renamed: integer(rawTransform.renamed, 'transformation renamed'),
      deduplicated: integer(rawTransform.deduplicated, 'transformation deduplicated'),
      truncated: integer(rawTransform.truncated, 'transformation truncated'),
    };
  }
  let roundTrip: RoundTripReport | undefined;
  if (root.round_trip !== undefined && root.round_trip !== null) {
    const rawRoundTrip = record(root.round_trip, 'round-trip report');
    if (!Array.isArray(rawRoundTrip.issues)) throw new Error('invalid round-trip issues');
    roundTrip = {
      attempted: boolean(rawRoundTrip.attempted, 'round-trip attempted'),
      compatible: boolean(rawRoundTrip.compatible, 'round-trip compatible'),
      sourceNodes: integer(rawRoundTrip.source_nodes, 'round-trip source_nodes'),
      reparsedNodes: integer(rawRoundTrip.reparsed_nodes, 'round-trip reparsed_nodes'),
      exactNodes: integer(rawRoundTrip.exact_nodes, 'round-trip exact_nodes'),
      changedNodes: integer(rawRoundTrip.changed_nodes, 'round-trip changed_nodes'),
      missingNodes: integer(rawRoundTrip.missing_nodes, 'round-trip missing_nodes'),
      extraNodes: integer(rawRoundTrip.extra_nodes, 'round-trip extra_nodes'),
      parserError: text(rawRoundTrip.parser_error, 'round-trip parser_error'),
      issues: rawRoundTrip.issues.map((raw, i): RoundTripIssue => {
        const issue = record(raw, `round-trip issue ${i}`);
        return {
          index: integer(issue.index, `round-trip issue ${i}.index`),
          code: text(issue.code, `round-trip issue ${i}.code`),
          message: text(issue.message, `round-trip issue ${i}.message`),
        };
      }),
    };
  }
  return {
    target,
    mimeType: text(root.mime_type, 'conversion mime_type'),
    content: text(root.content, 'conversion content'),
    report: {
      sourceNodes: integer(rawReport.source_nodes, 'conversion source_nodes'),
      emittedNodes: integer(rawReport.emitted_nodes, 'conversion emitted_nodes'),
      unsupported: integer(rawReport.unsupported, 'conversion unsupported'),
      lossy: integer(rawReport.lossy, 'conversion lossy'),
      warnings: integer(rawReport.warnings, 'conversion warnings'),
      issues,
    },
    ...(transformation !== undefined ? { transformation } : {}),
    ...(roundTrip !== undefined ? { roundTrip } : {}),
  };
}
