export interface InterruptedJobSummary {
  id: string;
  type: string;
  status: string;
  error: string;
  recoveredFrom: string;
}

export interface RecoveryInfo {
  jobID: string;
  jobType: string;
  interrupted: boolean;
  reconstructible: boolean;
  requiresConfirmation: boolean;
  requeueAvailable: boolean;
  activeDescendant: string;
  policy: string;
  reason: string;
}

export interface RecoveryRequeueResult {
  jobID: string;
  recoveredFrom: string;
  status: string;
  policy: string;
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
function bool(value: unknown, label: string, fallback = false): boolean {
  if (value === undefined || value === null) return fallback;
  if (typeof value !== 'boolean') throw new Error(`expected ${label} boolean`);
  return value;
}
function field(r: JsonRecord, lower: string, upper: string): unknown {
  return r[lower] !== undefined ? r[lower] : r[upper];
}

export function parseInterruptedJobHistory(value: unknown): InterruptedJobSummary[] {
  const root = record(value, 'history');
  if (!Array.isArray(root.jobs)) throw new Error('expected history jobs array');
  const jobs = root.jobs.map((raw, index): InterruptedJobSummary => {
    const job = record(raw, `history job ${index}`);
    return {
      id: text(field(job, 'id', 'ID'), `history job ${index}.id`),
      type: text(field(job, 'type', 'Type'), `history job ${index}.type`),
      status: text(field(job, 'status', 'Status'), `history job ${index}.status`),
      error: text(field(job, 'error', 'Error'), `history job ${index}.error`),
      recoveredFrom: text(field(job, 'recovered_from', 'RecoveredFrom'), `history job ${index}.recovered_from`),
    };
  });
  return jobs.filter((job) => job.status === 'failed' && job.error === 'server restarted');
}

export function parseRecoveryInfo(value: unknown): RecoveryInfo {
  const r = record(value, 'recovery info');
  return {
    jobID: text(r.job_id, 'recovery job_id'),
    jobType: text(r.job_type, 'recovery job_type'),
    interrupted: bool(r.interrupted, 'recovery interrupted'),
    reconstructible: bool(r.reconstructible, 'recovery reconstructible'),
    requiresConfirmation: bool(r.requires_confirmation, 'recovery requires_confirmation'),
    requeueAvailable: bool(r.requeue_available, 'recovery requeue_available'),
    activeDescendant: text(r.active_descendant, 'recovery active_descendant'),
    policy: text(r.policy, 'recovery policy'),
    reason: text(r.reason, 'recovery reason'),
  };
}

export function parseRecoveryRequeueResult(value: unknown): RecoveryRequeueResult {
  const r = record(value, 'recovery requeue result');
  return {
    jobID: text(r.job_id, 'requeue job_id'),
    recoveredFrom: text(r.recovered_from, 'requeue recovered_from'),
    status: text(r.status, 'requeue status'),
    policy: text(r.policy, 'requeue policy'),
  };
}
