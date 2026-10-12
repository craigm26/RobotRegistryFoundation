/**
 * Data for the /bounded-embodiment/ pages.
 *
 * The method text and the two guides are vendored byte for byte from
 * RobotRegistryFoundation/bounded-embodiment (src/data/bounded-embodiment/source.json records
 * the commit and SHA-256 of each; tests/bounded-embodiment.test.ts checks them).
 *
 * results.json is written at deploy time by the results repository's tools/build_table.py
 * (.github/workflows/deploy.yml). It comes from another repository, so parseResults() checks
 * every field before a page uses it: an unexpected value is shown as text or dropped, and a
 * link is made only from a value that matches the shape build_table.py writes.
 */

export const RESULTS_REPOSITORY = 'RobotRegistryFoundation/bounded-embodiment-results';
export const MAINTAINER_LABEL = "maintainer's own";
export const COLUMNS = [
  'Run (UTC)',
  'Test',
  'Verdict',
  'Role',
  'Lab',
  'Identity',
  'Instrument',
  'Control',
  'Reproduction',
  'Core',
  'Method',
] as const;

const VERDICTS = new Set(['PASS', 'FAIL', 'INCONCLUSIVE']);
const ROLES = new Set(['test', 'control', 'rehearsal']);
const REPOSITORY_RE = /^[A-Za-z0-9-]+\/[A-Za-z0-9._-]+$/;
const SHA_RE = /^[0-9a-f]{40}$/;
const RUN_PATH_RE =
  /^results\/[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?\/[a-z0-9]+-\d{8}T\d{6}Z-s\d{1,20}$/;
const ISO_RE = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d+))?(Z|[+-]\d{2}:\d{2})$/;
// Control characters (C0 and DEL), as build_table.py strips them.
const CONTROL_CHARS = /[\u0000-\u001f\u007f]/g;

export interface ResultRow {
  resultId: string;
  /** The run's directory on GitHub, or null when its path is not one build_table.py writes. */
  runUrl: string | null;
  test: string;
  /** PASS, FAIL or INCONCLUSIVE; anything else reads "unknown". */
  verdict: string;
  withdrawn: boolean;
  role: string;
  lab: string;
  labName: string;
  maintainersOwn: boolean;
  identityLevel: string;
  instrument: string;
  control: string;
  reproduction: string;
  coreVersion: string;
  methodVersion: string;
  /** The run's start, "YYYY-MM-DD HH:MM" in UTC, or the reported text when it does not parse. */
  when: string;
}

export interface ResultsTable {
  statement: string;
  notes: string;
  repository: string;
  sourceCommit: string | null;
  rows: ResultRow[];
  /** Rows left out because they were not objects or had no result id. */
  dropped: number;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

/** A short single-line string from a JSON value; "" for anything that is not a string. */
export function text(value: unknown, limit = 120): string {
  if (typeof value !== 'string') return '';
  const out = value.replace(CONTROL_CHARS, ' ').trim();
  return out.length <= limit ? out : `${out.slice(0, limit - 3)}...`;
}

/** An ISO 8601 time with a zone as UTC "YYYY-MM-DD HH:MM", or null when it is not one. */
export function utcMinute(value: unknown): string | null {
  if (typeof value !== 'string') return null;
  const m = ISO_RE.exec(value);
  if (!m) return null;
  const [, y, mo, d, h, mi, s, frac, zone] = m;
  const [year, month, day, hour, minute, second] = [y, mo, d, h, mi, s].map(Number);
  const ms = Number((frac ?? '0').slice(0, 3).padEnd(3, '0'));
  if (year < 1) return null; // Python's datetime starts at year 1
  // setUTCFullYear, unlike Date.UTC, keeps years below 100 as written.
  const local = new Date(0);
  local.setUTCFullYear(year, month - 1, day);
  local.setUTCHours(hour, minute, second, ms);
  // A date that rolled over (30 February, hour 24, second 60) is not one: refuse it, as Python does.
  if (
    local.getUTCFullYear() !== year ||
    local.getUTCMonth() !== month - 1 ||
    local.getUTCDate() !== day ||
    local.getUTCHours() !== hour ||
    local.getUTCMinutes() !== minute ||
    local.getUTCSeconds() !== second
  ) {
    return null;
  }
  let offsetMinutes = 0;
  if (zone !== 'Z') {
    const sign = zone[0] === '+' ? 1 : -1;
    offsetMinutes = sign * (Number(zone.slice(1, 3)) * 60 + Number(zone.slice(4, 6)));
  }
  const utc = new Date(local.getTime() - offsetMinutes * 60_000);
  const pad = (n: number) => String(n).padStart(2, '0');
  return (
    `${String(utc.getUTCFullYear()).padStart(4, '0')}-${pad(utc.getUTCMonth() + 1)}-` +
    `${pad(utc.getUTCDate())} ${pad(utc.getUTCHours())}:${pad(utc.getUTCMinutes())}`
  );
}

function parseRow(raw: unknown, repository: string): ResultRow | null {
  if (!isRecord(raw)) return null;
  const resultId = text(raw.result_id, 200);
  if (!resultId) return null;
  const path = typeof raw.path === 'string' && RUN_PATH_RE.test(raw.path) ? raw.path : null;
  const verdict = text(raw.verdict, 20);
  const role = text(raw.role, 20);
  const startedAt = text(raw.started_at, 40);
  return {
    resultId,
    runUrl: path ? `https://github.com/${repository}/tree/main/${path}` : null,
    test: text(raw.test, 40) || '?',
    verdict: VERDICTS.has(verdict) ? verdict : 'unknown',
    withdrawn: raw.withdrawn === true,
    role: ROLES.has(role) ? role : 'unknown',
    lab: text(raw.lab, 64),
    labName: text(raw.lab_name, 80),
    maintainersOwn: raw.maintainers_own === true,
    identityLevel: text(raw.identity_level, 40),
    instrument: text(raw.instrument, 80),
    control: text(raw.control, 80) || '-',
    reproduction: text(raw.reproduction, 200) || '-',
    coreVersion: text(raw.core_version, 40) || '?',
    methodVersion: text(raw.method_version, 40) || '?',
    when: utcMinute(raw.started_at) ?? (startedAt || '?'),
  };
}

/** The table from build_table.py's results.json, or null when the payload is not one. */
export function parseResults(payload: unknown): ResultsTable | null {
  if (!isRecord(payload) || !Array.isArray(payload.rows)) return null;
  const repository =
    typeof payload.repository === 'string' && REPOSITORY_RE.test(payload.repository)
      ? payload.repository
      : RESULTS_REPOSITORY;
  const rows: ResultRow[] = [];
  let dropped = 0;
  for (const raw of payload.rows) {
    const row = parseRow(raw, repository);
    if (row) rows.push(row);
    else dropped += 1;
  }
  return {
    statement: text(payload.statement, 2000),
    notes: text(payload.notes, 2000),
    repository,
    sourceCommit:
      typeof payload.source_commit === 'string' && SHA_RE.test(payload.source_commit)
        ? payload.source_commit
        : null,
    rows,
    dropped,
  };
}
