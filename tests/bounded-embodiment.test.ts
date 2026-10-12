import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { parseResults, text, utcMinute } from '../src/lib/bounded-embodiment';

const DATA = join(__dirname, '..', 'src', 'data', 'bounded-embodiment');
const source = JSON.parse(readFileSync(join(DATA, 'source.json'), 'utf8'));
const sha256 = (name: string) => createHash('sha256').update(readFileSync(join(DATA, name))).digest('hex');

describe('vendored Bounded Embodiment documents', () => {
  it('serves method v0.1 byte for byte: the text whose SHA-256 the method cites', () => {
    const METHOD_V01 = 'ff5b502e542bf14456a2a23c4c1b3fe9f68ccada0162d1052857bab53254c4a5';
    expect(sha256('method-v0.1.md')).toBe(METHOD_V01);
    expect(source.method.text_sha256).toBe(`sha256:${METHOD_V01}`);
    expect(source.files['method-v0.1.md'].sha256).toBe(METHOD_V01);
  });

  it('records the commit and hash each vendored file was copied at', () => {
    const names = Object.keys(source.files).sort();
    expect(names).toEqual(['accuracy-survey.md', 'lab-guide.md', 'method-v0.1.md']);
    for (const name of names) {
      const entry = source.files[name];
      expect(entry.commit).toMatch(/^[0-9a-f]{40}$/);
      expect(entry.sha256, `${name}: re-copy it from ${entry.path} and update source.json`).toBe(sha256(name));
    }
  });
});

const row = (over: Record<string, unknown> = {}) => ({
  result_id: 'lab-a/ev03-20261013T170000Z-s7',
  path: 'results/lab-a/ev03-20261013T170000Z-s7',
  test: 'ev03',
  verdict: 'FAIL',
  withdrawn: false,
  role: 'control',
  lab: 'lab-a',
  lab_name: 'Lab A',
  maintainers_own: false,
  identity_level: 'self-asserted',
  instrument: 'external: optical tracker',
  control: '-',
  reproduction: '-',
  reproduces: null,
  core_version: '0.1.0',
  method_version: '0.1',
  started_at: '2026-10-13T17:00:00.123456Z',
  ...over,
});

const payload = (rows: unknown[], over: Record<string, unknown> = {}) => ({
  title: 'Bounded Embodiment results',
  statement: 'Each row is one run.',
  notes: 'Lab identity is self-asserted.',
  repository: 'RobotRegistryFoundation/bounded-embodiment-results',
  source_commit: 'a'.repeat(40),
  rows,
  skipped: [],
  ...over,
});

describe('results.json from build_table.py', () => {
  it('reads a row as build_table.py writes it', () => {
    const table = parseResults(payload([row()]));
    expect(table?.sourceCommit).toBe('a'.repeat(40));
    expect(table?.rows).toEqual([
      expect.objectContaining({
        resultId: 'lab-a/ev03-20261013T170000Z-s7',
        runUrl:
          'https://github.com/RobotRegistryFoundation/bounded-embodiment-results/tree/main/results/lab-a/ev03-20261013T170000Z-s7',
        verdict: 'FAIL',
        role: 'control',
        when: '2026-10-13 17:00',
      }),
    ]);
  });

  it('makes no link from a value it does not recognise', () => {
    const table = parseResults(
      payload([row({ path: 'javascript:alert(1)' }), row({ path: '../../x' })], {
        repository: 'evil.example/../x',
        source_commit: 'not-a-sha',
      }),
    );
    expect(table?.repository).toBe('RobotRegistryFoundation/bounded-embodiment-results');
    expect(table?.sourceCommit).toBeNull();
    expect(table?.rows.map((r) => r.runUrl)).toEqual([null, null]);
  });

  it('shows unknown verdicts and roles as unknown, and drops rows without an id', () => {
    const table = parseResults(payload([row({ verdict: 'CERTIFIED', role: 'admin' }), { path: 'x' }, 'row', null]));
    expect(table?.rows.map((r) => [r.verdict, r.role])).toEqual([['unknown', 'unknown']]);
    expect(table?.dropped).toBe(3);
  });

  it('refuses a payload without rows', () => {
    expect(parseResults(undefined)).toBeNull();
    expect(parseResults({ rows: 'none' })).toBeNull();
    expect(parseResults([])).toBeNull();
  });

  it('converts start times to UTC minutes as build_table.py does', () => {
    expect(utcMinute('2026-10-13T17:00:59Z')).toBe('2026-10-13 17:00');
    expect(utcMinute('2026-10-13T10:30:00-07:00')).toBe('2026-10-13 17:30');
    expect(utcMinute('2026-10-14T01:15:00+08:45')).toBe('2026-10-13 16:30');
    expect(utcMinute('2026-02-30T10:00:00Z')).toBeNull();
    expect(utcMinute('0099-01-01T00:00:00Z')).toBe('0099-01-01 00:00');
    expect(utcMinute('0000-01-01T00:00:00Z')).toBeNull();
    expect(utcMinute('2026-10-13T24:00:00Z')).toBeNull();
    expect(utcMinute('2026-10-13 17:00:00')).toBeNull();
    expect(parseResults(payload([row({ started_at: 'yesterday' })]))?.rows[0].when).toBe('yesterday');
    expect(parseResults(payload([row({ started_at: 12 })]))?.rows[0].when).toBe('?');
  });

  it('keeps text to one short line', () => {
    expect(text('a\nb\u0007c')).toBe('a b c');
    expect(text('x'.repeat(200), 10)).toBe('xxxxxxx...');
    expect(text(5)).toBe('');
  });
});
