import { describe, expect, it } from 'vitest';
import { mkdtempSync, mkdirSync, writeFileSync, rmSync, utimesSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { SecretGuard, expandSecretPaths, secretValues } from '../src/http-proxy/secret-guard.js';

function setup(config?: unknown) {
  const home = mkdtempSync(join(tmpdir(), 'secret-guard-'));
  mkdirSync(join(home, 'keys', 'admin', 'nested'), { recursive: true });
  writeFileSync(join(home, 'keys', 'PLANTED_API_KEY.txt'), 'sk-planted-0123456789abcdef');
  writeFileSync(join(home, 'keys', 'SHORT_ID.txt'), '1234567');
  writeFileSync(join(home, 'keys', 'notes.md'), 'not-a-keyfile-value-abcdef');
  writeFileSync(join(home, 'keys', 'admin', 'nested', 'ADMIN.json'), '{"x":1}\nadmin-secret-value-xyz987\n');
  const configPath = join(home, 'secret-guard.json');
  if (config !== undefined) {
    writeFileSync(configPath, typeof config === 'string' ? config : JSON.stringify(config));
  }
  let now = 1_000_000;
  const guard = new SecretGuard(configPath, home, () => now);
  return {
    home,
    configPath,
    guard,
    advance: (ms: number) => { now += ms; },
    cleanup: () => rmSync(home, { recursive: true, force: true }),
  };
}

const CONFIG = {
  providers: ['custom-experiential'],
  paths: ['~/keys/*.txt', '~/keys/admin/**'],
};

const body = (text: string) => Buffer.from(JSON.stringify({ messages: [{ role: 'user', content: text }] }));

describe('secret guard', () => {
  it('is inert without a config file', () => {
    const t = setup();
    expect(t.guard.appliesTo('custom-experiential')).toBe(false);
    expect(t.guard.check('custom-experiential', body('sk-planted-0123456789abcdef'))).toEqual({ allowed: true });
    t.cleanup();
  });

  it('refuses a planted value and names the file, not the value', () => {
    const t = setup(CONFIG);
    expect(t.guard.appliesTo('custom-experiential')).toBe(true);
    const verdict = t.guard.check('custom-experiential', body('here: sk-planted-0123456789abcdef ok'));
    expect(verdict).toEqual({ allowed: false, reason: 'match', file: join(t.home, 'keys', 'PLANTED_API_KEY.txt') });
    expect(JSON.stringify(verdict)).not.toContain('sk-planted');
    t.cleanup();
  });

  it('covers nested admin files line by line', () => {
    const t = setup(CONFIG);
    const verdict = t.guard.check('custom-experiential', body('cat said admin-secret-value-xyz987'));
    expect(verdict).toMatchObject({ allowed: false, reason: 'match' });
    t.cleanup();
  });

  it('matches the JSON-escaped form of a value', () => {
    const t = setup(CONFIG);
    writeFileSync(join(t.home, 'keys', 'QUOTED.txt'), 'pa"ss\\word-with-quotes');
    t.advance(10_000);
    const raw = Buffer.from(JSON.stringify({ content: 'x pa"ss\\word-with-quotes y' }));
    expect(t.guard.check('custom-experiential', raw)).toMatchObject({ allowed: false, reason: 'match' });
    t.cleanup();
  });

  it('allows clean bodies, unlisted providers, short values and non-matching suffixes', () => {
    const t = setup(CONFIG);
    expect(t.guard.check('custom-experiential', body('nothing secret here'))).toEqual({ allowed: true });
    expect(t.guard.check('openai-oauth', body('sk-planted-0123456789abcdef'))).toEqual({ allowed: true });
    expect(t.guard.check('custom-experiential', body('id 1234567'))).toEqual({ allowed: true });
    expect(t.guard.check('custom-experiential', body('not-a-keyfile-value-abcdef'))).toEqual({ allowed: true });
    t.cleanup();
  });

  it('picks up a new keyfile after the rescan interval', () => {
    const t = setup(CONFIG);
    expect(t.guard.check('custom-experiential', body('fresh-secret-value-000111'))).toEqual({ allowed: true });
    writeFileSync(join(t.home, 'keys', 'FRESH.txt'), 'fresh-secret-value-000111');
    t.advance(6_000);
    expect(t.guard.check('custom-experiential', body('fresh-secret-value-000111'))).toMatchObject({ allowed: false });
    t.cleanup();
  });

  it('fails closed on an unparseable config, for every provider', () => {
    const t = setup('{not json');
    expect(t.guard.appliesTo('anything')).toBe(true);
    expect(t.guard.check('anything', body('hello'))).toMatchObject({ allowed: false, reason: 'guard-error' });
    t.cleanup();
  });

  it('reloads the config when it changes', () => {
    const t = setup(CONFIG);
    expect(t.guard.appliesTo('custom-openrouter')).toBe(false);
    writeFileSync(t.configPath, JSON.stringify({ ...CONFIG, providers: ['custom-openrouter'] }));
    utimesSync(t.configPath, new Date(), new Date(Date.now() + 5_000));
    expect(t.guard.appliesTo('custom-openrouter')).toBe(true);
    t.cleanup();
  });

  it('expands patterns and splits values', () => {
    const t = setup();
    const files = expandSecretPaths(['~/keys/*.txt', '~/keys/admin/**', '~/missing/*.txt'], t.home);
    expect(files.map(f => f.slice(t.home.length))).toEqual([
      '/keys/PLANTED_API_KEY.txt',
      '/keys/SHORT_ID.txt',
      '/keys/admin/nested/ADMIN.json',
    ]);
    expect(secretValues('  line-one-value-123\n\nline-two-value-456\n', 12)).toEqual([
      'line-one-value-123\n\nline-two-value-456',
      'line-one-value-123',
      'line-two-value-456',
    ]);
    t.cleanup();
  });
});
