// src/http-proxy/secret-guard.ts — refuse to send local secret values to listed providers
//
// Opt-in, local-only hardening. When `<CLODEX_HOME>/secret-guard.json` exists, every
// translated request whose route provider is listed there is scanned before it leaves
// the proxy: if the decoded body contains the exact value of any watched secret file,
// the request is refused and nothing is sent upstream. The error names the file, never
// the value.
//
// Config shape:
//   {
//     "providers": ["custom-experiential", "custom-openrouter"],
//     "paths": ["~/keys/*.txt", "~/keys/admin/**"],
//     "minLength": 12
//   }
//
// Path patterns support `<dir>/*<suffix>` (one directory, files ending in suffix) and
// `<dir>/**` (every file below dir). Values are the trimmed file content plus each
// non-empty line, so multi-line files are covered either way. Values shorter than
// minLength are skipped (a 4-character value would match ordinary text). The body is
// checked for both the raw value and its JSON-escaped form.
//
// Fail closed: if the config exists but cannot be parsed, or a watched file cannot be
// read, requests to listed providers are refused until it can.

import { readFileSync, readdirSync, statSync, existsSync } from 'node:fs';
import { homedir } from 'node:os';
import { join, resolve } from 'node:path';
import { getAppHome } from '../paths.js';

export interface SecretGuardConfig {
  providers: string[];
  paths: string[];
  minLength?: number;
}

export type SecretGuardVerdict =
  | { allowed: true }
  | { allowed: false; reason: 'match'; file: string }
  | { allowed: false; reason: 'guard-error'; detail: string };

interface LoadedSecret {
  file: string;
  values: string[];
}

const RESCAN_INTERVAL_MS = 5_000;
// Measured 2026-10-14 over the 326 files under ~/keys/*.txt and ~/keys/admin/**: the only
// values under 12 characters were two public ids (7 and 10 chars) and a 7-char stub;
// the shortest password was 15. Raise or lower via "minLength" in the config.
const DEFAULT_MIN_LENGTH = 12;

function expandHome(path: string, home: string): string {
  return path === '~' ? home : path.startsWith('~/') ? join(home, path.slice(2)) : path;
}

function walk(dir: string, out: string[]): void {
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const full = join(dir, entry.name);
    if (entry.isDirectory()) walk(full, out);
    else if (entry.isFile()) out.push(full);
  }
}

/** Expand the supported patterns into concrete file paths. Missing directories are skipped. */
export function expandSecretPaths(patterns: string[], home = homedir()): string[] {
  const files: string[] = [];
  for (const raw of patterns) {
    const pattern = expandHome(raw, home);
    if (pattern.endsWith('/**')) {
      const dir = pattern.slice(0, -3);
      if (existsSync(dir)) walk(dir, files);
      continue;
    }
    const star = pattern.lastIndexOf('/*');
    if (star >= 0 && !pattern.slice(star + 2).includes('/')) {
      const dir = pattern.slice(0, star);
      const suffix = pattern.slice(star + 2);
      if (!existsSync(dir)) continue;
      for (const entry of readdirSync(dir, { withFileTypes: true })) {
        if (entry.isFile() && entry.name.endsWith(suffix)) files.push(join(dir, entry.name));
      }
      continue;
    }
    if (existsSync(pattern)) files.push(resolve(pattern));
  }
  return [...new Set(files)].sort();
}

/** The values a file contributes: trimmed content plus each non-empty trimmed line. */
export function secretValues(content: string, minLength: number): string[] {
  const values = new Set<string>();
  const whole = content.trim();
  if (whole.length >= minLength) values.add(whole);
  for (const line of content.split(/\r?\n/)) {
    const value = line.trim();
    if (value.length >= minLength) values.add(value);
  }
  return [...values];
}

function jsonEscaped(value: string): string {
  return JSON.stringify(value).slice(1, -1);
}

export class SecretGuard {
  private config: SecretGuardConfig | null = null;
  private configError: string | null = null;
  private configMtimeMs = -1;
  private secrets: LoadedSecret[] = [];
  private loadError: string | null = null;
  private fingerprint = '';
  private lastScanAt = 0;

  constructor(
    private readonly configPath = join(getAppHome(), 'secret-guard.json'),
    private readonly home = homedir(),
    private readonly now: () => number = Date.now,
  ) {}

  /** Whether requests to this provider are subject to the guard (config present and listing it). */
  appliesTo(provider: string): boolean {
    this.refresh(true);
    if (this.configError) return true;
    return this.config?.providers.includes(provider) ?? false;
  }

  check(provider: string, body: Buffer | string): SecretGuardVerdict {
    this.refresh(false);
    if (this.configError) return { allowed: false, reason: 'guard-error', detail: this.configError };
    if (!this.config?.providers.includes(provider)) return { allowed: true };
    if (this.loadError) return { allowed: false, reason: 'guard-error', detail: this.loadError };
    const text = typeof body === 'string' ? body : body.toString('utf8');
    for (const secret of this.secrets) {
      for (const value of secret.values) {
        if (text.includes(value) || text.includes(jsonEscaped(value))) {
          return { allowed: false, reason: 'match', file: secret.file };
        }
      }
    }
    return { allowed: true };
  }

  /** Number of watched files and values, for diagnostics. */
  stats(): { files: number; values: number } {
    this.refresh(false);
    return {
      files: this.secrets.length,
      values: this.secrets.reduce((n, s) => n + s.values.length, 0),
    };
  }

  private refresh(configOnly: boolean): void {
    // Config: re-read whenever its mtime changes (cheap stat per request).
    let mtime = -1;
    try {
      mtime = existsSync(this.configPath) ? statSync(this.configPath).mtimeMs : -1;
    } catch (error) {
      this.configError = `cannot stat ${this.configPath}: ${(error as Error).message}`;
      return;
    }
    if (mtime !== this.configMtimeMs) {
      this.configMtimeMs = mtime;
      this.lastScanAt = 0;
      if (mtime < 0) {
        this.config = null;
        this.configError = null;
      } else {
        try {
          const parsed = JSON.parse(readFileSync(this.configPath, 'utf8')) as SecretGuardConfig;
          if (!Array.isArray(parsed.providers) || !Array.isArray(parsed.paths)) {
            throw new Error('needs "providers" and "paths" arrays');
          }
          this.config = parsed;
          this.configError = null;
        } catch (error) {
          this.config = null;
          this.configError = `invalid ${this.configPath}: ${(error as Error).message}`;
        }
      }
    }
    if (configOnly || !this.config) return;

    // Secrets: re-list and re-stat at most every RESCAN_INTERVAL_MS; reload on any change.
    const now = this.now();
    if (now - this.lastScanAt < RESCAN_INTERVAL_MS && this.lastScanAt !== 0) return;
    this.lastScanAt = now;
    try {
      const files = expandSecretPaths(this.config.paths, this.home);
      const fingerprint = files
        .map(file => {
          const s = statSync(file);
          return `${file}:${s.mtimeMs}:${s.size}`;
        })
        .join('|');
      if (fingerprint === this.fingerprint && !this.loadError) return;
      const minLength = this.config.minLength ?? DEFAULT_MIN_LENGTH;
      this.secrets = files.map(file => ({
        file,
        values: secretValues(readFileSync(file, 'utf8'), minLength),
      }));
      this.fingerprint = fingerprint;
      this.loadError = null;
    } catch (error) {
      this.loadError = `cannot load watched secrets: ${(error as Error).message}`;
    }
  }
}

/** Display form of a watched file: home-relative when possible. */
export function displaySecretPath(file: string, home = homedir()): string {
  return file.startsWith(home + '/') ? '~/' + file.slice(home.length + 1) : file;
}
