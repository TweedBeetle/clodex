import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { spawnSync } from 'node:child_process';
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import forge from 'node-forge';
import { ensureHttpProxyCertificates } from '../src/http-proxy/ca.js';

// Python 3.13+ verifies with VERIFY_X509_STRICT; OpenSSL 3's -x509_strict is the same check.
// macOS ships LibreSSL as /usr/bin/openssl, so accept a binary only when it reports OpenSSL 3+.
const OPENSSL = ['/opt/homebrew/opt/openssl@3/bin/openssl', '/usr/local/opt/openssl@3/bin/openssl', '/usr/bin/openssl']
  .filter(existsSync)
  .find((bin) => /^OpenSSL [3-9]\./.test(spawnSync(bin, ['version'], { encoding: 'utf8' }).stdout ?? ''));

let home: string;
const previousHome = process.env['CLODEX_HOME'];
beforeEach(() => {
  home = mkdtempSync(join(tmpdir(), 'clodex-ca-'));
  process.env['CLODEX_HOME'] = home;
});
afterEach(() => {
  rmSync(home, { recursive: true, force: true });
  if (previousHome === undefined) delete process.env['CLODEX_HOME'];
  else process.env['CLODEX_HOME'] = previousHome;
});

const dir = () => join(home, 'http-proxy');

function akiMatchesCa(caPem: string, serverPem: string): boolean {
  const ca = forge.pki.certificateFromPem(caPem);
  const server = forge.pki.certificateFromPem(serverPem);
  const ski = (ca.getExtension('subjectKeyIdentifier') as { subjectKeyIdentifier: string }).subjectKeyIdentifier;
  const aki = server.getExtension('authorityKeyIdentifier') as { value: string } | null;
  // The extension value is DER: SEQUENCE { [0] keyIdentifier }; the id is its last 20 bytes.
  return !!aki && forge.util.bytesToHex(aki.value).endsWith(ski);
}

function strictVerify(): string {
  const r = spawnSync(OPENSSL!, ['verify', '-x509_strict', '-CAfile', join(dir(), 'clodex-ca.pem'),
    join(dir(), 'api.anthropic.com.pem')], { encoding: 'utf8' });
  return `${r.stdout}${r.stderr}`.trim();
}

describe('http proxy certificates', () => {
  it('issues a server certificate with an Authority Key Identifier', () => {
    const certs = ensureHttpProxyCertificates();
    expect(akiMatchesCa(certs.caCert, certs.serverCert)).toBe(true);
    expect(readFileSync(join(dir(), 'version'), 'utf8')).toBe('2\n');
  });

  it.skipIf(!OPENSSL)('passes strict X.509 verification', () => {
    ensureHttpProxyCertificates();
    expect(strictVerify()).toMatch(/: OK$/);
  });

  it('keeps a version-1 CA and reissues only the server certificate', () => {
    const first = ensureHttpProxyCertificates();
    writeFileSync(join(dir(), 'version'), '1\n');
    const caKeyBefore = readFileSync(join(dir(), 'clodex-ca-key.pem'), 'utf8');
    const second = ensureHttpProxyCertificates();
    expect(second.caCert).toBe(first.caCert);
    expect(readFileSync(join(dir(), 'clodex-ca-key.pem'), 'utf8')).toBe(caKeyBefore);
    expect(second.serverCert).not.toBe(first.serverCert);
    expect(akiMatchesCa(second.caCert, second.serverCert)).toBe(true);
    expect(readFileSync(join(dir(), 'version'), 'utf8')).toBe('2\n');
  });

  it('regenerates everything when the stored CA key does not match the CA', () => {
    const first = ensureHttpProxyCertificates();
    const other = forge.pki.rsa.generateKeyPair(1024);
    writeFileSync(join(dir(), 'clodex-ca-key.pem'), forge.pki.privateKeyToPem(other.privateKey));
    writeFileSync(join(dir(), 'version'), '1\n');
    const second = ensureHttpProxyCertificates();
    expect(second.caCert).not.toBe(first.caCert);
    expect(akiMatchesCa(second.caCert, second.serverCert)).toBe(true);
  });

  it('leaves a current version-2 store untouched', () => {
    const first = ensureHttpProxyCertificates();
    const second = ensureHttpProxyCertificates();
    expect(second.serverCert).toBe(first.serverCert);
    expect(second.caCert).toBe(first.caCert);
  });
});
