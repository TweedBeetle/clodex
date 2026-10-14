import { afterAll, describe, expect, it, vi } from 'vitest';
import net from 'node:net';
import tls from 'node:tls';
import { once } from 'node:events';
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

// The guard reads <CLODEX_HOME>/secret-guard.json, and the proxy builds its guard at import.
const home = vi.hoisted(() => {
  const { mkdtempSync: mk } = require('node:fs') as typeof import('node:fs');
  const { tmpdir: td } = require('node:os') as typeof import('node:os');
  const { join: j } = require('node:path') as typeof import('node:path');
  const dir = mk(j(td(), 'sandbox-only-'));
  process.env.CLODEX_HOME = dir;
  return dir;
});

vi.mock('../src/provider-factory.js', async original => ({
  ...await original<typeof import('../src/provider-factory.js')>(),
  createLanguageModel: vi.fn(async (spec: unknown) => ({ spec })),
}));
vi.mock('../src/sdk-adapter.js', async original => ({
  ...await original<typeof import('../src/sdk-adapter.js')>(),
  generateAnthropicResponse: vi.fn(async (_model: unknown, _params: unknown, model: string) => ({
    id: 'msg_test', type: 'message', role: 'assistant', model,
    content: [{ type: 'text', text: 'ok' }], stop_reason: 'end_turn',
    usage: { input_tokens: 1, output_tokens: 1 },
  })),
}));

import { buildHttpProxyRoutes } from '../src/http-proxy/routes.js';
import { buildConfiguredHttpProxyOptions } from '../src/http-proxy/index.js';
import { startHttpProxy } from '../src/http-proxy/server.js';
import { ensureHttpProxyCertificates } from '../src/http-proxy/ca.js';
import { generateAnthropicResponse } from '../src/sdk-adapter.js';
import type { LocalProvider } from '../src/types.js';

const TOKEN = 'sbx-token-0123456789abcdef0123';
writeFileSync(join(home, 'sandbox-token'), TOKEN);
writeFileSync(join(home, 'secret-guard.json'), JSON.stringify({
  providers: ['custom-sbx', 'custom-zdr'],
  paths: [join(home, 'nokeys', '*.txt')],
  sandboxOnly: ['custom-sbx'],
  sandboxTokenFile: join(home, 'sandbox-token'),
}));
afterAll(() => rmSync(home, { recursive: true, force: true }));

const model = (id: string) => ({
  id, upstreamModelId: id, name: id, family: 'glm', brand: 'Z', modelFormat: 'openai' as const,
  npm: '@ai-sdk/openai-compatible', contextWindow: 200_000,
});
const providers: LocalProvider[] = [
  { id: 'custom-sbx', name: 'Sandbox-only', apiKey: 'k', baseURL: 'https://example.invalid/v1', models: [model('m-sbx')] },
  { id: 'custom-zdr', name: 'Allowed', apiKey: 'k', baseURL: 'https://example.invalid/v1', models: [model('m-zdr')] },
] as LocalProvider[];
const favorites = providers.map(p => ({ providerId: p.id, modelId: p.models[0]!.id }));
const aliases = [
  { name: 'sbx', providerId: 'custom-sbx', modelId: 'm-sbx' },
  { name: 'zdr', providerId: 'custom-zdr', modelId: 'm-zdr' },
];

/** One request through CONNECT + TLS MITM, optionally with the sandbox marker on the CONNECT. */
async function mitmPost(port: number, alias: string, marker?: string): Promise<{ status: number; body: string }> {
  const socket = net.connect(port, '127.0.0.1');
  socket.setTimeout(5000, () => socket.destroy(new Error(`timed out for ${alias}`)));
  await once(socket, 'connect');
  socket.write('CONNECT api.anthropic.com:443 HTTP/1.1\r\nHost: api.anthropic.com:443\r\n'
    + (marker ? `X-Clx-Sandbox: ${marker}\r\n` : '') + '\r\n');
  let head = Buffer.alloc(0);
  while (!head.includes(Buffer.from('\r\n\r\n'))) {
    const [chunk] = await once(socket, 'data') as [Buffer];
    head = Buffer.concat([head, chunk]);
  }
  const secure = tls.connect({ socket, servername: 'api.anthropic.com', ca: ensureHttpProxyCertificates().caCert });
  await once(secure, 'secureConnect');
  let text = '';
  secure.on('data', chunk => {
    text += chunk;
    const split = text.indexOf('\r\n\r\n');
    if (split < 0) return;
    const length = /content-length: (\d+)/i.exec(text.slice(0, split));
    const complete = length
      ? Buffer.byteLength(text.slice(split + 4)) >= Number(length[1])
      : text.endsWith('\r\n0\r\n\r\n');
    if (complete) secure.destroy();
  });
  const body = JSON.stringify({ model: alias, max_tokens: 16, stream: false, messages: [{ role: 'user', content: 'hi' }] });
  secure.write('POST /v1/messages HTTP/1.1\r\nHost: api.anthropic.com\r\nContent-Type: application/json\r\n'
    + `Content-Length: ${Buffer.byteLength(body)}\r\nConnection: close\r\n\r\n${body}`);
  await once(secure, 'close');
  return { status: Number(/^HTTP\/1\.1 (\d+)/.exec(text)?.[1]), body: text.slice(text.indexOf('\r\n\r\n') + 4) };
}

describe('sandbox-only providers in proxy mode', () => {
  it('serve only tunnels opened with the sandbox token; other providers are unaffected', async () => {
    const loaded = { ...buildHttpProxyRoutes(providers, favorites, aliases), favoriteCount: favorites.length };
    const proxy = await startHttpProxy(buildConfiguredHttpProxyOptions(loaded, 0));
    try {
      const plain = await mitmPost(proxy.port, 'sbx');
      expect(plain.status).toBe(400);
      expect(plain.body).toContain('custom-sbx is for sandbox sessions only');

      const wrong = await mitmPost(proxy.port, 'sbx', TOKEN + 'x');
      expect(wrong.status).toBe(400);
      expect(vi.mocked(generateAnthropicResponse)).not.toHaveBeenCalled();

      expect((await mitmPost(proxy.port, 'sbx', TOKEN)).status).toBe(200);
      expect((await mitmPost(proxy.port, 'zdr')).status).toBe(200);
      expect(vi.mocked(generateAnthropicResponse)).toHaveBeenCalledTimes(2);
    } finally {
      await proxy.close();
    }
  });
});
