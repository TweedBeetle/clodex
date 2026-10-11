import { describe, it, expect, vi, afterEach } from 'vitest';
import http from 'node:http';
import { startProxyCatalog, type ProxyRoute } from '../src/proxy.js';
import { isUnpinnedGoRelayRoute } from '../src/unpinned-host-guard.js';

function post(port: number, token: string, body: unknown, extra: Record<string, string> = {}, path = '/v1/messages') {
  return new Promise<{ status: number; body: string }>((resolve, reject) => {
    const payload = JSON.stringify(body);
    const req = http.request({
      hostname: '127.0.0.1', port, path, method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${token}`,
        'anthropic-version': '2023-06-01',
        'Content-Length': Buffer.byteLength(payload),
        ...extra,
      },
    }, (res) => {
      let data = '';
      res.on('data', (c) => { data += c; });
      res.on('end', () => resolve({ status: res.statusCode ?? 0, body: data }));
    });
    req.on('error', reject);
    req.write(payload);
    req.end();
  });
}

const goRoute = (realModelId: string, modelFormat: 'openai' | 'anthropic'): ProxyRoute => ({
  aliasId: `anthropic-opencode-go__${realModelId}`,
  realModelId,
  displayName: realModelId,
  upstreamUrl: modelFormat === 'anthropic' ? 'https://opencode.ai/zen/go' : '',
  apiKey: 'key',
  modelFormat,
  npm: modelFormat === 'anthropic' ? undefined : 'missing-sdk-provider-for-test',
  baseURL: 'https://opencode.ai/zen/go/v1',
  providerId: 'opencode-go',
});

const body = (model: string) => ({ model, max_tokens: 10, stream: false, messages: [{ role: 'user', content: 'hi' }] });

async function send(route: ProxyRoute, extra: Record<string, string> = {}, path?: string) {
  const handle = await startProxyCatalog([route], route.aliasId, false);
  try {
    return await post(handle.port, handle.token, body(route.aliasId), extra, path);
  } finally {
    handle.close();
  }
}

describe('unpinned OpenCode Go relay guard', () => {
  afterEach(() => vi.unstubAllGlobals());

  it('classifies only Go DeepSeek models on a non-Anthropic route', () => {
    expect(isUnpinnedGoRelayRoute(goRoute('deepseek-v4.1-flash', 'openai'))).toBe(true);
    expect(isUnpinnedGoRelayRoute(goRoute('deepseek-v4-pro', 'openai'))).toBe(true);
    expect(isUnpinnedGoRelayRoute(goRoute('deepseek-v4.1-flash', 'anthropic'))).toBe(false);
    expect(isUnpinnedGoRelayRoute(goRoute('muse-spark-1.3-contributor', 'openai'))).toBe(false);
    expect(isUnpinnedGoRelayRoute({ ...goRoute('deepseek-v4.1-flash', 'openai'), providerId: 'fireworks' })).toBe(false);
  });

  it('refuses a translated Go DeepSeek request without calling the upstream', async () => {
    const fetchMock = vi.fn();
    vi.stubGlobal('fetch', fetchMock);
    const res = await send(goRoute('deepseek-v4.1-flash', 'openai'));
    expect(res.status).toBe(400);
    expect(JSON.parse(res.body).error.message).toMatch(/relay hosts nobody chose/);
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it('lets an opted-in request through to the translated path', async () => {
    const fetchMock = vi.fn();
    vi.stubGlobal('fetch', fetchMock);
    const res = await send(goRoute('deepseek-v4.1-flash', 'openai'), { 'x-clx-unpinned-host-ok': '1' });
    // The test route has no SDK provider, so it fails further on; what matters is it was not this refusal.
    expect(res.body).not.toMatch(/relay hosts nobody chose/);
  });

  it('does not accept another value as the opt-in', async () => {
    vi.stubGlobal('fetch', vi.fn());
    const res = await send(goRoute('deepseek-v4.1-flash', 'openai'), { 'x-clx-unpinned-host-ok': 'true' });
    expect(res.status).toBe(400);
    expect(JSON.parse(res.body).error.message).toMatch(/relay hosts nobody chose/);
  });

  it('leaves the Anthropic-format Go route alone', async () => {
    const fetchMock = vi.fn(async () => new Response(
      JSON.stringify({ id: 'msg_1', type: 'message', role: 'assistant', model: 'deepseek-v4.1-flash', content: [], usage: { input_tokens: 1, output_tokens: 1 } }),
      { status: 200, headers: { 'Content-Type': 'application/json' } },
    ));
    vi.stubGlobal('fetch', fetchMock);
    const res = await send(goRoute('deepseek-v4.1-flash', 'anthropic'));
    expect(res.status).toBe(200);
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it('still answers token counting locally on the guarded route', async () => {
    vi.stubGlobal('fetch', vi.fn());
    const res = await send(goRoute('deepseek-v4.1-flash', 'openai'), {}, '/v1/messages/count_tokens');
    expect(res.status).toBe(200);
  });
});
