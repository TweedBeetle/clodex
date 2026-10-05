import { afterEach, describe, expect, it, vi } from 'vitest';
import { createServer } from 'node:http';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createLanguageModel } from '../src/provider-factory.js';
import { generateAnthropicResponse } from '../src/sdk-adapter.js';
import { relayAnthropicMessages } from '../src/upstream-forward.js';
import { readUpstreamServedHeaders, writeInferenceResponseLifecycleLog } from '../src/trace-log.js';

// What OpenCode Go returned on 2026-09-26 for deepseek-flash (model-currency registry P-2026-09-13d).
const SERVED = {
  'x-opencode-endpoint-id': 'deepseek.an',
  'x-opencode-upstream-model-id': 'deepseek-flash',
  'x-zen-model': 'deepseek-flash',
};

describe('readUpstreamServedHeaders', () => {
  it('reads the three served-by headers', () => {
    expect(readUpstreamServedHeaders(new Headers(SERVED))).toEqual({
      endpointId: 'deepseek.an', upstreamModelId: 'deepseek-flash', zenModel: 'deepseek-flash',
    });
  });
  it('keeps only the headers present', () => {
    expect(readUpstreamServedHeaders(new Headers({ 'x-zen-model': 'm' }))).toEqual({ zenModel: 'm' });
  });
  it('returns undefined for a response that names nothing', () => {
    expect(readUpstreamServedHeaders(new Headers({ 'content-type': 'application/json' }))).toBeUndefined();
  });
});

describe('served-by headers through the real SDK path', () => {
  it('reach onResponseHeaders on an openai-compatible generation', async () => {
    const server = createServer(async (req, res) => {
      for await (const _chunk of req) { /* drain */ }
      res.writeHead(200, { 'Content-Type': 'application/json', ...SERVED });
      res.end(JSON.stringify({
        id: 'chatcmpl-served', object: 'chat.completion', created: 0, model: 'deepseek-v4.1-flash',
        choices: [{ index: 0, message: { role: 'assistant', content: 'ok' }, finish_reason: 'stop' }],
        usage: { prompt_tokens: 1, completion_tokens: 1, total_tokens: 2 },
      }));
    });
    await new Promise<void>(resolve => server.listen(0, '127.0.0.1', resolve));
    const address = server.address();
    if (!address || typeof address === 'string') throw new Error('missing listener address');
    try {
      const seen: Headers[] = [];
      const model = await createLanguageModel({
        npm: '@ai-sdk/openai-compatible',
        modelId: 'deepseek-v4.1-flash',
        apiKey: 'go-key',
        baseURL: `http://127.0.0.1:${address.port}/v1`,
        providerId: 'opencode-go',
        authType: 'api',
        onResponseHeaders: headers => seen.push(headers),
      });
      await generateAnthropicResponse(
        model, { messages: [{ role: 'user', content: 'hi' }], maxOutputTokens: 16 }, 'deepseek-v4.1-flash',
      );
      expect(seen).toHaveLength(1);
      expect(readUpstreamServedHeaders(seen[0]!)).toEqual({
        endpointId: 'deepseek.an', upstreamModelId: 'deepseek-flash', zenModel: 'deepseek-flash',
      });
    } finally {
      await new Promise<void>((resolve, reject) => server.close(err => (err ? reject(err) : resolve())));
    }
  });
});

describe('lifecycle log', () => {
  it('writes the upstream block when present and omits it otherwise', () => {
    const dir = mkdtempSync(join(tmpdir(), 'clodex-served-'));
    const path = join(dir, 'inference.jsonl');
    try {
      const base = { requestId: 'r1', modelId: 'flash', provider: 'opencode-go', route: 'translated' as const };
      writeInferenceResponseLifecycleLog(path, {
        ...base, event: 'translation_completed',
        upstream: { endpointId: 'deepseek.an', upstreamModelId: 'deepseek-flash' },
      });
      writeInferenceResponseLifecycleLog(path, { ...base, event: 'translation_started' });
      const rows = readFileSync(path, 'utf8').trim().split('\n').map(l => JSON.parse(l.slice(l.indexOf('{'))));
      expect(rows[0].upstream).toEqual({ endpointId: 'deepseek.an', upstreamModelId: 'deepseek-flash' });
      expect(rows[1]).not.toHaveProperty('upstream');
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});

describe('served-by headers on the Messages relay (the path flash takes to Go)', () => {
  afterEach(() => { vi.unstubAllGlobals(); });
  const makeRes = () => {
    const res = {
      writeHead() { return res; }, write() { return true; },
      end() { res.finished = true; }, destroy() { /* noop */ },
      on() { return res; }, once() { return res; }, emit() { return false; },
      removeListener() { return res; }, finished: false,
    };
    return res;
  };
  for (const status of [200, 429]) {
    it(`hands the headers to onResponseHeaders on a ${status}`, async () => {
      vi.stubGlobal('fetch', vi.fn(async () => new Response(
        JSON.stringify({ id: 'msg_1', type: 'message', model: 'deepseek-v4.1-flash', content: [] }),
        { status, headers: { 'Content-Type': 'application/json', ...SERVED } },
      )));
      const seen: Headers[] = [];
      await relayAnthropicMessages(
        makeRes() as never, 'https://opencode.ai/zen/go/v1/messages', { model: 'deepseek-v4.1-flash' },
        'key', false, { onResponseHeaders: h => seen.push(h) },
      );
      expect(seen).toHaveLength(1);
      expect(readUpstreamServedHeaders(seen[0]!)?.endpointId).toBe('deepseek.an');
    });
  }
});
