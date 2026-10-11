import type { IncomingMessage } from 'node:http';

/**
 * Local guard (CLX, not upstream): refuse OpenCode Go DeepSeek models on the
 * translated (Chat Completions) route unless the request opts in.
 *
 * On that route Go hands DeepSeek requests to whichever relay it picks
 * (Novita, OrcaRouter, Luminal; model-currency sweep 2026-10-11, registry
 * P-2026-10-11c), at no published precision, and every Claude Code request
 * carries the user's CLAUDE.md. Go's Anthropic-format route is not affected:
 * it reached DeepSeek's own endpoint. Smoke tests opt in per request with the
 * header below (Claude Code sends it via ANTHROPIC_CUSTOM_HEADERS).
 */
export const UNPINNED_HOST_OPT_IN_HEADER = 'x-clx-unpinned-host-ok';

export interface GuardedRoute {
  providerId?: string;
  modelFormat?: string;
  realModelId: string;
}

export function isUnpinnedGoRelayRoute(route: GuardedRoute): boolean {
  return route.providerId === 'opencode-go'
    && route.modelFormat !== 'anthropic'
    && route.realModelId.startsWith('deepseek-');
}

export function unpinnedHostOptedIn(req: IncomingMessage): boolean {
  const raw = req.headers[UNPINNED_HOST_OPT_IN_HEADER];
  const value = Array.isArray(raw) ? raw[0] : raw;
  return value === '1';
}

export function unpinnedHostRefusal(realModelId: string): string {
  return `CLX refuses ${realModelId} on OpenCode Go's Chat Completions route: Go serves it from `
    + 'relay hosts nobody chose, and every Claude Code request carries your CLAUDE.md. '
    + 'For real Flash work use cc-zen (cc-zen-env deepseek-flash -- ...). '
    + `A smoke test can opt in with ANTHROPIC_CUSTOM_HEADERS="${UNPINNED_HOST_OPT_IN_HEADER}: 1".`;
}
