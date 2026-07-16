// Worker entry: health, WebSocket routing, and dev only debug endpoints. Every socket is
// routed to the mailbox Durable Object named by the handle in the URL query so the
// connection and queue live together; everything else happens inside the mailbox
// (src/mailbox.ts).

import { LIMITS } from '@nuco/protocol';

import type { Env } from './env';
import { apnsConfigState, ipRateKey, isDev } from './env';
import { handleAdmin } from './admin';

export { MailboxDO } from './mailbox';
export { ReportsDO } from './reports';

function isRoutableHandle(handle: string): boolean {
  return handle.length > 0 && handle.length <= LIMITS.handleMaxLen;
}

// A partial APNs secret set would otherwise fail as a silent no-op push; warn loudly,
// once per isolate.
let warnedApnsPartial = false;
function warnIfApnsPartial(env: Env): void {
  if (warnedApnsPartial || apnsConfigState(env) !== 'partial') return;
  warnedApnsPartial = true;
  console.error('[push] apns config incomplete: set all of APNS_KEY, APNS_KEY_ID, APNS_TEAM_ID, APNS_BUNDLE_ID, or none');
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);
    warnIfApnsPartial(env);

    if (url.pathname === '/health') {
      // The apns state is off/ok/partial only, never a secret; it lets an operator see a
      // misconfigured push setup from the outside.
      return Response.json({ ok: true, apns: apnsConfigState(env) });
    }

    // Operator endpoints (reports, ban, unban). 404 unless ADMIN_TOKEN is set.
    if (url.pathname.startsWith('/admin/')) {
      return handleAdmin(request, env);
    }

    // Test support: expose a mailbox's queue depth and mock wake counter. Never mounted
    // in production (DEV is a wrangler dev var, not a deploy var).
    if (isDev(env) && url.pathname === '/debug/state') {
      const handle = url.searchParams.get('handle') ?? '';
      if (!isRoutableHandle(handle)) return new Response('bad handle', { status: 400 });
      const stub = env.MAILBOX.get(env.MAILBOX.idFromName(handle));
      return Response.json(await stub.debugState());
    }

    if (request.headers.get('Upgrade')?.toLowerCase() === 'websocket') {
      const handle = url.searchParams.get('handle') ?? '';
      if (!isRoutableHandle(handle)) return new Response('missing or invalid handle', { status: 400 });
      // Per IP upgrade limit, checked before any Durable Object is woken. Fails open when
      // the binding is absent (trimmed self host config) or errors.
      try {
        const ip = request.headers.get('CF-Connecting-IP') ?? 'local';
        const outcome = await env.CONN_LIMIT?.limit({ key: await ipRateKey(ip) });
        if (outcome && !outcome.success) return new Response('rate limited', { status: 429 });
      } catch {
        // Fail open: rate limiting must never take the relay down.
      }
      const stub = env.MAILBOX.get(env.MAILBOX.idFromName(handle));
      return stub.fetch(request);
    }

    return new Response('not found', { status: 404 });
  },
} satisfies ExportedHandler<Env>;
