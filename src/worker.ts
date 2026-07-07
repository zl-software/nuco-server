// Worker entry: health, WebSocket routing, and dev only debug endpoints. Every socket is
// routed to the mailbox Durable Object named by the handle in the URL query so the
// connection and queue live together; everything else happens inside the mailbox
// (src/mailbox.ts).

import { LIMITS } from '@nuco/protocol';

import type { Env } from './env';
import { isDev } from './env';

export { MailboxDO } from './mailbox';

function isRoutableHandle(handle: string): boolean {
  return handle.length > 0 && handle.length <= LIMITS.handleMaxLen;
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);

    if (url.pathname === '/health') {
      return Response.json({ ok: true });
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
      const stub = env.MAILBOX.get(env.MAILBOX.idFromName(handle));
      return stub.fetch(request);
    }

    return new Response('not found', { status: 404 });
  },
} satisfies ExportedHandler<Env>;
