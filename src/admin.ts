// Operator surface: bearer authenticated HTTP endpoints over the abuse reports the app
// can submit since protocol 3.2. Mounted only when the ADMIN_TOKEN secret is set; without
// it every /admin path answers 404 and a bare relay exposes nothing. The operator lists
// reports, bans and unbans handles (a ban makes authenticate and register answer BANNED
// and drops the handle's queue, see PROTOCOL.md "Reports and bans"), and deletes handled
// report rows.

import { LIMITS } from '@nuco/protocol';

import type { Env } from './env';

// Same shape check the worker applies to socket handles. Local copy: the worker imports
// this module, so importing back from it would be circular.
function isRoutableHandle(handle: string): boolean {
  return handle.length > 0 && handle.length <= LIMITS.handleMaxLen;
}

// Constant time bearer comparison via SHA-256 digests: hashing first makes both sides a
// fixed length, so the byte loop never short circuits on a length mismatch.
async function tokenMatches(presented: string, expected: string): Promise<boolean> {
  const enc = new TextEncoder();
  const a = new Uint8Array(await crypto.subtle.digest('SHA-256', enc.encode(presented)));
  const b = new Uint8Array(await crypto.subtle.digest('SHA-256', enc.encode(expected)));
  let diff = 0;
  for (let i = 0; i < a.length; i += 1) diff |= (a[i] ?? 0) ^ (b[i] ?? 0);
  return diff === 0;
}

function intParam(v: string | null, fallback: number, max: number): number {
  if (v === null || v === '') return fallback;
  const n = Number.parseInt(v, 10);
  return Number.isFinite(n) && n > 0 ? Math.min(n, max) : fallback;
}

export async function handleAdmin(request: Request, env: Env): Promise<Response> {
  if (!env.ADMIN_TOKEN) return new Response('not found', { status: 404 });
  const auth = request.headers.get('Authorization') ?? '';
  const presented = auth.startsWith('Bearer ') ? auth.slice('Bearer '.length) : '';
  if (presented === '' || !(await tokenMatches(presented, env.ADMIN_TOKEN))) {
    return new Response('unauthorized', { status: 401 });
  }

  const url = new URL(request.url);
  const reports = () => env.REPORTS.get(env.REPORTS.idFromName('reports'));

  if (request.method === 'GET' && url.pathname === '/admin/reports') {
    const limit = intParam(url.searchParams.get('limit'), 100, 1000);
    const beforeRaw = url.searchParams.get('before');
    const before = beforeRaw === null ? undefined : Number.parseInt(beforeRaw, 10);
    const rows = await reports().list(limit, Number.isFinite(before as number) ? before : undefined);
    return Response.json({ reports: rows });
  }

  if (request.method === 'POST' && (url.pathname === '/admin/ban' || url.pathname === '/admin/unban')) {
    let body: unknown;
    try {
      body = await request.json();
    } catch {
      return new Response('bad request', { status: 400 });
    }
    const handle = (body as { handle?: unknown }).handle;
    if (typeof handle !== 'string' || !isRoutableHandle(handle)) {
      return new Response('bad request', { status: 400 });
    }
    const stub = env.MAILBOX.get(env.MAILBOX.idFromName(handle));
    await stub.setBanned(url.pathname === '/admin/ban');
    return Response.json({ ok: true });
  }

  if (request.method === 'POST' && url.pathname === '/admin/reports/delete') {
    let body: unknown;
    try {
      body = await request.json();
    } catch {
      return new Response('bad request', { status: 400 });
    }
    const ids = (body as { ids?: unknown }).ids;
    if (!Array.isArray(ids) || ids.some((id) => typeof id !== 'number' || !Number.isInteger(id))) {
      return new Response('bad request', { status: 400 });
    }
    const removed = await reports().remove(ids as number[]);
    return Response.json({ removed });
  }

  return new Response('not found', { status: 404 });
}
