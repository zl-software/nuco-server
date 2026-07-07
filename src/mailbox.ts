// The mailbox Durable Object: exactly one per handle (idFromName). It owns the handle's
// device record and message queue in its co-located SQLite storage, and holds the
// handle's live WebSocket via the hibernation API (zero cost while idle; the static ping
// is answered from the edge without waking the object).
//
// Frame handling mirrors the wire contract in ../protocol/PROTOCOL.md. The only frame
// that touches another handle (send) calls that handle's mailbox over DO RPC; the
// receiving side enqueues (delivery stays at least once, ack deletes, dedupe by envelope
// id) and either live delivers or triggers a content free push wake. The relay never sees
// plaintext, never holds a private key or any end to end key material (since protocol 2.0
// not even public identity keys), and never logs ciphertext or credentials.

import { DurableObject } from 'cloudflare:workers';

import {
  ErrorCode,
  isMajorCompatible,
  parseClientMessage,
  PROTOCOL_VERSION,
  type ClientMessage,
  type MessageEnvelope,
  type PushRegistration,
  type ServerMessage,
} from '@nuco/protocol';

import { intVar, isDev, type Env } from './env';
import { makeChallenge, verifyAuthSignature } from './auth';
import { issueTurnCredentials } from './turn';
import { sendApnsWake } from './push/apns';
import { sendUnifiedPushWake } from './push/unifiedpush';
import { isSyntacticallyPublicHttpsUrl } from './push/url-guard';

// Persisted per socket via serializeAttachment, so it survives hibernation.
interface SessionState {
  handle: string;
  authenticated: boolean;
  challenge: string | null;
  // Frames sent before authenticating. Handles are public and any socket can open against
  // a handle's mailbox, so an unauthenticated flood must not draw down the owner's
  // authenticated budget; a small per socket allowance covers the handshake and then the
  // socket is closed.
  preAuthFrames: number;
}

// A type literal (not an interface) so it satisfies the sql.exec Record constraint.
type DeviceRow = {
  auth_key: string;
  device_id: number;
  push_kind: string;
  push_token: string | null;
  push_endpoint: string | null;
  apns_topic: string | null;
  created_at: number;
  last_seen: number;
};

export type DeliverResult =
  | { ok: true; seq: number; delivered: boolean }
  | { ok: false; reason: 'no-such-handle' | 'queue-full' };

const SWEEP_INTERVAL_MS = 3_600_000;
const STATIC_PING = '{"type":"ping","ts":0}';
const STATIC_PONG = '{"type":"pong","ts":0}';
// Enough for the handshake (connect, optional register, authenticate) with slack.
const PRE_AUTH_FRAME_MAX = 8;

export class MailboxDO extends DurableObject<Env> {
  constructor(ctx: DurableObjectState, env: Env) {
    super(ctx, env);
    this.initSchema();
    // Answered at the edge without waking a hibernated object (byte exact match).
    this.ctx.setWebSocketAutoResponse(new WebSocketRequestResponsePair(STATIC_PING, STATIC_PONG));
  }

  private initSchema(): void {
    this.ctx.storage.sql.exec(`
      CREATE TABLE IF NOT EXISTS device (
        id INTEGER PRIMARY KEY CHECK (id = 1),
        auth_key TEXT NOT NULL,
        device_id INTEGER NOT NULL,
        push_kind TEXT NOT NULL,
        push_token TEXT,
        push_endpoint TEXT,
        apns_topic TEXT,
        created_at INTEGER NOT NULL,
        last_seen INTEGER NOT NULL
      );
      CREATE TABLE IF NOT EXISTS inbox (
        seq INTEGER PRIMARY KEY AUTOINCREMENT,
        id TEXT UNIQUE NOT NULL,
        sender TEXT NOT NULL,
        ciphertext TEXT NOT NULL,
        message_type TEXT NOT NULL,
        sent_at INTEGER NOT NULL,
        enqueued_at INTEGER NOT NULL
      );
    `);
  }

  // --- socket lifecycle ---

  async fetch(request: Request): Promise<Response> {
    if (request.headers.get('Upgrade')?.toLowerCase() !== 'websocket') {
      return new Response('expected websocket', { status: 426 });
    }
    // The worker routed this socket here by the handle in the URL, so by construction the
    // URL handle names this object; it becomes the session's expected handle.
    const handle = new URL(request.url).searchParams.get('handle') ?? '';
    const pair = new WebSocketPair();
    const client = pair[0];
    const server = pair[1];
    this.ctx.acceptWebSocket(server);
    setSession(server, { handle, authenticated: false, challenge: null, preAuthFrames: 0 });
    return new Response(null, { status: 101, webSocket: client });
  }

  async webSocketMessage(ws: WebSocket, raw: string | ArrayBuffer): Promise<void> {
    if (typeof raw !== 'string') {
      ws.close(1003, 'text frames only');
      return;
    }
    if (raw.length > intVar(this.env.MAX_MESSAGE_BYTES, 131072) + 8192) {
      this.fail(ws, ErrorCode.MessageTooLarge);
      return;
    }
    const session = getSession(ws);
    if (session.authenticated) {
      // The per handle token bucket applies only to the authenticated owner (nobody else
      // can authenticate as this handle), and it is persisted so hibernation cannot refill
      // it early.
      if (!this.rateAllow()) {
        this.fail(ws, ErrorCode.RateLimited);
        return;
      }
    } else {
      if (session.preAuthFrames >= PRE_AUTH_FRAME_MAX) {
        this.fail(ws, ErrorCode.RateLimited);
        ws.close(1008, 'unauthenticated flood');
        return;
      }
      session.preAuthFrames += 1;
      setSession(ws, session);
    }
    const parsed = parseClientMessage(raw);
    if (!parsed.ok) {
      this.fail(ws, parsed.code);
      return;
    }
    try {
      await this.dispatch(ws, parsed.message);
    } catch (err) {
      console.error('[relay] handler error', err);
      this.fail(ws, ErrorCode.Internal);
    }
  }

  async webSocketClose(): Promise<void> {
    // Nothing to clean up: session state lives on the socket attachment and storage is
    // authoritative. The runtime drops the socket from getWebSockets() on its own.
  }

  // --- frame dispatch (mirrors the old handlers.ts) ---

  private async dispatch(ws: WebSocket, msg: ClientMessage): Promise<void> {
    const session = getSession(ws);
    switch (msg.type) {
      case 'connect': {
        if (!isMajorCompatible(msg.protocolVersion)) {
          this.fail(ws, ErrorCode.ProtocolVersionMismatch);
          ws.close(1002, 'protocol version mismatch');
          return;
        }
        // The URL handle routed the socket to this mailbox; a mismatching connect frame
        // is a confused or hostile client.
        if (msg.handle !== session.handle) {
          this.fail(ws, ErrorCode.MalformedMessage);
          ws.close(1008, 'handle mismatch');
          return;
        }
        session.challenge = makeChallenge();
        setSession(ws, session);
        this.send(ws, {
          type: 'connected',
          protocolVersion: { major: PROTOCOL_VERSION.major, minor: PROTOCOL_VERSION.minor },
          challenge: session.challenge,
        });
        return;
      }

      case 'register': {
        const existing = this.getDevice();
        // Creating a new handle is allowed before auth (trust on first use for the random
        // handle namespace); updating an existing one is not.
        if (existing && !session.authenticated) {
          this.fail(ws, ErrorCode.Unauthenticated, msg.rid);
          return;
        }
        if (msg.push.kind === 'unifiedpush' && (!msg.push.endpoint || !isSyntacticallyPublicHttpsUrl(msg.push.endpoint))) {
          this.fail(ws, ErrorCode.MalformedMessage, msg.rid);
          return;
        }
        this.registerDevice(msg.authKey, msg.deviceId, msg.push, existing?.created_at);
        if (isDev(this.env)) console.log(`[relay] registered ${session.handle}`);
        this.send(ws, { type: 'ok', rid: msg.rid });
        return;
      }

      case 'authenticate': {
        if (!session.challenge) {
          this.fail(ws, ErrorCode.Unauthenticated);
          return;
        }
        const device = this.getDevice();
        if (!device) {
          this.fail(ws, ErrorCode.NotRegistered);
          return;
        }
        if (!(await verifyAuthSignature(device.auth_key, session.challenge, msg.signature))) {
          this.fail(ws, ErrorCode.AuthFailed);
          return;
        }
        session.authenticated = true;
        session.challenge = null; // one time nonce, consumed
        setSession(ws, session);
        // Last authenticated socket wins: drop any previous socket for this handle.
        for (const other of this.ctx.getWebSockets()) {
          if (other !== ws) other.close(1000, 'superseded');
        }
        this.ctx.storage.sql.exec('UPDATE device SET last_seen = ? WHERE id = 1', Date.now());
        if (isDev(this.env)) console.log(`[relay] authenticated ${session.handle}`);
        this.send(ws, { type: 'authenticated' });
        this.sweepExpired();
        this.deliverQueued(ws);
        return;
      }

      case 'send': {
        if (!this.requireAuth(ws, session, msg.rid)) return;
        if (msg.envelope.ciphertext.length > intVar(this.env.MAX_MESSAGE_BYTES, 131072)) {
          this.fail(ws, ErrorCode.MessageTooLarge, msg.rid);
          return;
        }
        const stub = this.env.MAILBOX.get(this.env.MAILBOX.idFromName(msg.to));
        const result = await stub.deliver(session.handle, msg.envelope);
        if (!result.ok) {
          this.fail(ws, result.reason === 'no-such-handle' ? ErrorCode.NoSuchHandle : ErrorCode.QueueFull, msg.rid);
          return;
        }
        this.send(ws, { type: 'ok', rid: msg.rid });
        return;
      }

      case 'ack': {
        if (!session.authenticated) {
          this.fail(ws, ErrorCode.Unauthenticated);
          return;
        }
        this.ctx.storage.sql.exec('DELETE FROM inbox WHERE id = ?', msg.id);
        return;
      }

      case 'ping': {
        // Fallback for nonstatic payloads; the constant ping is answered by the runtime
        // without waking this object.
        this.send(ws, { type: 'pong', ts: msg.ts });
        return;
      }

      case 'deregister': {
        if (!this.requireAuth(ws, session, msg.rid)) return;
        await this.ctx.storage.deleteAll();
        this.initSchema();
        session.authenticated = false;
        setSession(ws, session);
        if (isDev(this.env)) console.log(`[relay] deregistered ${session.handle}`);
        this.send(ws, { type: 'ok', rid: msg.rid });
        return;
      }

      case 'turnCredentials': {
        if (!this.requireAuth(ws, session, msg.rid)) return;
        const creds = await issueTurnCredentials(this.env);
        if (!creds) {
          this.fail(ws, ErrorCode.CallsUnavailable, msg.rid);
          return;
        }
        this.send(ws, {
          type: 'turnCredentialsResult',
          rid: msg.rid,
          urls: creds.urls,
          username: creds.username,
          credential: creds.credential,
          expiresAt: creds.expiresAt,
        });
        return;
      }
    }
  }

  // --- RPC surface (called by other mailboxes and the worker) ---

  // The sending side calls the RECIPIENT's mailbox. Enqueue first (delivery stays queue
  // backed and at least once), then push to a live socket or trigger a content free wake.
  async deliver(from: string, envelope: MessageEnvelope): Promise<DeliverResult> {
    const device = this.getDevice();
    if (!device) return { ok: false, reason: 'no-such-handle' };

    const existing = this.ctx.storage.sql
      .exec<{ seq: number }>('SELECT seq FROM inbox WHERE id = ?', envelope.id)
      .toArray()[0];
    if (existing) {
      // Duplicate send (client retry): the message is already queued. Re deliver to a live
      // socket if the recipient is now connected (deduped by id on the client), but never
      // trigger another push wake and never re-check the cap; that would let a repeated id
      // spam wakes while the queue depth stays at one.
      let delivered = false;
      for (const ws of this.ctx.getWebSockets()) {
        if (getSession(ws).authenticated) {
          this.send(ws, { type: 'deliver', from, envelope, seq: existing.seq });
          delivered = true;
        }
      }
      return { ok: true, seq: existing.seq, delivered };
    }

    if (this.queueDepth() >= intVar(this.env.QUEUE_MAX, 1000)) return { ok: false, reason: 'queue-full' };
    this.ctx.storage.sql.exec(
      'INSERT INTO inbox (id, sender, ciphertext, message_type, sent_at, enqueued_at) VALUES (?, ?, ?, ?, ?, ?)',
      envelope.id,
      from,
      envelope.ciphertext,
      envelope.messageType,
      envelope.sentAt,
      Date.now(),
    );
    const seq = this.ctx.storage.sql.exec<{ seq: number }>('SELECT seq FROM inbox WHERE id = ?', envelope.id).one().seq;
    await this.ensureSweepAlarm();

    let delivered = false;
    for (const ws of this.ctx.getWebSockets()) {
      if (getSession(ws).authenticated) {
        this.send(ws, { type: 'deliver', from, envelope, seq });
        delivered = true;
      }
    }
    if (!delivered) await this.wake(device);
    return { ok: true, seq, delivered };
  }

  // Dev only debug surface (gated in the worker).
  async debugState(): Promise<{ queueDepth: number; wakes: number }> {
    return { queueDepth: this.queueDepth(), wakes: (this.ctx.storage.kv.get('wakes') as number | undefined) ?? 0 };
  }

  // --- queue maintenance ---

  async alarm(): Promise<void> {
    this.sweepExpired();
    if (this.queueDepth() > 0) await this.ctx.storage.setAlarm(Date.now() + SWEEP_INTERVAL_MS);
  }

  private async ensureSweepAlarm(): Promise<void> {
    if ((await this.ctx.storage.getAlarm()) === null) {
      await this.ctx.storage.setAlarm(Date.now() + SWEEP_INTERVAL_MS);
    }
  }

  private sweepExpired(): void {
    const ttlMs = intVar(this.env.QUEUE_TTL_SECONDS, 2592000) * 1000;
    this.ctx.storage.sql.exec('DELETE FROM inbox WHERE enqueued_at < ?', Date.now() - ttlMs);
  }

  // --- helpers ---

  private getDevice(): DeviceRow | undefined {
    return this.ctx.storage.sql.exec<DeviceRow>('SELECT * FROM device WHERE id = 1').toArray()[0];
  }

  private registerDevice(authKey: string, deviceId: number, push: PushRegistration, createdAt: number | undefined): void {
    const now = Date.now();
    this.ctx.storage.sql.exec(
      `INSERT OR REPLACE INTO device (id, auth_key, device_id, push_kind, push_token, push_endpoint, apns_topic, created_at, last_seen)
       VALUES (1, ?, ?, ?, ?, ?, ?, ?, ?)`,
      authKey,
      deviceId,
      push.kind,
      push.token ?? null,
      push.endpoint ?? null,
      push.apnsTopic ?? null,
      createdAt ?? now,
      now,
    );
  }

  private queueDepth(): number {
    return Number(this.ctx.storage.sql.exec('SELECT COUNT(*) AS n FROM inbox').one().n);
  }

  private deliverQueued(ws: WebSocket): void {
    const rows = this.ctx.storage.sql
      .exec<{ seq: number; id: string; sender: string; ciphertext: string; message_type: string; sent_at: number }>(
        'SELECT seq, id, sender, ciphertext, message_type, sent_at FROM inbox ORDER BY seq',
      )
      .toArray();
    for (const m of rows) {
      this.send(ws, {
        type: 'deliver',
        from: m.sender,
        envelope: { id: m.id, ciphertext: m.ciphertext, messageType: m.message_type as MessageEnvelope['messageType'], sentAt: m.sent_at },
        seq: m.seq,
      });
    }
  }

  private async wake(device: DeviceRow): Promise<void> {
    try {
      if (isDev(this.env)) {
        // Dev mode: record instead of sending (also, wrangler dev cannot reach APNs over
        // HTTP/2). The counter feeds the /debug endpoint the tests read.
        const wakes = ((this.ctx.storage.kv.get('wakes') as number | undefined) ?? 0) + 1;
        this.ctx.storage.kv.put('wakes', wakes);
        console.log(`[push:mock] content free wake via ${device.push_kind}`);
        return;
      }
      if (device.push_kind === 'apns' && device.push_token) {
        const result = await sendApnsWake(this.env, device.push_token, device.apns_topic ?? undefined);
        if (result.unregistered) {
          // Dead token: prune it so we stop paying for rejected pushes.
          this.ctx.storage.sql.exec("UPDATE device SET push_kind = 'none', push_token = NULL, apns_topic = NULL WHERE id = 1");
        }
      } else if (device.push_kind === 'unifiedpush' && device.push_endpoint) {
        await sendUnifiedPushWake(device.push_endpoint);
      }
    } catch (err) {
      // Push is fire and forget: the message is queued either way.
      console.error('[push] wake failed', err instanceof Error ? err.message : 'unknown');
    }
  }

  private requireAuth(ws: WebSocket, session: SessionState, rid?: string): boolean {
    if (!session.authenticated) {
      this.fail(ws, ErrorCode.Unauthenticated, rid);
      return false;
    }
    return true;
  }

  // Token bucket persisted in storage so it survives hibernation (an in memory bucket would
  // reset to full on every wake, defeating the limit). Synchronous kv on the SQLite object.
  private rateAllow(): boolean {
    const maxPerMinute = intVar(this.env.RATE_MAX_PER_MIN, 600);
    const now = Date.now();
    const tokens = (this.ctx.storage.kv.get('rateTokens') as number | undefined) ?? maxPerMinute;
    const last = (this.ctx.storage.kv.get('rateLast') as number | undefined) ?? now;
    let refilled = Math.min(maxPerMinute, tokens + ((now - last) * maxPerMinute) / 60_000);
    this.ctx.storage.kv.put('rateLast', now);
    if (refilled < 1) {
      this.ctx.storage.kv.put('rateTokens', refilled);
      return false;
    }
    refilled -= 1;
    this.ctx.storage.kv.put('rateTokens', refilled);
    return true;
  }

  private send(ws: WebSocket, msg: ServerMessage): void {
    try {
      ws.send(JSON.stringify(msg));
    } catch {
      // Socket already gone; queued rows redeliver on the next connect.
    }
  }

  private fail(ws: WebSocket, code: ErrorCode, rid?: string): void {
    this.send(ws, rid ? { type: 'error', code, rid } : { type: 'error', code });
  }
}

function getSession(ws: WebSocket): SessionState {
  return (ws.deserializeAttachment() as SessionState | null) ?? { handle: '', authenticated: false, challenge: null, preAuthFrames: 0 };
}

function setSession(ws: WebSocket, session: SessionState): void {
  ws.serializeAttachment(session);
}
