// Message handling: the relay's behavior for every client frame. Kept as pure functions
// over a RelayContext so the transport wiring (server.ts) stays separate from the logic.

import {
  ErrorCode,
  isMajorCompatible,
  parseClientMessage,
  type ClientMessage,
  type MessageEnvelope,
} from '@nuco/protocol';

import type { Config } from '../config.js';
import type { Storage, DeviceRecord, QueuedMessage } from '../storage/interface.js';
import { Session } from './session.js';
import { makeChallenge, verifyAuthSignature } from '../auth.js';

export interface RelayContext {
  readonly config: Config;
  readonly storage: Storage;
  now(): number;
  rateAllow(key: string): boolean;
  bind(handle: string, session: Session): void;
  liveSession(handle: string): Session | undefined;
  wake(device: DeviceRecord): void;
}

function fail(session: Session, code: ErrorCode, rid?: string): void {
  session.send(rid ? { type: 'error', code, rid } : { type: 'error', code });
}

function toEnvelope(m: QueuedMessage): MessageEnvelope {
  return { id: m.id, ciphertext: m.ciphertext, messageType: m.messageType, sentAt: m.sentAt };
}

export function deliverQueued(ctx: RelayContext, session: Session): void {
  if (!session.handle) return;
  for (const m of ctx.storage.dequeueMessages(session.handle)) {
    session.send({ type: 'deliver', from: m.from, envelope: toEnvelope(m), seq: m.seq });
  }
}

export function handleRawMessage(ctx: RelayContext, session: Session, raw: string): void {
  if (!ctx.rateAllow(session.ip)) {
    fail(session, ErrorCode.RateLimited);
    return;
  }
  const parsed = parseClientMessage(raw);
  if (!parsed.ok) {
    fail(session, parsed.code);
    return;
  }
  try {
    dispatch(ctx, session, parsed.message);
  } catch (err) {
    console.error('[relay] handler error', err);
    fail(session, ErrorCode.Internal);
  }
}

function requireAuth(session: Session, rid?: string): boolean {
  if (!session.authenticated || !session.handle) {
    fail(session, ErrorCode.Unauthenticated, rid);
    return false;
  }
  return true;
}

function dispatch(ctx: RelayContext, session: Session, msg: ClientMessage): void {
  switch (msg.type) {
    case 'connect': {
      if (!isMajorCompatible(msg.protocolVersion)) {
        fail(session, ErrorCode.ProtocolVersionMismatch);
        session.ws.close();
        return;
      }
      session.handle = msg.handle;
      session.challenge = makeChallenge();
      session.send({
        type: 'connected',
        protocolVersion: { major: msg.protocolVersion.major, minor: msg.protocolVersion.minor },
        challenge: session.challenge,
      });
      return;
    }

    case 'register': {
      if (!session.handle) {
        fail(session, ErrorCode.Unauthenticated, msg.rid);
        return;
      }
      const existing = ctx.storage.getDevice(session.handle);
      // Creating a new handle is allowed before auth; updating an existing one is not.
      if (existing && !session.authenticated) {
        fail(session, ErrorCode.Unauthenticated, msg.rid);
        return;
      }
      const now = ctx.now();
      ctx.storage.registerDevice({
        handle: session.handle,
        identityKey: msg.identityKey,
        authKey: msg.authKey,
        registrationId: msg.registrationId,
        deviceId: msg.deviceId,
        push: msg.push,
        createdAt: existing?.createdAt ?? now,
        lastSeen: now,
      });
      if (ctx.config.dev) console.log(`[relay] registered ${session.handle}`);
      session.send({ type: 'ok', rid: msg.rid });
      return;
    }

    case 'authenticate': {
      if (!session.handle || !session.challenge) {
        fail(session, ErrorCode.Unauthenticated);
        return;
      }
      const device = ctx.storage.getDevice(session.handle);
      if (!device) {
        fail(session, ErrorCode.NotRegistered);
        return;
      }
      if (!verifyAuthSignature(device.authKey, session.challenge, msg.signature)) {
        fail(session, ErrorCode.AuthFailed);
        return;
      }
      session.authenticated = true;
      ctx.bind(session.handle, session);
      ctx.storage.touchDevice(session.handle, ctx.now());
      if (ctx.config.dev) console.log(`[relay] authenticated ${session.handle}`);
      session.send({ type: 'authenticated' });
      deliverQueued(ctx, session);
      return;
    }

    case 'publishPreKeys': {
      if (!requireAuth(session, msg.rid)) return;
      ctx.storage.publishPreKeys(session.handle!, msg.preKeys);
      session.send({ type: 'ok', rid: msg.rid, data: { oneTimeCount: ctx.storage.countOneTimePreKeys(session.handle!) } });
      return;
    }

    case 'fetchPreKeyBundle': {
      if (!requireAuth(session, msg.rid)) return;
      const bundle = ctx.storage.takePreKeyBundle(msg.handle);
      if (!bundle) {
        fail(session, ErrorCode.NoSuchHandle, msg.rid);
        return;
      }
      session.send({ type: 'preKeyBundle', rid: msg.rid, bundle });
      return;
    }

    case 'preKeyCount': {
      if (!requireAuth(session, msg.rid)) return;
      session.send({
        type: 'preKeyCountResult',
        rid: msg.rid,
        hasSignedPreKey: ctx.storage.hasSignedPreKey(session.handle!),
        oneTimeCount: ctx.storage.countOneTimePreKeys(session.handle!),
      });
      return;
    }

    case 'send': {
      if (!requireAuth(session, msg.rid)) return;
      if (msg.envelope.ciphertext.length > ctx.config.maxMessageBytes) {
        fail(session, ErrorCode.MessageTooLarge, msg.rid);
        return;
      }
      const recipient = ctx.storage.getDevice(msg.to);
      if (!recipient) {
        fail(session, ErrorCode.NoSuchHandle, msg.rid);
        return;
      }
      const result = ctx.storage.enqueueMessage(
        msg.to,
        {
          id: msg.envelope.id,
          from: session.handle!,
          ciphertext: msg.envelope.ciphertext,
          messageType: msg.envelope.messageType,
          sentAt: msg.envelope.sentAt,
        },
        ctx.now(),
        ctx.config.queueMax,
      );
      if (!result.ok) {
        fail(session, ErrorCode.QueueFull, msg.rid);
        return;
      }
      session.send({ type: 'ok', rid: msg.rid });

      const live = ctx.liveSession(msg.to);
      if (live) {
        live.send({ type: 'deliver', from: session.handle!, envelope: msg.envelope, seq: result.seq });
      } else {
        ctx.wake(recipient);
      }
      return;
    }

    case 'ack': {
      if (!requireAuth(session)) return;
      ctx.storage.ackMessage(session.handle!, msg.id);
      return;
    }

    case 'ping': {
      session.send({ type: 'pong', ts: msg.ts });
      return;
    }
  }
}
