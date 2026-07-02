// Default storage backend: better-sqlite3. Synchronous, fast, and prebuilt for current
// Node. All content columns are opaque to the relay.

import Database from 'better-sqlite3';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

import type { PushRegistration, PreKeyBundle, PreKeyUpload, CipherMessageType } from '@nuco/protocol';
import type { Storage, DeviceRecord, QueuedMessage, EnqueueResult } from './interface.js';

interface DeviceRow {
  handle: string;
  identity_key: string;
  auth_key: string;
  registration_id: number;
  device_id: number;
  push_kind: string;
  push_token: string | null;
  push_endpoint: string | null;
  apns_topic: string | null;
  created_at: number;
  last_seen: number;
}

interface QueueRow {
  seq: number;
  id: string;
  sender: string;
  ciphertext: string;
  message_type: string;
  sent_at: number;
  enqueued_at: number;
}

function rowToDevice(r: DeviceRow): DeviceRecord {
  const push: PushRegistration = {
    kind: r.push_kind as PushRegistration['kind'],
    ...(r.push_token !== null ? { token: r.push_token } : {}),
    ...(r.push_endpoint !== null ? { endpoint: r.push_endpoint } : {}),
    ...(r.apns_topic !== null ? { apnsTopic: r.apns_topic } : {}),
  };
  return {
    handle: r.handle,
    identityKey: r.identity_key,
    authKey: r.auth_key,
    registrationId: r.registration_id,
    deviceId: r.device_id,
    push,
    createdAt: r.created_at,
    lastSeen: r.last_seen,
  };
}

export class SqliteStorage implements Storage {
  private readonly db: Database.Database;

  constructor(path: string) {
    this.db = new Database(path);
    this.db.pragma('journal_mode = WAL');
    this.db.pragma('busy_timeout = 5000');
    this.db.pragma('foreign_keys = ON');
    const schema = readFileSync(fileURLToPath(new URL('./schema.sql', import.meta.url)), 'utf8');
    this.db.exec(schema);
  }

  registerDevice(rec: DeviceRecord): void {
    this.db
      .prepare(
        `INSERT INTO devices
          (handle, identity_key, auth_key, registration_id, device_id, push_kind, push_token, push_endpoint, apns_topic, created_at, last_seen)
         VALUES (@handle, @identityKey, @authKey, @registrationId, @deviceId, @pushKind, @pushToken, @pushEndpoint, @apnsTopic, @createdAt, @lastSeen)
         ON CONFLICT(handle) DO UPDATE SET
          identity_key = excluded.identity_key,
          auth_key = excluded.auth_key,
          registration_id = excluded.registration_id,
          device_id = excluded.device_id,
          push_kind = excluded.push_kind,
          push_token = excluded.push_token,
          push_endpoint = excluded.push_endpoint,
          apns_topic = excluded.apns_topic,
          last_seen = excluded.last_seen`,
      )
      .run({
        handle: rec.handle,
        identityKey: rec.identityKey,
        authKey: rec.authKey,
        registrationId: rec.registrationId,
        deviceId: rec.deviceId,
        pushKind: rec.push.kind,
        pushToken: rec.push.token ?? null,
        pushEndpoint: rec.push.endpoint ?? null,
        apnsTopic: rec.push.apnsTopic ?? null,
        createdAt: rec.createdAt,
        lastSeen: rec.lastSeen,
      });
  }

  getDevice(handle: string): DeviceRecord | undefined {
    const row = this.db.prepare('SELECT * FROM devices WHERE handle = ?').get(handle) as DeviceRow | undefined;
    return row ? rowToDevice(row) : undefined;
  }

  updatePush(handle: string, push: PushRegistration): void {
    this.db
      .prepare('UPDATE devices SET push_kind = ?, push_token = ?, push_endpoint = ?, apns_topic = ? WHERE handle = ?')
      .run(push.kind, push.token ?? null, push.endpoint ?? null, push.apnsTopic ?? null, handle);
  }

  clearPush(handle: string): void {
    this.db
      .prepare("UPDATE devices SET push_kind = 'none', push_token = NULL, push_endpoint = NULL, apns_topic = NULL WHERE handle = ?")
      .run(handle);
  }

  deleteAccount(handle: string): void {
    const tx = this.db.transaction(() => {
      // Messages queued for this recipient have no FK to devices, so remove them explicitly.
      this.db.prepare('DELETE FROM queued_messages WHERE recipient = ?').run(handle);
      // Deleting the device cascades to signed_prekeys and onetime_prekeys (ON DELETE CASCADE).
      this.db.prepare('DELETE FROM devices WHERE handle = ?').run(handle);
    });
    tx();
  }

  touchDevice(handle: string, now: number): void {
    this.db.prepare('UPDATE devices SET last_seen = ? WHERE handle = ?').run(now, handle);
  }

  publishPreKeys(handle: string, upload: PreKeyUpload): void {
    const tx = this.db.transaction(() => {
      this.db
        .prepare(
          `INSERT INTO signed_prekeys (handle, key_id, public_key, signature)
           VALUES (?, ?, ?, ?)
           ON CONFLICT(handle) DO UPDATE SET key_id = excluded.key_id, public_key = excluded.public_key, signature = excluded.signature`,
        )
        .run(handle, upload.signedPreKey.keyId, upload.signedPreKey.publicKey, upload.signedPreKey.signature);
      const insert = this.db.prepare(
        'INSERT OR IGNORE INTO onetime_prekeys (handle, key_id, public_key) VALUES (?, ?, ?)',
      );
      for (const k of upload.oneTimePreKeys) insert.run(handle, k.keyId, k.publicKey);
    });
    tx();
  }

  countOneTimePreKeys(handle: string): number {
    const row = this.db.prepare('SELECT COUNT(*) AS n FROM onetime_prekeys WHERE handle = ?').get(handle) as { n: number };
    return row.n;
  }

  hasSignedPreKey(handle: string): boolean {
    return this.db.prepare('SELECT 1 FROM signed_prekeys WHERE handle = ?').get(handle) !== undefined;
  }

  takePreKeyBundle(handle: string): PreKeyBundle | undefined {
    const tx = this.db.transaction((): PreKeyBundle | undefined => {
      const device = this.db.prepare('SELECT * FROM devices WHERE handle = ?').get(handle) as DeviceRow | undefined;
      if (!device) return undefined;
      const spk = this.db.prepare('SELECT key_id, public_key, signature FROM signed_prekeys WHERE handle = ?').get(handle) as
        | { key_id: number; public_key: string; signature: string }
        | undefined;
      if (!spk) return undefined;
      const otp = this.db
        .prepare('SELECT key_id, public_key FROM onetime_prekeys WHERE handle = ? ORDER BY key_id LIMIT 1')
        .get(handle) as { key_id: number; public_key: string } | undefined;
      if (otp) {
        this.db.prepare('DELETE FROM onetime_prekeys WHERE handle = ? AND key_id = ?').run(handle, otp.key_id);
      }
      const bundle: PreKeyBundle = {
        handle,
        deviceId: device.device_id,
        registrationId: device.registration_id,
        identityKey: device.identity_key,
        signedPreKey: { keyId: spk.key_id, publicKey: spk.public_key, signature: spk.signature },
        ...(otp ? { oneTimePreKey: { keyId: otp.key_id, publicKey: otp.public_key } } : {}),
      };
      return bundle;
    });
    return tx();
  }

  enqueueMessage(
    to: string,
    msg: Omit<QueuedMessage, 'seq' | 'enqueuedAt'>,
    now: number,
    max: number,
  ): EnqueueResult {
    const tx = this.db.transaction((): EnqueueResult => {
      const depth = this.queueDepth(to);
      // Allow re enqueue of an existing id (dedupe) even at capacity.
      const existing = this.db.prepare('SELECT seq FROM queued_messages WHERE recipient = ? AND id = ?').get(to, msg.id) as
        | { seq: number }
        | undefined;
      if (existing) return { ok: true, seq: existing.seq };
      if (depth >= max) return { ok: false, reason: 'full' };
      const info = this.db
        .prepare(
          `INSERT OR IGNORE INTO queued_messages (recipient, id, sender, ciphertext, message_type, sent_at, enqueued_at)
           VALUES (?, ?, ?, ?, ?, ?, ?)`,
        )
        .run(to, msg.id, msg.from, msg.ciphertext, msg.messageType, msg.sentAt, now);
      return { ok: true, seq: Number(info.lastInsertRowid) };
    });
    return tx();
  }

  dequeueMessages(handle: string): QueuedMessage[] {
    const rows = this.db
      .prepare('SELECT seq, id, sender, ciphertext, message_type, sent_at, enqueued_at FROM queued_messages WHERE recipient = ? ORDER BY seq')
      .all(handle) as QueueRow[];
    return rows.map((r) => ({
      seq: r.seq,
      id: r.id,
      from: r.sender,
      ciphertext: r.ciphertext,
      messageType: r.message_type as CipherMessageType,
      sentAt: r.sent_at,
      enqueuedAt: r.enqueued_at,
    }));
  }

  ackMessage(handle: string, id: string): void {
    this.db.prepare('DELETE FROM queued_messages WHERE recipient = ? AND id = ?').run(handle, id);
  }

  queueDepth(handle: string): number {
    const row = this.db.prepare('SELECT COUNT(*) AS n FROM queued_messages WHERE recipient = ?').get(handle) as { n: number };
    return row.n;
  }

  deleteExpired(ttlSeconds: number, now: number): number {
    const cutoff = now - ttlSeconds * 1000;
    const info = this.db.prepare('DELETE FROM queued_messages WHERE enqueued_at < ?').run(cutoff);
    return info.changes;
  }

  close(): void {
    this.db.close();
  }
}
