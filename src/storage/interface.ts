// Storage contract for the relay. Everything content related is an opaque string the
// relay never interprets. The default implementation is SQLite (see sqlite.ts); the same
// interface can be backed by Postgres or Redis later without touching relay logic.

import type { PushRegistration, CipherMessageType, PreKeyBundle, PreKeyUpload } from '@nuco/protocol';

export interface DeviceRecord {
  handle: string;
  identityKey: string;
  authKey: string;
  registrationId: number;
  deviceId: number;
  push: PushRegistration;
  createdAt: number;
  lastSeen: number;
}

export interface QueuedMessage {
  seq: number;
  id: string;
  from: string;
  ciphertext: string;
  messageType: CipherMessageType;
  sentAt: number;
  enqueuedAt: number;
}

export type EnqueueResult = { ok: true; seq: number } | { ok: false; reason: 'full' };

export interface Storage {
  // Devices.
  registerDevice(rec: DeviceRecord): void;
  getDevice(handle: string): DeviceRecord | undefined;
  updatePush(handle: string, push: PushRegistration): void;
  touchDevice(handle: string, now: number): void;

  // Prekeys.
  publishPreKeys(handle: string, upload: PreKeyUpload): void;
  countOneTimePreKeys(handle: string): number;
  hasSignedPreKey(handle: string): boolean;
  // Pops one one time prekey atomically and returns the bundle, or undefined if unknown.
  takePreKeyBundle(handle: string): PreKeyBundle | undefined;

  // Message queue.
  enqueueMessage(to: string, msg: Omit<QueuedMessage, 'seq' | 'enqueuedAt'>, now: number, max: number): EnqueueResult;
  dequeueMessages(handle: string): QueuedMessage[];
  ackMessage(handle: string, id: string): void;
  queueDepth(handle: string): number;

  // Maintenance.
  deleteExpired(ttlSeconds: number, now: number): number;
  close(): void;
}
