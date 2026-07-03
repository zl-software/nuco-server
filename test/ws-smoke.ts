// Server level smoke test: drives the relay over real WebSockets with an Ed25519 auth
// key and placeholder ciphertext, exercising connect, register, authenticate, prekey
// publish and fetch, live delivery, ack, TURN credential issuance, and the offline push
// wake. Real Signal crypto is exercised by the two client end to end harness (test/e2e.ts).
//
// Run: npx tsx test/ws-smoke.ts

import { generateKeyPairSync, sign, createHmac, type KeyObject } from 'node:crypto';
import { WebSocket } from 'ws';

import {
  PROTOCOL_VERSION,
  type ServerMessage,
  type MessageEnvelope,
  type PreKeyUpload,
} from '@nuco/protocol';

import { SqliteStorage } from '../src/storage/sqlite.js';
import { PushFanout } from '../src/push/sender.js';
import { MockPushSender } from '../src/push/mock.js';
import { RelayServer } from '../src/ws/server.js';
import { createServer } from '../src/http/server.js';
import { loadConfig } from '../src/config.js';
import { computeTurnPassword } from '../src/turn.js';

let failures = 0;
function check(cond: boolean, label: string): void {
  if (cond) {
    console.log(`  ok  ${label}`);
  } else {
    console.error(`  FAIL ${label}`);
    failures += 1;
  }
}

function rawEd25519PublicKeyB64(key: KeyObject): string {
  const jwk = key.export({ format: 'jwk' }) as { x: string };
  return Buffer.from(jwk.x, 'base64url').toString('base64');
}

interface AuthKeys {
  publicB64: string;
  privateKey: KeyObject;
}
function makeAuthKeys(): AuthKeys {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  return { publicB64: rawEd25519PublicKeyB64(publicKey), privateKey };
}

// A minimal promise based test client over the relay protocol.
class Client {
  private ws: WebSocket;
  private ridCounter = 0;
  private pending = new Map<string, (m: ServerMessage) => void>();
  public delivered: Array<{ from: string; envelope: MessageEnvelope }> = [];
  private onDeliver?: () => void;

  private constructor(
    ws: WebSocket,
    public readonly handle: string,
    private readonly auth: AuthKeys,
  ) {
    this.ws = ws;
    ws.on('message', (data) => this.onMessage(JSON.parse(data.toString()) as ServerMessage));
  }

  static connect(port: number, handle: string, auth: AuthKeys): Promise<Client> {
    return new Promise((resolve, reject) => {
      const ws = new WebSocket(`ws://localhost:${port}`);
      ws.on('error', reject);
      ws.on('open', () => resolve(new Client(ws, handle, auth)));
    });
  }

  private onMessage(m: ServerMessage): void {
    if ('rid' in m && m.rid && this.pending.has(m.rid)) {
      const resolve = this.pending.get(m.rid)!;
      this.pending.delete(m.rid);
      resolve(m);
      return;
    }
    if (m.type === 'deliver') {
      this.delivered.push({ from: m.from, envelope: m.envelope });
      this.onDeliver?.();
    }
  }

  private send(obj: unknown): void {
    this.ws.send(JSON.stringify(obj));
  }
  private rid(): string {
    this.ridCounter += 1;
    return `r${this.ridCounter}`;
  }
  private request(build: (rid: string) => unknown): Promise<ServerMessage> {
    const rid = this.rid();
    return new Promise((resolve) => {
      this.pending.set(rid, resolve);
      this.send(build(rid));
    });
  }
  // A frame that gets a non rid reply (connect -> connected).
  private once(predicate: (m: ServerMessage) => boolean): Promise<ServerMessage> {
    return new Promise((resolve) => {
      const handler = (data: Buffer): void => {
        const m = JSON.parse(data.toString()) as ServerMessage;
        if (predicate(m)) {
          this.ws.off('message', handler);
          resolve(m);
        }
      };
      this.ws.on('message', handler);
    });
  }

  async handshake(identityKeyB64: string): Promise<void> {
    const connected = this.once((m) => m.type === 'connected' || m.type === 'error');
    this.send({ type: 'connect', protocolVersion: PROTOCOL_VERSION, handle: this.handle });
    const c = await connected;
    if (c.type !== 'connected') throw new Error('connect failed');
    if (c.protocolVersion.major !== PROTOCOL_VERSION.major || c.protocolVersion.minor !== PROTOCOL_VERSION.minor) {
      throw new Error(
        `connected reply version ${c.protocolVersion.major}.${c.protocolVersion.minor} != relay ${PROTOCOL_VERSION.major}.${PROTOCOL_VERSION.minor}`,
      );
    }
    await this.request((rid) => ({
      type: 'register',
      rid,
      identityKey: identityKeyB64,
      authKey: this.auth.publicB64,
      registrationId: 1,
      deviceId: 1,
      push: { kind: 'apns', token: 'devtoken', apnsTopic: 'com.example' },
    }));
    const challengeBytes = Buffer.from(c.challenge, 'base64');
    const signature = sign(null, challengeBytes, this.auth.privateKey).toString('base64');
    const authed = this.once((m) => m.type === 'authenticated' || m.type === 'error');
    this.send({ type: 'authenticate', signature });
    const a = await authed;
    if (a.type !== 'authenticated') throw new Error('auth failed');
  }

  publishPreKeys(upload: PreKeyUpload): Promise<ServerMessage> {
    return this.request((rid) => ({ type: 'publishPreKeys', rid, preKeys: upload }));
  }
  fetchBundle(handle: string): Promise<ServerMessage> {
    return this.request((rid) => ({ type: 'fetchPreKeyBundle', rid, handle }));
  }
  sendMessage(to: string, envelope: MessageEnvelope): Promise<ServerMessage> {
    return this.request((rid) => ({ type: 'send', rid, to, envelope }));
  }
  turnCredentials(): Promise<ServerMessage> {
    return this.request((rid) => ({ type: 'turnCredentials', rid }));
  }
  ack(id: string): void {
    this.send({ type: 'ack', id });
  }
  waitForDeliver(): Promise<void> {
    if (this.delivered.length > 0) return Promise.resolve();
    return new Promise((resolve) => {
      this.onDeliver = resolve;
    });
  }
  close(): void {
    this.ws.close();
  }
}

function dummyUpload(seed: number): PreKeyUpload {
  return {
    signedPreKey: { keyId: 1, publicKey: Buffer.from(`spk${seed}`).toString('base64'), signature: Buffer.from('sig').toString('base64') },
    oneTimePreKeys: [
      { keyId: 1, publicKey: Buffer.from(`otp${seed}a`).toString('base64') },
      { keyId: 2, publicKey: Buffer.from(`otp${seed}b`).toString('base64') },
    ],
  };
}

async function main(): Promise<void> {
  process.env.RELAY_DEV = '1';
  const config = {
    ...loadConfig(),
    port: 0,
    turn: { secret: 'nuco-test-secret', urls: ['turn:turn.test:3478?transport=udp'], ttlSeconds: 600 },
  };
  const storage = new SqliteStorage(':memory:');
  const mock = new MockPushSender();
  const relay = new RelayServer(config, storage, new PushFanout(null, null, mock));
  const server = createServer(config);
  relay.attach(server);
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const port = (server.address() as { port: number }).port;
  console.log(`relay listening on ${port} for smoke test`);

  const aliceAuth = makeAuthKeys();
  const bobAuth = makeAuthKeys();
  const aliceIdentity = Buffer.from('alice-identity').toString('base64');
  const bobIdentity = Buffer.from('bob-identity').toString('base64');

  const alice = await Client.connect(port, 'alice', aliceAuth);
  const bob = await Client.connect(port, 'bob', bobAuth);

  await alice.handshake(aliceIdentity);
  await bob.handshake(bobIdentity);
  check(true, 'both clients registered and authenticated');

  const pubResult = await alice.publishPreKeys(dummyUpload(1));
  check(pubResult.type === 'ok' && (pubResult.data?.oneTimeCount as number) === 2, 'alice published prekeys (2 one time)');

  const bundleMsg = await bob.fetchBundle('alice');
  check(bundleMsg.type === 'preKeyBundle', 'bob fetched alice prekey bundle');
  if (bundleMsg.type === 'preKeyBundle') {
    check(bundleMsg.bundle.identityKey === aliceIdentity, 'bundle carries alice identity key');
    check(bundleMsg.bundle.oneTimePreKey?.keyId === 1, 'bundle popped one time prekey id 1');
  }

  // Live delivery: alice is connected, bob sends, alice receives and acks.
  const envelope: MessageEnvelope = {
    id: 'msg-1',
    ciphertext: Buffer.from('sealed-ciphertext-placeholder').toString('base64'),
    messageType: 'prekey',
    sentAt: 1234,
  };
  const sendResult = await bob.sendMessage('alice', envelope);
  check(sendResult.type === 'ok', 'bob send accepted');
  await alice.waitForDeliver();
  check(alice.delivered.length === 1, 'alice received one delivery');
  check(alice.delivered[0]?.envelope.ciphertext === envelope.ciphertext, 'delivered ciphertext matches');
  check(alice.delivered[0]?.from === 'bob', 'delivery is attributed to bob');
  alice.ack('msg-1');
  await new Promise((r) => setTimeout(r, 50));
  check(storage.queueDepth('alice') === 0, 'queue empty after ack');

  // Offline wake: a third handle registered but not connected triggers a push wake.
  const carolAuth = makeAuthKeys();
  const carol = await Client.connect(port, 'carol', carolAuth);
  await carol.handshake(Buffer.from('carol-identity').toString('base64'));
  carol.close();
  await new Promise((r) => setTimeout(r, 50));
  const beforeWakes = mock.sent.length;
  await bob.sendMessage('carol', { id: 'msg-2', ciphertext: Buffer.from('x').toString('base64'), messageType: 'whisper', sentAt: 1 });
  await new Promise((r) => setTimeout(r, 50));
  check(mock.sent.length === beforeWakes + 1, 'offline recipient triggered a content free push wake');
  check(storage.queueDepth('carol') === 1, 'message queued for offline carol');

  // TURN credentials: authenticated issuance with a verifiable HMAC.
  const turnMsg = await alice.turnCredentials();
  check(turnMsg.type === 'turnCredentialsResult', 'alice got turn credentials');
  if (turnMsg.type === 'turnCredentialsResult') {
    check(turnMsg.urls.length === 1 && turnMsg.urls[0] === 'turn:turn.test:3478?transport=udp', 'turn urls echo the config');
    check(/^\d+:[0-9a-f]{12}$/.test(turnMsg.username), 'turn username is expiry:randomid');
    check(turnMsg.expiresAt === Number(turnMsg.username.split(':')[0]), 'expiresAt matches the username expiry');
    const nowSec = Math.floor(Date.now() / 1000);
    check(turnMsg.expiresAt >= nowSec + 590 && turnMsg.expiresAt <= nowSec + 610, 'expiry honors the configured ttl');
    const expected = createHmac('sha1', 'nuco-test-secret').update(turnMsg.username).digest('base64');
    check(turnMsg.credential === expected, 'credential is HMAC-SHA1 over the username');
  }
  // Known answer vector: pins the algorithm (a matched change on both sides of the HMAC
  // recomputation above would otherwise slip through).
  check(
    computeTurnPassword('nuco-test-secret', '1700000000:testuser') === 'tmkZjBUsrItOKoRgRYlQXDLFGhQ=',
    'turn password matches the known answer vector',
  );

  // TURN credentials require an authenticated socket.
  const dave = await Client.connect(port, 'dave', makeAuthKeys());
  const unauthTurn = await dave.turnCredentials();
  check(unauthTurn.type === 'error' && unauthTurn.code === 'UNAUTHENTICATED', 'turn credentials require auth');
  dave.close();

  // A relay without TURN configured answers CALLS_UNAVAILABLE.
  const bareConfig = { ...loadConfig(), port: 0, turn: null };
  const bareStorage = new SqliteStorage(':memory:');
  const bareRelay = new RelayServer(bareConfig, bareStorage, new PushFanout(null, null, new MockPushSender()));
  const bareServer = createServer(bareConfig);
  bareRelay.attach(bareServer);
  await new Promise<void>((resolve) => bareServer.listen(0, '127.0.0.1', resolve));
  const barePort = (bareServer.address() as { port: number }).port;
  const erin = await Client.connect(barePort, 'erin', makeAuthKeys());
  await erin.handshake(Buffer.from('erin-identity').toString('base64'));
  const unavailable = await erin.turnCredentials();
  check(unavailable.type === 'error' && unavailable.code === 'CALLS_UNAVAILABLE', 'relay without turn answers CALLS_UNAVAILABLE');
  erin.close();
  bareRelay.close();
  bareServer.close();
  bareStorage.close();

  // Version mismatch is rejected.
  const stranger = new WebSocket(`ws://localhost:${port}`);
  await new Promise<void>((resolve) => stranger.on('open', () => resolve()));
  const mismatch = await new Promise<ServerMessage>((resolve) => {
    stranger.on('message', (d) => resolve(JSON.parse(d.toString()) as ServerMessage));
    stranger.send(JSON.stringify({ type: 'connect', protocolVersion: { major: 999, minor: 0 }, handle: 'x' }));
  });
  check(mismatch.type === 'error' && mismatch.code === 'PROTOCOL_VERSION_MISMATCH', 'major version mismatch rejected');
  stranger.close();

  alice.close();
  bob.close();
  relay.close();
  server.close();
  storage.close();

  if (failures > 0) {
    console.error(`\nws smoke test FAILED with ${failures} failure(s)`);
    process.exit(1);
  }
  console.log('\nws smoke test OK');
  process.exit(0);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
