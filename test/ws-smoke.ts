// Server level smoke test: drives the Workers relay (real workerd via wrangler dev) over
// real WebSockets with an Ed25519 auth key and placeholder ciphertext, exercising connect,
// register, authenticate, prekey publish and fetch, live delivery, ack, TURN credential
// issuance, the offline push wake, and the transport rules added in protocol 1.4 (handle
// in the URL, static ping auto response). Real Signal crypto is exercised by the two
// client end to end harness (test/e2e.ts).
//
// Run: npx tsx test/ws-smoke.ts

import { generateKeyPairSync, sign, type KeyObject } from 'node:crypto';
import { WebSocket } from 'ws';

import {
  PROTOCOL_VERSION,
  type ServerMessage,
  type MessageEnvelope,
  type PreKeyUpload,
} from '@nuco/protocol';

import { startDevServer, debugState, type DevServer } from './dev-server';

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
  public raw: ServerMessage[] = [];
  private onDeliver?: () => void;

  private constructor(
    ws: WebSocket,
    public readonly handle: string,
    private readonly auth: AuthKeys,
  ) {
    this.ws = ws;
    ws.on('message', (data) => this.onMessage(JSON.parse(data.toString()) as ServerMessage));
  }

  static connect(server: DevServer, handle: string, auth: AuthKeys): Promise<Client> {
    return new Promise((resolve, reject) => {
      const ws = new WebSocket(`${server.wsUrl}/?handle=${encodeURIComponent(handle)}`);
      ws.on('error', reject);
      ws.on('open', () => resolve(new Client(ws, handle, auth)));
    });
  }

  private onMessage(m: ServerMessage): void {
    this.raw.push(m);
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

  send(obj: unknown): void {
    this.ws.send(JSON.stringify(obj));
  }
  private rid(): string {
    this.ridCounter += 1;
    return `r${this.ridCounter}`;
  }
  request(build: (rid: string) => unknown): Promise<ServerMessage> {
    const rid = this.rid();
    return new Promise((resolve) => {
      this.pending.set(rid, resolve);
      this.send(build(rid));
    });
  }
  // A frame that gets a non rid reply (connect -> connected, ping -> pong).
  once(predicate: (m: ServerMessage) => boolean): Promise<ServerMessage> {
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
  console.log('booting wrangler dev for the smoke test');
  const server = await startDevServer(8800, { TURN_TEST: '1' });

  try {
    const aliceAuth = makeAuthKeys();
    const bobAuth = makeAuthKeys();
    const aliceIdentity = Buffer.from('alice-identity').toString('base64');
    const bobIdentity = Buffer.from('bob-identity').toString('base64');

    const alice = await Client.connect(server, 'alice', aliceAuth);
    const bob = await Client.connect(server, 'bob', bobAuth);

    await alice.handshake(aliceIdentity);
    await bob.handshake(bobIdentity);
    check(true, 'both clients registered and authenticated');

    // Transport rule (1.4): a socket without a handle in the URL is rejected at upgrade.
    const noHandle = new WebSocket(server.wsUrl);
    const rejected = await new Promise<boolean>((resolve) => {
      noHandle.on('error', () => resolve(true));
      noHandle.on('open', () => resolve(false));
    });
    check(rejected, 'socket without a url handle is rejected');

    // Transport rule (1.4): a connect frame whose handle differs from the url handle fails.
    const impostor = await Client.connect(server, 'mallory', makeAuthKeys());
    const mismatch = impostor.once((m) => m.type === 'error');
    impostor.send({ type: 'connect', protocolVersion: PROTOCOL_VERSION, handle: 'alice' });
    const mm = await mismatch;
    check(mm.type === 'error' && mm.code === 'MALFORMED_MESSAGE', 'url and frame handle mismatch rejected');
    impostor.close();

    // Static ping is answered (by the runtime auto response, without waking the mailbox).
    const pong = alice.once((m) => m.type === 'pong');
    alice.send({ type: 'ping', ts: 0 });
    check((await pong).type === 'pong', 'static ping answered');

    const pubResult = await alice.publishPreKeys(dummyUpload(1));
    check(pubResult.type === 'ok' && (pubResult.data?.oneTimeCount as number) === 2, 'alice published prekeys (2 one time)');

    const bundleMsg = await bob.fetchBundle('alice');
    check(bundleMsg.type === 'preKeyBundle', 'bob fetched alice prekey bundle');
    if (bundleMsg.type === 'preKeyBundle') {
      check(bundleMsg.bundle.identityKey === aliceIdentity, 'bundle carries alice identity key');
      check(bundleMsg.bundle.oneTimePreKey?.keyId === 1, 'bundle popped one time prekey id 1');
    }
    const missing = await bob.fetchBundle('nobody-here');
    check(missing.type === 'error' && missing.code === 'NO_SUCH_HANDLE', 'unknown handle yields NO_SUCH_HANDLE');

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
    await new Promise((r) => setTimeout(r, 200));
    check((await debugState(server, 'alice')).queueDepth === 0, 'queue empty after ack');

    // Offline wake: a third handle registered but not connected triggers a push wake
    // (mocked and counted in dev mode).
    const carol = await Client.connect(server, 'carol', makeAuthKeys());
    await carol.handshake(Buffer.from('carol-identity').toString('base64'));
    carol.close();
    await new Promise((r) => setTimeout(r, 200));
    await bob.sendMessage('carol', { id: 'msg-2', ciphertext: Buffer.from('x').toString('base64'), messageType: 'whisper', sentAt: 1 });
    await new Promise((r) => setTimeout(r, 200));
    const carolState = await debugState(server, 'carol');
    check(carolState.wakes === 1, 'offline recipient triggered a content free push wake');
    check(carolState.queueDepth === 1, 'message queued for offline carol');

    // TURN credentials (test mode: canned, exercising the frame path end to end).
    const turnMsg = await alice.turnCredentials();
    check(turnMsg.type === 'turnCredentialsResult', 'alice got turn credentials');
    if (turnMsg.type === 'turnCredentialsResult') {
      check(turnMsg.urls.length === 1 && turnMsg.urls[0] === 'turn:turn.test:3478?transport=udp', 'turn urls echo the test config');
      const nowSec = Math.floor(Date.now() / 1000);
      check(turnMsg.expiresAt >= nowSec + 7100 && turnMsg.expiresAt <= nowSec + 7300, 'expiry honors the default ttl');
      check(turnMsg.username.endsWith(':test') && turnMsg.credential.length > 0, 'credential shape is complete');
    }

    // TURN credentials require an authenticated socket.
    const dave = await Client.connect(server, 'dave', makeAuthKeys());
    const unauthTurn = await dave.turnCredentials();
    check(unauthTurn.type === 'error' && unauthTurn.code === 'UNAUTHENTICATED', 'turn credentials require auth');
    dave.close();

    // Version mismatch is rejected.
    const stranger = new WebSocket(`${server.wsUrl}/?handle=stranger`);
    await new Promise<void>((resolve) => stranger.on('open', () => resolve()));
    const mismatchReply = await new Promise<ServerMessage>((resolve) => {
      stranger.on('message', (d) => resolve(JSON.parse(d.toString()) as ServerMessage));
      stranger.send(JSON.stringify({ type: 'connect', protocolVersion: { major: 999, minor: 0 }, handle: 'stranger' }));
    });
    check(mismatchReply.type === 'error' && mismatchReply.code === 'PROTOCOL_VERSION_MISMATCH', 'major version mismatch rejected');
    stranger.close();

    alice.close();
    bob.close();
  } finally {
    server.stop();
  }

  // A relay without TURN configured answers CALLS_UNAVAILABLE (separate instance, no
  // TURN_TEST var and no TURN key secrets).
  console.log('booting a second instance without turn');
  const bare = await startDevServer(8802);
  try {
    const erin = await Client.connect(bare, 'erin', makeAuthKeys());
    await erin.handshake(Buffer.from('erin-identity').toString('base64'));
    const unavailable = await erin.turnCredentials();
    check(unavailable.type === 'error' && unavailable.code === 'CALLS_UNAVAILABLE', 'relay without turn answers CALLS_UNAVAILABLE');
    erin.close();
  } finally {
    bare.stop();
  }

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
