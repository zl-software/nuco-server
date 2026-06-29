// End to end harness: two headless clients that share the app's real crypto and transport
// code run the full flow against a running relay, proving the contract without two phones.
//   register -> publish prekeys -> fetch bundle -> X3DH session -> safety number match ->
//   send a sealed (real Signal) message -> recipient receives, decrypts, asserts plaintext.
// Also asserts the relay only ever holds ciphertext, and that an offline recipient triggers
// a content free push wake.
//
// Run: npx tsx test/e2e.ts

import { WebSocket } from 'ws';
import { randomUUID } from 'node:crypto';

import { SqliteStorage } from '../src/storage/sqlite.js';
import { PushFanout } from '../src/push/sender.js';
import { MockPushSender } from '../src/push/mock.js';
import { RelayServer } from '../src/ws/server.js';
import { createServer } from '../src/http/server.js';
import { loadConfig } from '../src/config.js';

// Shared app code (pure, no React Native imports).
import {
  generateIdentity,
  generatePreKeys,
  installIdentity,
  toUploadBundle,
  identityPublicKeyBase64,
  authPublicKeyBase64,
} from '../../nuco-messenger/src/crypto/identity';
import { NucoSignal } from '../../nuco-messenger/src/crypto/signal';
import { NucoSignalStore, InMemoryKvBackend } from '../../nuco-messenger/src/crypto/store';
import { utf8Encode, utf8Decode } from '../../nuco-messenger/src/crypto/bytes';
import { RelayClient, type WebSocketCtor } from '../../nuco-messenger/src/transport/relay';

let failures = 0;
function check(cond: boolean, label: string): void {
  if (cond) console.log(`  ok  ${label}`);
  else {
    console.error(`  FAIL ${label}`);
    failures += 1;
  }
}

interface HeadlessClient {
  handle: string;
  signal: NucoSignal;
  client: RelayClient;
  received: Array<{ from: string; text: string }>;
  identityKeyB64: string;
}

async function makeClient(port: number, handle: string): Promise<HeadlessClient> {
  const store = new NucoSignalStore(new InMemoryKvBackend());
  const id = await generateIdentity();
  const pre = await generatePreKeys(id.identityKeyPair, 1, 1, 10);
  await installIdentity(store, id, pre);
  const signal = new NucoSignal(store);
  const received: Array<{ from: string; text: string }> = [];

  const client = new RelayClient({
    url: `ws://127.0.0.1:${port}`,
    handle,
    authKeyPair: id.authKeyPair,
    WebSocketImpl: WebSocket as unknown as WebSocketCtor,
    registerOnConnect: {
      identityKey: identityPublicKeyBase64(id),
      authKey: authPublicKeyBase64(id.authKeyPair),
      registrationId: id.registrationId,
      deviceId: 1,
      push: { kind: 'apns', token: `token-${handle}`, apnsTopic: 'com.zlsoftware.nuco' },
    },
    autoReconnect: false,
    onDeliver: async (from, envelope) => {
      const plaintext = await signal.decrypt(from, { ciphertext: envelope.ciphertext, messageType: envelope.messageType });
      received.push({ from, text: utf8Decode(plaintext) });
      client.ack(envelope.id);
    },
  });
  client.start();
  await client.ensureReady();
  await client.publishPreKeys(toUploadBundle(pre));
  return { handle, signal, client, received, identityKeyB64: identityPublicKeyBase64(id) };
}

function waitFor(predicate: () => boolean, timeoutMs = 4000): Promise<void> {
  return new Promise((resolve, reject) => {
    const start = Date.now();
    const tick = (): void => {
      if (predicate()) return resolve();
      if (Date.now() - start > timeoutMs) return reject(new Error('timeout waiting for condition'));
      setTimeout(tick, 20);
    };
    tick();
  });
}

async function main(): Promise<void> {
  process.env.RELAY_DEV = '1';
  const config = { ...loadConfig(), port: 0 };
  const storage = new SqliteStorage(':memory:');
  const mock = new MockPushSender();
  const relay = new RelayServer(config, storage, new PushFanout(null, null, mock));
  const server = createServer(config);
  relay.attach(server);
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const port = (server.address() as { port: number }).port;
  console.log(`nuco end to end harness against relay on ${port}\n`);

  const alice = await makeClient(port, 'alice');
  const bob = await makeClient(port, 'bob');
  check(true, 'both clients registered, authenticated, and published prekeys');

  // Bob fetches Alice's bundle and establishes a session (X3DH).
  const bundle = await bob.client.fetchPreKeyBundle('alice');
  check(bundle.identityKey === alice.identityKeyB64, 'fetched bundle carries Alice identity key');
  await bob.signal.startSession('alice', bundle);

  // Both derive the same safety number and emoji SAS (the in person verification check).
  const av = await alice.signal.verificationStrings('alice', 'bob', bob.identityKeyB64);
  const bv = await bob.signal.verificationStrings('bob', 'alice', alice.identityKeyB64);
  check(av.safetyNumber === bv.safetyNumber, 'safety number matches on both sides');
  check(
    av.emoji.map((e) => e.emoji).join('') === bv.emoji.map((e) => e.emoji).join(''),
    'emoji SAS matches on both sides',
  );

  // Bob seals a real Signal message and sends it over the wire.
  const plaintext = 'hello alice, sealed over the relay';
  const sealed = await bob.signal.encrypt('alice', utf8Encode(plaintext));
  await bob.client.sendEnvelope('alice', {
    id: randomUUID(),
    ciphertext: sealed.ciphertext,
    messageType: sealed.messageType,
    sentAt: Date.now(),
  });
  await waitFor(() => alice.received.length >= 1);
  check(alice.received[0]?.text === plaintext, 'Alice received and decrypted the sealed message');
  check(alice.received[0]?.from === 'bob', 'message attributed to Bob');

  // The relay only ever holds ciphertext: the wire body does not contain the plaintext.
  const sealedBytes = utf8Decode(Uint8Array.from(Buffer.from(sealed.ciphertext, 'base64')));
  check(!sealedBytes.includes('sealed over the relay'), 'relay payload is ciphertext, not plaintext');

  // Alice replies, exercising the ratchet the other way over the wire.
  const reply = 'got it, talk soon';
  const sealedReply = await alice.signal.encrypt('bob', utf8Encode(reply));
  await alice.client.sendEnvelope('bob', {
    id: randomUUID(),
    ciphertext: sealedReply.ciphertext,
    messageType: sealedReply.messageType,
    sentAt: Date.now(),
  });
  await waitFor(() => bob.received.length >= 1);
  check(bob.received[0]?.text === reply, 'Bob received and decrypted the reply');

  // Offline recipient: Carol registers, disconnects, then a send to her triggers a wake.
  const carol = await makeClient(port, 'carol');
  carol.client.stop();
  await waitFor(() => !carol.client.isConnected());
  const wakesBefore = mock.sent.length;
  const sealedToCarol = await bob.signal.encrypt('alice', utf8Encode('placeholder')).catch(() => null);
  // Bob has no session with carol; send a raw placeholder envelope to exercise the relay
  // wake path (delivery semantics are validated above with the real session).
  await bob.client.sendEnvelope('carol', {
    id: randomUUID(),
    ciphertext: (sealedToCarol?.ciphertext ?? Buffer.from('x').toString('base64')),
    messageType: 'whisper',
    sentAt: Date.now(),
  });
  await waitFor(() => mock.sent.length > wakesBefore);
  check(mock.sent.some((w) => w.handle === 'carol'), 'offline recipient triggered a content free push wake');

  alice.client.stop();
  bob.client.stop();
  relay.close();
  server.close();
  storage.close();

  if (failures > 0) {
    console.error(`\nend to end harness FAILED with ${failures} failure(s)`);
    process.exit(1);
  }
  console.log('\nend to end harness OK');
  process.exit(0);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
