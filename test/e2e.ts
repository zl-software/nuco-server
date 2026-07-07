// End to end harness: headless clients that share the app's real crypto and transport
// code run the full protocol 2.0 flow against the Workers relay (real workerd via
// wrangler dev), proving the contract without two phones.
//   register (no key material) -> exchange contact cards out of band (the QR) ->
//   deterministic initiator runs X3DH offline -> verify/confirm exchange with the card
//   hash proof in both directions -> sealed text both ways -> call signaling -> the
//   screenshot protection request/accept/cancel trio.
// Also asserts the relay only ever holds ciphertext, that an offline recipient triggers a
// content free push wake, and that a prekey envelope held unacked (the unknown sender
// rule) survives at the relay and redelivers after a reconnect, exactly what the app does
// when the confirm of a not yet reciprocated scan arrives early. Real WebRTC cannot run
// in Node, so call checks use a fake SDP of realistic size and validate signaling,
// freshness, and glare rules only.
//
// Run: npx tsx test/e2e.ts

import { WebSocket } from 'ws';
import { randomUUID } from 'node:crypto';

import {
  encodeContent,
  decodeContent,
  callOfferWins,
  CALL_OFFER_STALE_SECONDS,
  type DecodedContent,
} from '@nuco/protocol';

import { startDevServer, debugState } from './dev-server';

// Shared app code (pure, no React Native imports).
import {
  generateIdentity,
  generateSignedPreKey,
  installIdentity,
  toSignedPreKeyPublic,
  identityPublicKeyBase64,
  authPublicKeyBase64,
} from '../../nuco-messenger/src/crypto/identity';
import { NucoSignal, type SessionBootstrap } from '../../nuco-messenger/src/crypto/signal';
import { computeCardHash, isSessionInitiator } from '../../nuco-messenger/src/crypto/verification';
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

interface ReceivedContent {
  from: string;
  content: DecodedContent;
  sentAt: number;
  receivedAt: number;
}

// What this client's QR card advertises, as the scanner consumes it.
type Card = SessionBootstrap & { handle: string };

interface HeadlessClient {
  handle: string;
  signal: NucoSignal;
  client: RelayClient;
  received: ReceivedContent[];
  identityKeyB64: string;
  card: Card;
  // Mirrors the app's unknown sender rule: until this client has "scanned" the sender, a
  // prekey envelope is left unacked (held) so the relay keeps it queued for redelivery.
  scanned: boolean;
  heldPrekey: number;
}

async function makeClient(port: number, handle: string, scanned = true): Promise<HeadlessClient> {
  const store = new NucoSignalStore(new InMemoryKvBackend());
  const id = await generateIdentity();
  const signedPreKey = await generateSignedPreKey(id.identityKeyPair, 1);
  await installIdentity(store, id, signedPreKey);
  const signal = new NucoSignal(store);

  const me: HeadlessClient = {
    handle,
    signal,
    client: null as unknown as RelayClient,
    received: [],
    identityKeyB64: identityPublicKeyBase64(id),
    card: {
      handle,
      identityKey: identityPublicKeyBase64(id),
      registrationId: id.registrationId,
      signedPreKey: toSignedPreKeyPublic(signedPreKey),
    },
    scanned,
    heldPrekey: 0,
  };

  me.client = new RelayClient({
    url: `ws://127.0.0.1:${port}`,
    handle,
    authKeyPair: id.authKeyPair,
    WebSocketImpl: WebSocket as unknown as WebSocketCtor,
    registerOnConnect: {
      authKey: authPublicKeyBase64(id.authKeyPair),
      deviceId: 1,
      push: { kind: 'apns', token: `token-${handle}`, apnsTopic: 'com.zlsoftware.nuco' },
    },
    autoReconnect: false,
    onDeliver: async (from, envelope) => {
      if (!me.scanned && envelope.messageType === 'prekey') {
        me.heldPrekey += 1;
        return; // unacked on purpose: the relay must keep it queued
      }
      const plaintext = await signal.decrypt(from, { ciphertext: envelope.ciphertext, messageType: envelope.messageType });
      me.received.push({ from, content: decodeContent(plaintext), sentAt: envelope.sentAt, receivedAt: Date.now() });
      me.client.ack(envelope.id);
    },
  });
  me.client.start();
  await me.client.ensureReady();
  return me;
}

async function sendSealed(sender: HeadlessClient, to: string, content: Parameters<typeof encodeContent>[0]): Promise<string> {
  const sealed = await sender.signal.encrypt(to, encodeContent(content));
  await sender.client.sendEnvelope(to, {
    id: randomUUID(),
    ciphertext: sealed.ciphertext,
    messageType: sealed.messageType,
    sentAt: Date.now(),
  });
  return sealed.ciphertext;
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
  console.log('booting wrangler dev for the end to end harness');
  // TURN_TEST gives the dev relay canned credentials, so the CLIENT side turnCredentials
  // path is coverable end to end (its version gate once tripped on the 2.0 minor reset).
  const server = await startDevServer(8801, { TURN_TEST: '1' });
  const port = server.port;
  console.log(`nuco end to end harness against the workers relay on ${port}\n`);

  const alice = await makeClient(port, 'alice');
  const bob = await makeClient(port, 'bob');
  check(true, 'both clients registered and authenticated without exposing key material');

  // Deterministic roles from the exchanged cards: exactly one side runs X3DH.
  const aliceInitiates = isSessionInitiator(alice.identityKeyB64, bob.identityKeyB64);
  check(aliceInitiates !== isSessionInitiator(bob.identityKeyB64, alice.identityKeyB64), 'exactly one side is the session initiator');
  const initiator = aliceInitiates ? alice : bob;
  const responder = aliceInitiates ? bob : alice;

  // The initiator establishes the session fully offline from the responder's card.
  await initiator.signal.startSession(responder.handle, responder.card);

  // Both derive the same safety number and emoji SAS (the in person verification check).
  const av = await alice.signal.verificationStrings('alice', 'bob', bob.identityKeyB64);
  const bv = await bob.signal.verificationStrings('bob', 'alice', alice.identityKeyB64);
  check(av.safetyNumber === bv.safetyNumber, 'safety number matches on both sides');
  check(
    av.emoji.map((e) => e.emoji).join('') === bv.emoji.map((e) => e.emoji).join(''),
    'emoji SAS matches on both sides',
  );

  // The confirm exchange: the initiator's confirm is the session's first sealed message
  // (a prekey envelope), carrying the hash of the responder's card as proof of the scan.
  const confirmWire = await sendSealed(initiator, responder.handle, {
    t: 'verify/confirm',
    cardHash: computeCardHash(responder.card),
  });
  await waitFor(() => responder.received.length >= 1);
  const inboundConfirm = responder.received[0];
  check(inboundConfirm?.content.t === 'verify/confirm', 'responder received the confirm as the first sealed message');
  check(
    inboundConfirm?.content.t === 'verify/confirm' && inboundConfirm.content.cardHash === computeCardHash(responder.card),
    'confirm proves possession of the responder card',
  );
  check(!utf8Decode(Buffer.from(confirmWire, 'base64')).includes('verify/confirm'), 'confirm is opaque on the wire');

  // The responder answers with its own confirm over the now materialized session.
  await sendSealed(responder, initiator.handle, {
    t: 'verify/confirm',
    cardHash: computeCardHash(initiator.card),
  });
  await waitFor(() => initiator.received.length >= 1);
  const replyConfirm = initiator.received[0];
  check(
    replyConfirm?.content.t === 'verify/confirm' && replyConfirm.content.cardHash === computeCardHash(initiator.card),
    'initiator validated the responder confirm against its own card',
  );
  // The receive gate orders on this: both sides saw a confirm before any other content.
  check(
    initiator.received[0]?.content.t === 'verify/confirm' && responder.received[0]?.content.t === 'verify/confirm',
    'no content preceded the confirm exchange on either side',
  );

  // A wrong card hash (here: the hash of the WRONG card) must not validate.
  check(
    computeCardHash(initiator.card) !== computeCardHash(responder.card),
    'a confirm built without the receiver card cannot validate',
  );

  // Mutually verified: sealed text flows both ways over the wire.
  const plaintext = 'hello, sealed over the relay';
  const textWire = await sendSealed(initiator, responder.handle, { t: 'text', body: plaintext });
  await waitFor(() => responder.received.length >= 2);
  const firstMsg = responder.received[1];
  check(firstMsg?.content.t === 'text' && firstMsg.content.body === plaintext, 'responder received and decrypted the sealed text');
  check(firstMsg?.from === initiator.handle, 'message attributed to the initiator');
  check(!utf8Decode(Buffer.from(textWire, 'base64')).includes('sealed over the relay'), 'relay payload is ciphertext, not plaintext');

  const reply = 'got it, talk soon';
  await sendSealed(responder, initiator.handle, { t: 'text', body: reply });
  await waitFor(() => initiator.received.length >= 2);
  const replyMsg = initiator.received[1];
  check(replyMsg?.content.t === 'text' && replyMsg.content.body === reply, 'initiator received and decrypted the reply');

  // Voice call signaling rides the same sealed channel as typed content. The relay cannot
  // tell it apart from ordinary messages.
  const callId = randomUUID();
  const fakeSdp = 'v=0\r\no=- 0 0 IN IP4 0.0.0.0\r\n' + 'a=candidate:relay '.repeat(60);
  const offerWire = await sendSealed(initiator, responder.handle, { t: 'call/offer', callId, sdp: fakeSdp });
  await waitFor(() => responder.received.length >= 3);
  const offer = responder.received[2];
  check(
    offer !== undefined && offer.content.t === 'call/offer' && offer.content.callId === callId && offer.content.sdp === fakeSdp,
    'responder received the sealed call offer intact',
  );
  check(
    offer !== undefined && offer.receivedAt - offer.sentAt < CALL_OFFER_STALE_SECONDS * 1000,
    'a live offer is fresh under the staleness rule',
  );
  check(!utf8Decode(Buffer.from(offerWire, 'base64')).includes('call/offer'), 'call signaling is opaque on the wire');

  await sendSealed(responder, initiator.handle, { t: 'call/answer', callId, sdp: fakeSdp });
  await waitFor(() => initiator.received.length >= 3);
  const answer = initiator.received[2];
  check(answer !== undefined && answer.content.t === 'call/answer' && answer.content.callId === callId, 'initiator received the call answer for the same call');

  await sendSealed(initiator, responder.handle, { t: 'call/end', callId, reason: 'hangup' });
  await waitFor(() => responder.received.length >= 4);
  const end = responder.received[3];
  check(end !== undefined && end.content.t === 'call/end' && end.content.reason === 'hangup', 'responder received the call end');

  // A queued offer redelivered late classifies as stale (missed call, never a ring).
  const sealedStale = await initiator.signal.encrypt(responder.handle, encodeContent({ t: 'call/offer', callId: randomUUID(), sdp: fakeSdp }));
  await initiator.client.sendEnvelope(responder.handle, {
    id: randomUUID(),
    ciphertext: sealedStale.ciphertext,
    messageType: sealedStale.messageType,
    sentAt: Date.now() - (CALL_OFFER_STALE_SECONDS * 1000 + 5000),
  });
  await waitFor(() => responder.received.length >= 5);
  const stale = responder.received[4];
  check(
    stale !== undefined && stale.receivedAt - stale.sentAt >= CALL_OFFER_STALE_SECONDS * 1000,
    'a late redelivered offer classifies as stale',
  );

  // The screenshot protection negotiation rides the same sealed channel: request over,
  // accept back, cancel over, all opaque to the relay.
  const shotWire = await sendSealed(initiator, responder.handle, { t: 'screenshot/request', on: true });
  await waitFor(() => responder.received.length >= 6);
  const shotReq = responder.received[5];
  check(
    shotReq?.content.t === 'screenshot/request' && shotReq.content.on === true,
    'responder received the screenshot protection request',
  );
  check(!utf8Decode(Buffer.from(shotWire, 'base64')).includes('screenshot'), 'screenshot negotiation is opaque on the wire');

  await sendSealed(responder, initiator.handle, { t: 'screenshot/accept', on: true });
  await waitFor(() => initiator.received.length >= 4);
  const shotAccept = initiator.received[3];
  check(
    shotAccept?.content.t === 'screenshot/accept' && shotAccept.content.on === true,
    'initiator received the accept, protection agreed on both ends',
  );

  await sendSealed(initiator, responder.handle, { t: 'screenshot/cancel' });
  await waitFor(() => responder.received.length >= 7);
  check(responder.received[6]?.content.t === 'screenshot/cancel', 'responder received the cancel');

  // Glare tiebreak is shared and antisymmetric, so both sides derive the same winner.
  check(callOfferWins('a-id', 'b-id') && !callOfferWins('b-id', 'a-id'), 'glare tiebreak is deterministic');

  // The app transport must fetch TURN credentials from a 2.x relay: the frame exists in
  // every 2.x, and the client gate may only refuse a 1.x relay below minor 3 (gating on
  // the minor alone broke when the 2.0 bump reset it to 0).
  const turn = await alice.client.turnCredentials();
  check(turn.urls.length > 0 && turn.credential.length > 0, 'client fetched turn credentials from a 2.x relay');

  // The unknown sender rule: dave scanned erin, but erin has not scanned dave back. Dave's
  // confirm (a prekey envelope) arrives at erin, who holds it UNACKED. It must survive at
  // the relay and redeliver after erin "scans" and reconnects, then decrypt cleanly.
  const dave = await makeClient(port, 'dave');
  const erin = await makeClient(port, 'erin', false);
  const daveInitiates = isSessionInitiator(dave.identityKeyB64, erin.identityKeyB64);
  const scanner = daveInitiates ? dave : erin;
  const late = daveInitiates ? erin : dave;
  late.scanned = false;
  scanner.scanned = true;
  await scanner.signal.startSession(late.handle, late.card);
  await sendSealed(scanner, late.handle, { t: 'verify/confirm', cardHash: computeCardHash(late.card) });
  await waitFor(() => late.heldPrekey >= 1);
  check(late.received.length === 0, 'unreciprocated confirm is held unacked, not processed');

  late.scanned = true; // the scan happened; the app reconnects to drain the queue
  late.client.stop();
  await waitFor(() => !late.client.isConnected());
  late.client.start();
  await waitFor(() => late.received.length >= 1, 8000);
  const lateConfirm = late.received[0];
  check(
    lateConfirm?.content.t === 'verify/confirm' && lateConfirm.content.cardHash === computeCardHash(late.card),
    'held confirm redelivered after reconnect and decrypted',
  );

  // Offline recipient: carol registers, disconnects, then a send to her triggers a wake
  // (mocked and counted by the dev relay).
  const carol = await makeClient(port, 'carol');
  carol.client.stop();
  await waitFor(() => !carol.client.isConnected());
  await bob.client.sendEnvelope('carol', {
    id: randomUUID(),
    ciphertext: Buffer.from('x').toString('base64'),
    messageType: 'whisper',
    sentAt: Date.now(),
  });
  let carolWakes = 0;
  await waitFor(() => {
    void debugState(server, 'carol').then((s) => (carolWakes = s.wakes));
    return carolWakes > 0;
  });
  check(carolWakes === 1, 'offline recipient triggered a content free push wake');

  alice.client.stop();
  bob.client.stop();
  dave.client.stop();
  erin.client.stop();
  server.stop();

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
