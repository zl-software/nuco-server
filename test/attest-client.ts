// Client side attestation flow against an ENFORCING relay, using the real app transport
// (RelayClient) with a fake attest provider. Proves the reactive negotiation end to end:
// a plain register is answered ATTESTATION_REQUIRED, the provider is then called with
// this socket's challenge, the attested retry reaches the relay, and only a real verify
// verdict surfaces through onError. Regression coverage for the launch blocker where a
// correlated ATTESTATION_REQUIRED reply also fired onError and tore the client down
// before the retry could run.
//
// Run: npx tsx test/attest-client.ts

import { WebSocket } from 'ws';

import { generateIdentity, authPublicKeyBase64 } from '../../nuco-messenger/src/crypto/identity';
import { NodeLibsignalBackend } from '../../nuco-messenger/src/crypto/backend-node';
import { RelayClient, type WebSocketCtor } from '../../nuco-messenger/src/transport/relay';

import { startDevServer } from './dev-server';

let failures = 0;
function check(cond: boolean, label: string): void {
  if (cond) {
    console.log(`  ok  ${label}`);
  } else {
    console.error(`  FAIL ${label}`);
    failures += 1;
  }
}

interface Outcome {
  errors: string[];
  providerChallenges: string[];
  connected: boolean;
}

async function runClient(port: number, handle: string, withProvider: boolean): Promise<Outcome> {
  // The identity key comes from the same official libsignal core the app uses; only the
  // transport auth key matters here, but the signature requires a backend since 3.0.
  const id = await generateIdentity(new NodeLibsignalBackend());
  const outcome: Outcome = { errors: [], providerChallenges: [], connected: false };
  const client = new RelayClient({
    url: `ws://127.0.0.1:${port}`,
    handle,
    authKeyPair: id.authKeyPair,
    WebSocketImpl: WebSocket as unknown as WebSocketCtor,
    registerOnConnect: {
      authKey: authPublicKeyBase64(id.authKeyPair),
      deviceId: 1,
      push: { kind: 'none' },
    },
    attestProvider: withProvider
      ? async (challenge) => {
          outcome.providerChallenges.push(challenge);
          // Synthetic attestation: structurally valid base64, guaranteed to fail the
          // relay's verification against the real Apple root.
          return {
            kind: 'apple-app-attest',
            keyId: Buffer.alloc(32, 7).toString('base64'),
            data: Buffer.from('not a real attestation').toString('base64'),
          };
        }
      : undefined,
    autoReconnect: false,
    onDeliver: () => {},
    onError: (code) => {
      outcome.errors.push(code);
    },
  });
  client.start();
  const ready = client.waitUntilReady(8000);
  outcome.connected = await ready;
  client.stop();
  return outcome;
}

async function main(): Promise<void> {
  console.log('booting an enforcing relay for the client attestation flow');
  const gated = await startDevServer(8806, { ATTEST_REQUIRED: '1', ATTEST_APP_ID: 'TEAM00TEST.com.zlsoftware.nuco' });
  try {
    const attested = await runClient(gated.port, 'attest-flow', true);
    check(attested.providerChallenges.length === 1, 'provider called exactly once with the challenge');
    check((attested.providerChallenges[0] ?? '').length > 0, 'provider received a nonempty challenge');
    check(attested.errors.includes('ATTESTATION_FAILED'), 'synthetic attestation surfaces ATTESTATION_FAILED');
    check(!attested.errors.includes('ATTESTATION_REQUIRED'), 'required verdict is not surfaced when the retry runs');
    check(!attested.connected, 'client does not report connected on a rejected registration');

    const bare = await runClient(gated.port, 'attest-none', false);
    check(bare.errors.includes('ATTESTATION_REQUIRED'), 'client without a provider surfaces ATTESTATION_REQUIRED');
  } finally {
    gated.stop();
  }

  console.log('booting a permissive relay to prove the provider stays idle');
  const open = await startDevServer(8808);
  try {
    const plain = await runClient(open.port, 'attest-open', true);
    check(plain.connected, 'client connects against a relay without enforcement');
    check(plain.providerChallenges.length === 0, 'provider is never called without enforcement');
    check(plain.errors.length === 0, 'no errors surface without enforcement');
  } finally {
    open.stop();
  }

  if (failures > 0) {
    console.error(`\nattest client flow FAILED with ${failures} failure(s)`);
    process.exit(1);
  }
  console.log('\nattest client flow OK');
  process.exit(0);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
