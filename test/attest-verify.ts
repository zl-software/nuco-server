import 'reflect-metadata';
// Unit test vectors for the App Attest verifier: a synthetic certificate chain built
// with @peculiar/x509 drives the happy path and every failure branch. The chain mimics
// Apple's shape (P-384 root and intermediate, P-256 credential certificate carrying the
// nonce extension); a real device fixture can be pinned later via the rootPem/now hooks.
//
// Run: npx tsx test/attest-verify.ts

import * as x509 from '@peculiar/x509';

import { verifyAppAttestation } from '../src/attest/verify';

x509.cryptoProvider.set(crypto);

let failures = 0;
function check(cond: boolean, label: string): void {
  if (cond) {
    console.log(`  ok  ${label}`);
  } else {
    console.error(`  FAIL ${label}`);
    failures += 1;
  }
}

const NONCE_EXTENSION_OID = '1.2.840.113635.100.8.2';
const APP_ID = 'TEAM00TEST.com.zlsoftware.nuco';
const CHALLENGE = 'dGVzdC1jaGFsbGVuZ2UtYmFzZTY0'; // the base64 STRING is the client data

function bytesToB64(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString('base64');
}

async function sha256(bytes: Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.digest('SHA-256', bytes as BufferSource));
}

// --- minimal CBOR encoder (test only; the production side only decodes) ---

function cborUint(major: number, value: number): number[] {
  if (value < 24) return [(major << 5) | value];
  if (value < 256) return [(major << 5) | 24, value];
  if (value < 65536) return [(major << 5) | 25, value >> 8, value & 0xff];
  return [(major << 5) | 26, (value >>> 24) & 0xff, (value >>> 16) & 0xff, (value >>> 8) & 0xff, value & 0xff];
}

type TestCbor = string | Uint8Array | TestCbor[] | { [key: string]: TestCbor };

function encodeCbor(value: TestCbor): Uint8Array {
  const out: number[] = [];
  const write = (v: TestCbor): void => {
    if (typeof v === 'string') {
      const bytes = new TextEncoder().encode(v);
      out.push(...cborUint(3, bytes.length), ...bytes);
    } else if (v instanceof Uint8Array) {
      out.push(...cborUint(2, v.length), ...v);
    } else if (Array.isArray(v)) {
      out.push(...cborUint(4, v.length));
      for (const item of v) write(item);
    } else {
      const keys = Object.keys(v);
      out.push(...cborUint(5, keys.length));
      for (const key of keys) {
        const keyBytes = new TextEncoder().encode(key);
        out.push(...cborUint(3, keyBytes.length), ...keyBytes);
        write(v[key]!);
      }
    }
  };
  write(value);
  return new Uint8Array(out);
}

// --- synthetic chain ---

function nonceExtensionValue(nonce: Uint8Array): Uint8Array {
  // SEQUENCE { [1] { OCTET STRING (32) } }
  return new Uint8Array([0x30, 0x24, 0xa1, 0x22, 0x04, 0x20, ...nonce]);
}

interface FixtureOptions {
  aaguid?: string; // 'production' | 'development' | 'garbage'
  signCount?: number;
  appId?: string;
  challenge?: string;
  credIdOverride?: Uint8Array;
  leafExpired?: boolean;
  swapChain?: boolean;
}

interface Fixture {
  keyIdB64: string;
  attestationB64: string;
  rootPem: string;
}

const AAGUIDS: Record<string, Uint8Array> = {
  production: new TextEncoder().encode('appattest\0\0\0\0\0\0\0'),
  development: new TextEncoder().encode('appattestdevelop'),
  garbage: new TextEncoder().encode('somethingelse!!!'),
};

async function makeFixture(opts: FixtureOptions = {}): Promise<Fixture> {
  const alg384 = { name: 'ECDSA', namedCurve: 'P-384' };
  const alg256 = { name: 'ECDSA', namedCurve: 'P-256' };
  const sig384 = { name: 'ECDSA', hash: 'SHA-384' };
  const sig256 = { name: 'ECDSA', hash: 'SHA-256' };

  const rootKeys = await crypto.subtle.generateKey(alg384, true, ['sign', 'verify']);
  const intermediateKeys = await crypto.subtle.generateKey(alg384, true, ['sign', 'verify']);
  const credKeys = await crypto.subtle.generateKey(alg256, true, ['sign', 'verify']);

  const now = Date.now();
  const day = 86_400_000;

  const root = await x509.X509CertificateGenerator.createSelfSigned({
    serialNumber: '01',
    name: 'CN=Test App Attest Root',
    notBefore: new Date(now - 30 * day),
    notAfter: new Date(now + 3650 * day),
    signingAlgorithm: sig384,
    keys: rootKeys,
    extensions: [new x509.BasicConstraintsExtension(true, undefined, true)],
  });

  const intermediate = await x509.X509CertificateGenerator.create({
    serialNumber: '02',
    subject: 'CN=Test App Attest Intermediate',
    issuer: root.subject,
    notBefore: new Date(now - 30 * day),
    notAfter: new Date(now + 3650 * day),
    signingAlgorithm: sig384,
    publicKey: intermediateKeys.publicKey,
    signingKey: rootKeys.privateKey,
    extensions: [new x509.BasicConstraintsExtension(true, 0, true)],
  });

  // The credential public key determines the key id, which feeds authData, which feeds
  // the nonce, which lands in the credential certificate's extension.
  const point = new Uint8Array(await crypto.subtle.exportKey('raw', credKeys.publicKey));
  const keyId = await sha256(point);

  const rpIdHash = await sha256(new TextEncoder().encode(opts.appId ?? APP_ID));
  const aaguid = AAGUIDS[opts.aaguid ?? 'production']!;
  const signCount = opts.signCount ?? 0;
  const credId = opts.credIdOverride ?? keyId;
  const authData = new Uint8Array(87);
  authData.set(rpIdHash, 0);
  authData[32] = 0x40; // attested credential data present
  authData[33] = (signCount >>> 24) & 0xff;
  authData[34] = (signCount >>> 16) & 0xff;
  authData[35] = (signCount >>> 8) & 0xff;
  authData[36] = signCount & 0xff;
  authData.set(aaguid, 37);
  authData[53] = 0;
  authData[54] = 32;
  authData.set(credId, 55);

  const clientDataHash = await sha256(new TextEncoder().encode(opts.challenge ?? CHALLENGE));
  const nonceInput = new Uint8Array(authData.length + 32);
  nonceInput.set(authData, 0);
  nonceInput.set(clientDataHash, authData.length);
  const nonce = await sha256(nonceInput);

  const credCert = await x509.X509CertificateGenerator.create({
    serialNumber: '03',
    subject: 'CN=Test Credential',
    issuer: intermediate.subject,
    notBefore: new Date(now - (opts.leafExpired ? 30 : 1) * day),
    notAfter: new Date(now + (opts.leafExpired ? -20 : 30) * day),
    signingAlgorithm: sig384,
    publicKey: credKeys.publicKey,
    signingKey: intermediateKeys.privateKey,
    extensions: [new x509.Extension(NONCE_EXTENSION_OID, false, nonceExtensionValue(nonce))],
  });

  const x5c = opts.swapChain
    ? [new Uint8Array(intermediate.rawData), new Uint8Array(credCert.rawData)]
    : [new Uint8Array(credCert.rawData), new Uint8Array(intermediate.rawData)];
  const attestation = encodeCbor({
    fmt: 'apple-appattest',
    attStmt: { x5c, receipt: new Uint8Array([1, 2, 3]) },
    authData,
  });

  return {
    keyIdB64: bytesToB64(keyId),
    attestationB64: bytesToB64(attestation),
    rootPem: root.toString('pem'),
  };
}

async function main(): Promise<void> {
  const base = { challenge: CHALLENGE, appId: APP_ID, acceptSandbox: false };

  const good = await makeFixture();
  const goodResult = await verifyAppAttestation(
    { ...base, keyIdB64: good.keyIdB64, attestationB64: good.attestationB64 },
    { rootPem: good.rootPem },
  );
  check(goodResult.ok && goodResult.environment === 'production', 'valid production attestation verifies');

  const wrongChallenge = await verifyAppAttestation(
    { ...base, challenge: 'c29tZXRoaW5nLWVsc2U=', keyIdB64: good.keyIdB64, attestationB64: good.attestationB64 },
    { rootPem: good.rootPem },
  );
  check(!wrongChallenge.ok && wrongChallenge.reason === 'nonce-mismatch', 'wrong challenge fails the nonce');

  const wrongApp = await verifyAppAttestation(
    { ...base, appId: 'TEAM00TEST.com.other.app', keyIdB64: good.keyIdB64, attestationB64: good.attestationB64 },
    { rootPem: good.rootPem },
  );
  check(!wrongApp.ok && wrongApp.reason === 'appid-mismatch', 'wrong app id fails');

  const realRoot = await verifyAppAttestation(
    { ...base, keyIdB64: good.keyIdB64, attestationB64: good.attestationB64 },
    {},
  );
  check(!realRoot.ok && realRoot.reason === 'chain-intermediate', 'synthetic chain does not verify against the pinned apple root');

  const tamperedKeyId = await verifyAppAttestation(
    { ...base, keyIdB64: bytesToB64(new Uint8Array(32).fill(7)), attestationB64: good.attestationB64 },
    { rootPem: good.rootPem },
  );
  check(!tamperedKeyId.ok && tamperedKeyId.reason === 'keyid-mismatch', 'tampered key id fails');

  const nonzero = await makeFixture({ signCount: 5 });
  const nonzeroResult = await verifyAppAttestation(
    { ...base, keyIdB64: nonzero.keyIdB64, attestationB64: nonzero.attestationB64 },
    { rootPem: nonzero.rootPem },
  );
  check(!nonzeroResult.ok && nonzeroResult.reason === 'signcount-nonzero', 'nonzero sign count fails');

  const sandbox = await makeFixture({ aaguid: 'development' });
  const sandboxRejected = await verifyAppAttestation(
    { ...base, keyIdB64: sandbox.keyIdB64, attestationB64: sandbox.attestationB64 },
    { rootPem: sandbox.rootPem },
  );
  check(!sandboxRejected.ok && sandboxRejected.reason === 'sandbox-rejected', 'development attestation rejected by default');
  const sandboxAccepted = await verifyAppAttestation(
    { ...base, acceptSandbox: true, keyIdB64: sandbox.keyIdB64, attestationB64: sandbox.attestationB64 },
    { rootPem: sandbox.rootPem },
  );
  check(sandboxAccepted.ok && sandboxAccepted.environment === 'development', 'development attestation accepted with the flag');

  const badGuid = await makeFixture({ aaguid: 'garbage' });
  const badGuidResult = await verifyAppAttestation(
    { ...base, keyIdB64: badGuid.keyIdB64, attestationB64: badGuid.attestationB64 },
    { rootPem: badGuid.rootPem },
  );
  check(!badGuidResult.ok && badGuidResult.reason === 'aaguid-unknown', 'unknown aaguid fails');

  const credMismatch = await makeFixture({ credIdOverride: new Uint8Array(32).fill(9) });
  const credResult = await verifyAppAttestation(
    { ...base, keyIdB64: credMismatch.keyIdB64, attestationB64: credMismatch.attestationB64 },
    { rootPem: credMismatch.rootPem },
  );
  check(!credResult.ok && credResult.reason === 'credid-mismatch', 'credential id mismatch fails');

  const expired = await makeFixture({ leafExpired: true });
  const expiredResult = await verifyAppAttestation(
    { ...base, keyIdB64: expired.keyIdB64, attestationB64: expired.attestationB64 },
    { rootPem: expired.rootPem },
  );
  check(!expiredResult.ok && expiredResult.reason === 'cert-expired', 'expired credential certificate fails');
  const pinnedNow = await verifyAppAttestation(
    { ...base, keyIdB64: expired.keyIdB64, attestationB64: expired.attestationB64 },
    { rootPem: expired.rootPem, now: new Date(Date.now() - 25 * 86_400_000) },
  );
  check(pinnedNow.ok, 'expired fixture verifies with an injected clock');

  const swapped = await makeFixture({ swapChain: true });
  const swappedResult = await verifyAppAttestation(
    { ...base, keyIdB64: swapped.keyIdB64, attestationB64: swapped.attestationB64 },
    { rootPem: swapped.rootPem },
  );
  check(!swappedResult.ok, 'swapped certificate order fails');

  const garbage = await verifyAppAttestation(
    { ...base, keyIdB64: good.keyIdB64, attestationB64: bytesToB64(new Uint8Array([0xff, 0x01, 0x02])) },
    { rootPem: good.rootPem },
  );
  check(!garbage.ok && garbage.reason === 'envelope-undecodable', 'garbage attestation fails to decode');

  const textEnvelope = await verifyAppAttestation(
    { ...base, keyIdB64: good.keyIdB64, attestationB64: bytesToB64(encodeCbor('just a string')) },
    { rootPem: good.rootPem },
  );
  check(!textEnvelope.ok && textEnvelope.reason === 'envelope-not-map', 'non map envelope fails');

  const wrongFmt = encodeCbor({ fmt: 'packed', attStmt: { x5c: [] }, authData: new Uint8Array(87) });
  const wrongFmtResult = await verifyAppAttestation(
    { ...base, keyIdB64: good.keyIdB64, attestationB64: bytesToB64(wrongFmt) },
    { rootPem: good.rootPem },
  );
  check(!wrongFmtResult.ok && wrongFmtResult.reason === 'wrong-fmt', 'non apple fmt fails');

  if (failures > 0) {
    console.error(`\nattest verify test FAILED with ${failures} failure(s)`);
    process.exit(1);
  }
  console.log('\nattest verify test OK');
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
