// Apple App Attest attestation verification, following Apple's published steps
// (developer.apple.com, "Validating apps that connect to your server"). Runs entirely
// offline against the pinned Apple App Attestation Root CA: no call to Apple happens
// here. X.509 parsing and signature verification go through @peculiar/x509 over WebCrypto
// (never hand rolled); the CBOR envelope and the one custom DER extension are parsed by
// the strict local decoders in this directory.
//
// The challenge convention matters: the client passes the base64 challenge STRING from
// the connected frame to DCAppAttestService as UTF-8, so the client data hash here is
// SHA-256 over the UTF-8 bytes of that string, NOT over the decoded nonce bytes (the
// authenticate signature, by contrast, signs the decoded bytes). See PROTOCOL.md,
// "App attestation".

// tsyringe (used internally by @peculiar/x509) needs the Reflect metadata polyfill at
// module load, on workerd exactly as on Node. Keep this import first.
import 'reflect-metadata';
import * as x509 from '@peculiar/x509';

import { APPLE_APP_ATTEST_ROOT_PEM } from './apple-root';
import { decodeCbor, type CborMap } from './cbor';

const NONCE_EXTENSION_OID = '1.2.840.113635.100.8.2';
const VALIDITY_LEEWAY_MS = 5 * 60 * 1000;

// authData layout (WebAuthn authenticator data with Apple's attested credential data):
// rpIdHash [0..32), flags [32], signCount [33..37), aaguid [37..53), credential id
// length [53..55), credential id [55..87).
const AUTH_DATA_MIN_LEN = 87;

export interface AttestVerifyInput {
  keyIdB64: string;
  attestationB64: string;
  // The base64 challenge string exactly as it appeared in this socket's connected frame.
  challenge: string;
  // TEAMID.bundleid of the app the relay accepts.
  appId: string;
  acceptSandbox: boolean;
}

export type AttestVerifyResult =
  | { ok: true; environment: 'production' | 'development' }
  | { ok: false; reason: string };

interface VerifyOpts {
  rootPem?: string; // test hook: a synthetic root for fixture chains
  now?: Date; // test hook: pinned fixtures have expired leaf certificates
}

function b64ToBytes(b64: string): Uint8Array {
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i += 1) out[i] = bin.charCodeAt(i);
  return out;
}

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i += 1) diff |= a[i]! ^ b[i]!;
  return diff === 0;
}

async function sha256(bytes: Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.digest('SHA-256', bytes as BufferSource));
}

// Byte exact parse of the nonce extension value: SEQUENCE { [1] { OCTET STRING (32) } }.
// Returns the 32 nonce bytes or null on any structural mismatch.
function parseNonceExtension(value: Uint8Array): Uint8Array | null {
  let offset = 0;
  const readLen = (): number | null => {
    if (offset >= value.length) return null;
    const first = value[offset]!;
    offset += 1;
    if (first < 0x80) return first;
    if (first === 0x81) {
      if (offset >= value.length) return null;
      const len = value[offset]!;
      offset += 1;
      return len;
    }
    if (first === 0x82) {
      if (offset + 1 >= value.length) return null;
      const len = (value[offset]! << 8) | value[offset + 1]!;
      offset += 2;
      return len;
    }
    return null;
  };
  if (value[offset] !== 0x30) return null; // SEQUENCE
  offset += 1;
  const seqLen = readLen();
  if (seqLen === null || offset + seqLen !== value.length) return null;
  if (value[offset] !== 0xa1) return null; // context tag [1], constructed
  offset += 1;
  const ctxLen = readLen();
  if (ctxLen === null || offset + ctxLen !== value.length) return null;
  if (value[offset] !== 0x04) return null; // OCTET STRING
  offset += 1;
  const octLen = readLen();
  if (octLen !== 32 || offset + 32 !== value.length) return null;
  return value.subarray(offset, offset + 32);
}

function withinValidity(cert: x509.X509Certificate, now: Date): boolean {
  const t = now.getTime();
  return t >= cert.notBefore.getTime() - VALIDITY_LEEWAY_MS && t <= cert.notAfter.getTime() + VALIDITY_LEEWAY_MS;
}

const AAGUID_PRODUCTION = new TextEncoder().encode('appattest\0\0\0\0\0\0\0');
const AAGUID_DEVELOPMENT = new TextEncoder().encode('appattestdevelop');

export async function verifyAppAttestation(input: AttestVerifyInput, opts: VerifyOpts = {}): Promise<AttestVerifyResult> {
  const failed = (reason: string): AttestVerifyResult => ({ ok: false, reason });
  const now = opts.now ?? new Date();

  // 0. Decode the envelope. Anything structurally off is a verification failure, never a
  // thrown error escaping to the caller.
  let envelope: CborMap;
  let keyId: Uint8Array;
  try {
    keyId = b64ToBytes(input.keyIdB64);
    const decoded = decodeCbor(b64ToBytes(input.attestationB64));
    if (typeof decoded !== 'object' || decoded instanceof Uint8Array || Array.isArray(decoded)) {
      return failed('envelope-not-map');
    }
    envelope = decoded;
  } catch {
    return failed('envelope-undecodable');
  }
  if (envelope.fmt !== 'apple-appattest') return failed('wrong-fmt');
  const attStmt = envelope.attStmt;
  if (typeof attStmt !== 'object' || attStmt instanceof Uint8Array || Array.isArray(attStmt)) return failed('no-attstmt');
  const x5c = (attStmt as CborMap).x5c;
  if (!Array.isArray(x5c) || x5c.length < 2 || !x5c.every((c) => c instanceof Uint8Array)) return failed('bad-x5c');
  const authData = envelope.authData;
  if (!(authData instanceof Uint8Array) || authData.length < AUTH_DATA_MIN_LEN) return failed('bad-authdata');
  if (keyId.length !== 32) return failed('bad-keyid');

  try {
    // 1. Certificate chain: credCert signed by the intermediate, intermediate signed by
    // the pinned Apple root, all inside their validity windows (with leeway for skew).
    const credCert = new x509.X509Certificate(x5c[0] as Uint8Array<ArrayBuffer>);
    const intermediate = new x509.X509Certificate(x5c[1] as Uint8Array<ArrayBuffer>);
    const root = new x509.X509Certificate(opts.rootPem ?? APPLE_APP_ATTEST_ROOT_PEM);
    if (!withinValidity(credCert, now) || !withinValidity(intermediate, now) || !withinValidity(root, now)) {
      return failed('cert-expired');
    }
    if (!(await credCert.verify({ publicKey: intermediate, signatureOnly: true }, crypto))) {
      return failed('chain-cred');
    }
    if (!(await intermediate.verify({ publicKey: root, signatureOnly: true }, crypto))) {
      return failed('chain-intermediate');
    }

    // 2-4. Nonce: SHA-256(authData || SHA-256(utf8(challenge))) must equal the value in
    // the credCert's Apple nonce extension, compared byte exact after a strict DER walk.
    const clientDataHash = await sha256(new TextEncoder().encode(input.challenge));
    const nonceInput = new Uint8Array(authData.length + clientDataHash.length);
    nonceInput.set(authData, 0);
    nonceInput.set(clientDataHash, authData.length);
    const expectedNonce = await sha256(nonceInput);
    const ext = credCert.getExtension(NONCE_EXTENSION_OID);
    if (!ext) return failed('nonce-missing');
    const nonce = parseNonceExtension(new Uint8Array(ext.value));
    if (!nonce || !bytesEqual(nonce, expectedNonce)) return failed('nonce-mismatch');

    // 5. Key id: SHA-256 of the credCert's uncompressed P-256 public key point (the last
    // 65 bytes of the SPKI) must equal the claimed key id.
    const spki = new Uint8Array(credCert.publicKey.rawData);
    if (spki.length < 65) return failed('bad-cred-key');
    const point = spki.subarray(spki.length - 65);
    if (point[0] !== 0x04) return failed('bad-cred-key');
    if (!bytesEqual(await sha256(point), keyId)) return failed('keyid-mismatch');

    // 6. RP ID: the first 32 bytes of authData are SHA-256 of the expected app id.
    const rpIdHash = authData.subarray(0, 32);
    if (!bytesEqual(rpIdHash, await sha256(new TextEncoder().encode(input.appId)))) {
      return failed('appid-mismatch');
    }

    // 7. A fresh attestation always carries counter zero.
    const signCount =
      (authData[33]! << 24) | (authData[34]! << 16) | (authData[35]! << 8) | authData[36]!;
    if (signCount !== 0) return failed('signcount-nonzero');

    // 8. Environment marker.
    const aaguid = authData.subarray(37, 53);
    let environment: 'production' | 'development';
    if (bytesEqual(aaguid, AAGUID_PRODUCTION)) {
      environment = 'production';
    } else if (bytesEqual(aaguid, AAGUID_DEVELOPMENT)) {
      if (!input.acceptSandbox) return failed('sandbox-rejected');
      environment = 'development';
    } else {
      return failed('aaguid-unknown');
    }

    // 9. Credential id equals the key id.
    if (authData[53] !== 0 || authData[54] !== 32) return failed('credid-len');
    if (!bytesEqual(authData.subarray(55, 87), keyId)) return failed('credid-mismatch');

    return { ok: true, environment };
  } catch {
    return failed('verify-error');
  }
}
