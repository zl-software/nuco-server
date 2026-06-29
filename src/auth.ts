// Socket authentication. The relay issues a random challenge nonce and verifies the
// client's Ed25519 signature over it using Node's built in crypto, so no Signal specific
// crypto and no extra dependency are needed. The transport auth key is separate from the
// Signal identity key.

import { randomBytes, createPublicKey, verify } from 'node:crypto';

export function makeChallenge(): string {
  return randomBytes(32).toString('base64');
}

export function verifyAuthSignature(
  authKeyB64: string,
  challengeB64: string,
  signatureB64: string,
): boolean {
  try {
    const raw = Buffer.from(authKeyB64, 'base64');
    if (raw.length !== 32) return false;
    const sig = Buffer.from(signatureB64, 'base64');
    if (sig.length !== 64) return false;
    const pub = createPublicKey({
      key: { kty: 'OKP', crv: 'Ed25519', x: raw.toString('base64url') },
      format: 'jwk',
    });
    const message = Buffer.from(challengeB64, 'base64');
    return verify(null, message, pub, sig);
  } catch {
    return false;
  }
}
