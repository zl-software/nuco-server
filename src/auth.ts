// Socket authentication: the client signs a random challenge with its Ed25519 transport
// auth key (separate from the Signal identity key; see PROTOCOL.md). Verification uses the
// runtime WebCrypto Ed25519 support; the relay never holds a private key.

import { base64ToBytes, bytesToBase64 } from './bytes';

export function makeChallenge(): string {
  const nonce = new Uint8Array(32);
  crypto.getRandomValues(nonce);
  return bytesToBase64(nonce);
}

// authKeyB64 is a raw 32 byte Ed25519 public key, signatureB64 a 64 byte signature over
// the raw challenge bytes. Any malformed input verifies false rather than throwing.
export async function verifyAuthSignature(authKeyB64: string, challengeB64: string, signatureB64: string): Promise<boolean> {
  try {
    const publicKey = base64ToBytes(authKeyB64);
    const signature = base64ToBytes(signatureB64);
    const message = base64ToBytes(challengeB64);
    if (publicKey.length !== 32 || signature.length !== 64) return false;
    const key = await crypto.subtle.importKey('raw', publicKey, { name: 'Ed25519' }, false, ['verify']);
    return await crypto.subtle.verify({ name: 'Ed25519' }, key, signature, message);
  } catch {
    return false;
  }
}
