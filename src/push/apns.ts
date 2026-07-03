// Content free APNs wake over fetch. The payload carries no message content and no sender
// identity, only content-available so iOS wakes the app to pull from the relay.
//
// Transport note: Apple's provider API requires HTTP/2. Deployed Workers negotiate HTTP/2
// to the origin at the edge, which is the established pattern for APNs from Workers, but
// it is not exercisable under `wrangler dev` (local outbound fetch is HTTP/1.1 only), so
// dev mode mocks push sending entirely; verify APNs against a deployed Worker.

import { SignJWT, importPKCS8 } from 'jose';

import type { Env } from '../env';

const TOKEN_TTL_MS = 45 * 60 * 1000; // Apple accepts provider tokens for up to an hour

// Cached per isolate; safe because the JWT carries no per device data.
let cachedJwt: { token: string; mintedAt: number; keyId: string } | null = null;

async function providerJwt(env: Env): Promise<string> {
  const now = Date.now();
  if (cachedJwt && cachedJwt.keyId === env.APNS_KEY_ID && now - cachedJwt.mintedAt < TOKEN_TTL_MS) {
    return cachedJwt.token;
  }
  const key = await importPKCS8(env.APNS_KEY!, 'ES256');
  const token = await new SignJWT({})
    .setProtectedHeader({ alg: 'ES256', kid: env.APNS_KEY_ID! })
    .setIssuer(env.APNS_TEAM_ID!)
    .setIssuedAt()
    .sign(key);
  cachedJwt = { token, mintedAt: now, keyId: env.APNS_KEY_ID! };
  return token;
}

export interface ApnsResult {
  sent: boolean;
  // HTTP 410: the token is no longer valid for the topic; the caller prunes it.
  unregistered: boolean;
}

export async function sendApnsWake(env: Env, deviceToken: string, apnsTopic: string | undefined): Promise<ApnsResult> {
  if (!env.APNS_KEY || !env.APNS_KEY_ID || !env.APNS_TEAM_ID) return { sent: false, unregistered: false };
  const jwt = await providerJwt(env);
  const host = env.APNS_HOST && env.APNS_HOST !== '' ? env.APNS_HOST : 'api.push.apple.com';
  const res = await fetch(`https://${host}/3/device/${deviceToken}`, {
    method: 'POST',
    headers: {
      authorization: `Bearer ${jwt}`,
      'apns-topic': apnsTopic ?? env.APNS_BUNDLE_ID ?? '',
      'apns-push-type': 'background',
      'apns-priority': '5',
    },
    body: JSON.stringify({ aps: { 'content-available': 1 } }),
  });
  return { sent: res.ok, unregistered: res.status === 410 };
}
