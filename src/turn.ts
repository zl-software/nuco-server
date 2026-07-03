// Short lived TURN credentials for voice calls, minted by Cloudflare Realtime TURN
// (turn.cloudflare.com). The relay exchanges its long lived TURN key (secret) for
// per call credentials with a bounded TTL; nothing is stored, and the credential TTL
// caps how long an established call can refresh its allocation. Never log the key,
// a username, or a credential.

import type { Env } from './env';
import { intVar, isDev } from './env';

export interface IssuedTurnCredentials {
  urls: readonly string[];
  username: string;
  credential: string;
  expiresAt: number; // unix seconds
}

interface GenerateResponse {
  iceServers: { urls: string[]; username: string; credential: string };
}

// Returns null when TURN is not configured (the caller answers CALLS_UNAVAILABLE).
export async function issueTurnCredentials(env: Env): Promise<IssuedTurnCredentials | null> {
  const ttl = intVar(env.TURN_TTL_SECONDS, 7200);
  if (isDev(env) && env.TURN_TEST === '1') {
    // Test mode: canned credentials so the frame path is coverable without a real key.
    return {
      urls: ['turn:turn.test:3478?transport=udp'],
      username: `${Math.floor(Date.now() / 1000) + ttl}:test`,
      credential: 'dGVzdC1jcmVkZW50aWFs',
      expiresAt: Math.floor(Date.now() / 1000) + ttl,
    };
  }
  if (!env.TURN_KEY_ID || !env.TURN_KEY_SECRET) return null;

  const res = await fetch(`https://rtc.live.cloudflare.com/v1/turn/keys/${env.TURN_KEY_ID}/credentials/generate`, {
    method: 'POST',
    headers: {
      authorization: `Bearer ${env.TURN_KEY_SECRET}`,
      'content-type': 'application/json',
    },
    body: JSON.stringify({ ttl }),
  });
  if (!res.ok) throw new Error(`turn credential generation failed: ${res.status}`);
  const data = (await res.json()) as GenerateResponse;

  // Keep turn/turns urls only (the app forces relay only ICE, stun is unused) and drop
  // the port 53 variants (blocked by many networks and not needed).
  const urls = data.iceServers.urls.filter((u) => (u.startsWith('turn:') || u.startsWith('turns:')) && !u.includes(':53?'));
  // The TURN REST username embeds the unix expiry as its first colon separated field.
  const embedded = Number(data.iceServers.username.split(':')[0]);
  const expiresAt = Number.isFinite(embedded) && embedded > 0 ? embedded : Math.floor(Date.now() / 1000) + ttl;
  return { urls, username: data.iceServers.username, credential: data.iceServers.credential, expiresAt };
}
