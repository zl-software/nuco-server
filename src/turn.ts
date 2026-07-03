// Short lived TURN credentials for voice calls, in the TURN REST API scheme that coturn
// implements with use-auth-secret: the username is '<unixExpiry>:<id>' and the password is
// base64(HMAC-SHA1(static secret, username)). The TURN server recomputes the HMAC to verify,
// so nothing is stored on either side and every credential expires on its own. HMAC-SHA1 is
// what the scheme specifies; it is used as a MAC via the platform primitive in node:crypto
// (not hand rolled, and not relied on for collision resistance).
//
// The username suffix is a random id, not the handle: coturn writes usernames to its own
// logs, and keeping handles out of them avoids persisting a second handle to call time map
// on disk. The trade off is that coturn's user-quota binds per credential instead of per
// account; total-quota and max-bps still bound global abuse, and issuance already requires
// an authenticated socket. Never log the secret, a username, or a credential.

import { createHmac, randomBytes } from 'node:crypto';

import type { TurnConfig } from './config.js';

export interface IssuedTurnCredentials {
  urls: readonly string[];
  username: string;
  credential: string;
  expiresAt: number; // unix seconds
}

export function computeTurnPassword(secret: string, username: string): string {
  return createHmac('sha1', secret).update(username).digest('base64');
}

export function issueTurnCredentials(turn: TurnConfig, nowMs: number): IssuedTurnCredentials {
  const expiresAt = Math.floor(nowMs / 1000) + turn.ttlSeconds;
  const username = `${expiresAt}:${randomBytes(6).toString('hex')}`;
  return {
    urls: turn.urls,
    username,
    credential: computeTurnPassword(turn.secret, username),
    expiresAt,
  };
}
