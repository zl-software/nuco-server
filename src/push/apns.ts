// Content free APNs push over fetch. The payload carries no message content and no sender
// identity: a visible generic banner whose text is a fixed localization key that the app
// bundle resolves on the device (Localizable.strings), so the relay stays locale blind.
// The literal English sentence is the key on purpose: iOS renders the raw key when the
// lookup fails, so builds without the strings file still show sensible text. A static
// collapse id folds a queue of N messages into a single banner.
//
// Transport note: Apple's provider API requires HTTP/2. Deployed Workers negotiate HTTP/2
// to the origin at the edge, which is the established pattern for APNs from Workers, but
// it is not exercisable under `wrangler dev` (local outbound fetch is HTTP/1.1 only), so
// dev mode mocks push sending entirely; verify APNs against a deployed Worker.

import { SignJWT, importPKCS8 } from 'jose';

import { apnsConfigState, type Env } from '../env';

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

// A partial secret set would silently no-op every push; complain once per isolate.
let warnedPartial = false;

export async function sendApnsWake(env: Env, deviceToken: string, apnsTopic: string | undefined): Promise<ApnsResult> {
  const state = apnsConfigState(env);
  if (state !== 'ok') {
    if (state === 'partial' && !warnedPartial) {
      warnedPartial = true;
      console.error('[push] apns config incomplete: set all of APNS_KEY, APNS_KEY_ID, APNS_TEAM_ID, APNS_BUNDLE_ID, or none');
    }
    return { sent: false, unregistered: false };
  }
  const jwt = await providerJwt(env);
  const host = env.APNS_HOST && env.APNS_HOST !== '' ? env.APNS_HOST : 'api.push.apple.com';
  const res = await fetch(`https://${host}/3/device/${deviceToken}`, {
    method: 'POST',
    headers: {
      authorization: `Bearer ${jwt}`,
      'apns-topic': apnsTopic ?? env.APNS_BUNDLE_ID ?? '',
      'apns-push-type': 'alert',
      'apns-priority': '10',
      'apns-collapse-id': 'nuco',
    },
    body: JSON.stringify({ aps: { alert: { 'loc-key': 'New message' }, sound: 'default' } }),
  });
  if (!res.ok && res.status !== 410) {
    // The APNs reason string ("InvalidProviderToken", "TopicDisallowed", ...) is safe to
    // log: it never contains the token or the payload.
    const reason = await res
      .json()
      .then((b) => (b as { reason?: string }).reason ?? 'unknown')
      .catch(() => 'unknown');
    console.error('[push] apns rejected', res.status, reason);
    // An expired provider token would otherwise keep failing for up to TOKEN_TTL_MS.
    if (res.status === 403) cachedJwt = null;
  }
  return { sent: res.ok, unregistered: res.status === 410 };
}

// A VoIP wake (PushKit): an incoming call for a device with no live socket. The payload
// is empty on purpose; iOS requires the app to report the push as an incoming call, and
// everything about the call stays inside the sealed envelope the app fetches on wake.
// The short expiry matches the ring window: a call wake delivered later than the caller
// keeps ringing would only produce a phantom call screen.
const VOIP_EXPIRY_SECONDS = 45;

export async function sendApnsVoipWake(env: Env, voipToken: string, apnsTopic: string | undefined): Promise<ApnsResult> {
  const state = apnsConfigState(env);
  if (state !== 'ok') {
    if (state === 'partial' && !warnedPartial) {
      warnedPartial = true;
      console.error('[push] apns config incomplete: set all of APNS_KEY, APNS_KEY_ID, APNS_TEAM_ID, APNS_BUNDLE_ID, or none');
    }
    return { sent: false, unregistered: false };
  }
  const jwt = await providerJwt(env);
  const host = env.APNS_HOST && env.APNS_HOST !== '' ? env.APNS_HOST : 'api.push.apple.com';
  const topic = `${apnsTopic ?? env.APNS_BUNDLE_ID ?? ''}.voip`;
  const res = await fetch(`https://${host}/3/device/${voipToken}`, {
    method: 'POST',
    headers: {
      authorization: `Bearer ${jwt}`,
      'apns-topic': topic,
      'apns-push-type': 'voip',
      'apns-priority': '10',
      'apns-expiration': String(Math.floor(Date.now() / 1000) + VOIP_EXPIRY_SECONDS),
    },
    body: JSON.stringify({ aps: {} }),
  });
  if (!res.ok && res.status !== 410) {
    const reason = await res
      .json()
      .then((b) => (b as { reason?: string }).reason ?? 'unknown')
      .catch(() => 'unknown');
    console.error('[push] apns voip rejected', res.status, reason);
    if (res.status === 403) cachedJwt = null;
  }
  return { sent: res.ok, unregistered: res.status === 410 };
}
