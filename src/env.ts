// Worker environment: bindings, vars, and secrets. Numeric settings arrive as strings
// (wrangler vars); parse with defaults matching the documented values in wrangler.jsonc.

import type { MailboxDO } from './mailbox';

export interface Env {
  MAILBOX: DurableObjectNamespace<MailboxDO>;
  // Rate limiting bindings (optional so a trimmed self host config still runs; every use
  // fails open when absent). REG_LIMIT gates new handle creation, CONN_LIMIT WebSocket
  // upgrades, both keyed per client IP (hashed, see ipRateKey).
  REG_LIMIT?: RateLimit;
  CONN_LIMIT?: RateLimit;
  // Vars
  QUEUE_MAX?: string;
  QUEUE_TTL_SECONDS?: string;
  RATE_MAX_PER_MIN?: string;
  MAX_MESSAGE_BYTES?: string;
  TURN_TTL_SECONDS?: string;
  SOCKETS_MAX_PER_HANDLE?: string;
  APNS_HOST?: string;
  // App Attest registration gating (relay policy, see PROTOCOL.md "App attestation").
  // ATTEST_REQUIRED=1 makes new handle creation demand a valid Apple App Attest
  // attestation for ATTEST_APP_ID (TEAMID.bundleid). Off by default: self hosted relays
  // and the local dev and test setups register plain. ATTEST_ACCEPT_SANDBOX=1 also
  // accepts development environment attestations (never set it on production).
  ATTEST_REQUIRED?: string;
  ATTEST_APP_ID?: string;
  ATTEST_ACCEPT_SANDBOX?: string;
  // Dev only (wrangler dev --var): DEV enables debug endpoints and mocks push sending;
  // TURN_TEST makes turnCredentials return canned credentials so tests cover the frame
  // path without a real TURN key.
  DEV?: string;
  TURN_TEST?: string;
  // Secrets
  TURN_KEY_ID?: string;
  TURN_KEY_SECRET?: string;
  APNS_KEY?: string;
  APNS_KEY_ID?: string;
  APNS_TEAM_ID?: string;
  APNS_BUNDLE_ID?: string;
}

export function intVar(v: string | undefined, fallback: number): number {
  if (v === undefined || v === '') return fallback;
  const n = Number.parseInt(v, 10);
  return Number.isFinite(n) && n > 0 ? n : fallback;
}

export function isDev(env: Env): boolean {
  return env.DEV === '1';
}

export function attestRequired(env: Env): boolean {
  return env.ATTEST_REQUIRED === '1';
}

// Rate limit keys are a truncated SHA-256 of the client IP, never the raw IP. The binding
// keeps per key counters for at most its 60 second window, per colo; the relay itself
// stores nothing.
export async function ipRateKey(ip: string): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(ip));
  return [...new Uint8Array(digest.slice(0, 16))].map((b) => b.toString(16).padStart(2, '0')).join('');
}

export type ApnsConfigState = 'off' | 'ok' | 'partial';

// The operator contract is all four APNs secrets or none. A partial set is a
// misconfiguration that would otherwise fail as a silent no-op push.
export function apnsConfigState(env: Env): ApnsConfigState {
  const set = [env.APNS_KEY, env.APNS_KEY_ID, env.APNS_TEAM_ID, env.APNS_BUNDLE_ID].filter(
    (v) => v !== undefined && v !== '',
  ).length;
  if (set === 0) return 'off';
  return set === 4 ? 'ok' : 'partial';
}
