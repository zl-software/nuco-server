// Worker environment: bindings, vars, and secrets. Numeric settings arrive as strings
// (wrangler vars); parse with defaults matching the documented values in wrangler.jsonc.

import type { MailboxDO } from './mailbox';

export interface Env {
  MAILBOX: DurableObjectNamespace<MailboxDO>;
  // Vars
  QUEUE_MAX?: string;
  QUEUE_TTL_SECONDS?: string;
  RATE_MAX_PER_MIN?: string;
  MAX_MESSAGE_BYTES?: string;
  TURN_TTL_SECONDS?: string;
  APNS_HOST?: string;
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
