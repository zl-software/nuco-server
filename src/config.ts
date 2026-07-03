// Relay configuration from the environment. A tiny optional .env loader keeps local
// development friendly without adding a dependency.

import { existsSync, readFileSync } from 'node:fs';
import { resolve } from 'node:path';

function loadEnvFile(): void {
  const path = resolve(process.cwd(), process.env.RELAY_ENV_FILE ?? '.env');
  if (!existsSync(path)) return;
  for (const line of readFileSync(path, 'utf8').split('\n')) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#')) continue;
    const eq = trimmed.indexOf('=');
    if (eq === -1) continue;
    const key = trimmed.slice(0, eq).trim();
    let value = trimmed.slice(eq + 1).trim();
    if ((value.startsWith('"') && value.endsWith('"')) || (value.startsWith("'") && value.endsWith("'"))) {
      value = value.slice(1, -1);
    }
    if (process.env[key] === undefined) process.env[key] = value;
  }
}

function bool(name: string, fallback: boolean): boolean {
  const v = process.env[name];
  if (v === undefined) return fallback;
  return v === '1' || v.toLowerCase() === 'true';
}
function int(name: string, fallback: number): number {
  const v = process.env[name];
  if (v === undefined) return fallback;
  const n = Number.parseInt(v, 10);
  return Number.isFinite(n) ? n : fallback;
}
function str(name: string, fallback: string): string {
  const v = process.env[name];
  return v === undefined || v === '' ? fallback : v;
}
function optStr(name: string): string | undefined {
  const v = process.env[name];
  return v === undefined || v === '' ? undefined : v;
}

export interface ApnsConfig {
  keyPath: string;
  keyId: string;
  teamId: string;
  bundleId: string;
  host: string;
}

export interface TurnConfig {
  secret: string;
  urls: string[];
  ttlSeconds: number;
}

export interface Config {
  dev: boolean;
  host: string;
  port: number;
  tls: { cert: string; key: string } | null;
  sqlitePath: string;
  queueMax: number;
  queueTtlSeconds: number;
  rateMaxPerMin: number;
  maxMessageBytes: number;
  apns: ApnsConfig | null;
  turn: TurnConfig | null;
}

export function loadConfig(): Config {
  loadEnvFile();
  const dev = bool('RELAY_DEV', false) || process.argv.includes('--dev');

  const tlsCert = optStr('RELAY_TLS_CERT');
  const tlsKey = optStr('RELAY_TLS_KEY');
  const tls = !dev && tlsCert && tlsKey ? { cert: tlsCert, key: tlsKey } : null;

  const apnsKeyPath = optStr('APNS_KEY_PATH');
  let apns: ApnsConfig | null = null;
  if (!dev && apnsKeyPath) {
    // Fail fast on a partial APNs config: empty key id / team id / bundle id would produce
    // JWTs that APNs silently rejects, turning every push into a dead end with no signal.
    const keyId = optStr('APNS_KEY_ID');
    const teamId = optStr('APNS_TEAM_ID');
    const bundleId = optStr('APNS_BUNDLE_ID');
    const missing = [
      ['APNS_KEY_ID', keyId],
      ['APNS_TEAM_ID', teamId],
      ['APNS_BUNDLE_ID', bundleId],
    ]
      .filter(([, v]) => !v)
      .map(([name]) => name);
    if (missing.length > 0) {
      throw new Error(`APNS_KEY_PATH is set but ${missing.join(', ')} ${missing.length === 1 ? 'is' : 'are'} missing`);
    }
    apns = {
      keyPath: apnsKeyPath,
      keyId: keyId!,
      teamId: teamId!,
      bundleId: bundleId!,
      host: str('APNS_HOST', 'api.push.apple.com'),
    };
  }

  // TURN credential issuance for voice calls (src/turn.ts). Fail fast on a partial config:
  // a secret without urls advertises nothing a client can use, and urls without a secret
  // would issue credentials the TURN server rejects. Deliberately not gated on dev: a dev
  // relay pointed at a LAN coturn is the supported local call testing path, and a relay
  // without TURN vars simply answers CALLS_UNAVAILABLE. The TTL caps how long an
  // established call can refresh its TURN allocation, so it bounds call length too.
  const turnSecret = optStr('RELAY_TURN_SECRET');
  const turnUrlList = optStr('RELAY_TURN_URLS');
  let turn: TurnConfig | null = null;
  if (turnSecret || turnUrlList) {
    if (!turnSecret || !turnUrlList) {
      throw new Error('RELAY_TURN_SECRET and RELAY_TURN_URLS must be set together');
    }
    const urls = turnUrlList
      .split(',')
      .map((u) => u.trim())
      .filter((u) => u.length > 0);
    if (urls.length === 0 || !urls.every((u) => u.startsWith('turn:') || u.startsWith('turns:'))) {
      throw new Error('RELAY_TURN_URLS must be a comma separated list of turn: or turns: URLs');
    }
    turn = { secret: turnSecret, urls, ttlSeconds: int('RELAY_TURN_TTL_SECONDS', 7200) };
  }

  return {
    dev,
    host: str('RELAY_HOST', '0.0.0.0'),
    port: int('RELAY_PORT', 8787),
    tls,
    sqlitePath: dev ? str('RELAY_SQLITE_PATH', ':memory:') : str('RELAY_SQLITE_PATH', './data/nuco.sqlite'),
    queueMax: int('RELAY_QUEUE_MAX', 1000),
    queueTtlSeconds: int('RELAY_QUEUE_TTL_SECONDS', 2592000),
    rateMaxPerMin: int('RELAY_RATE_MAX_PER_MIN', 600),
    maxMessageBytes: int('RELAY_MAX_MESSAGE_BYTES', 131072),
    apns,
    turn,
  };
}
