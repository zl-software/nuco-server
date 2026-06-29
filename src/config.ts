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
}

export function loadConfig(): Config {
  loadEnvFile();
  const dev = bool('RELAY_DEV', false) || process.argv.includes('--dev');

  const tlsCert = optStr('RELAY_TLS_CERT');
  const tlsKey = optStr('RELAY_TLS_KEY');
  const tls = !dev && tlsCert && tlsKey ? { cert: tlsCert, key: tlsKey } : null;

  const apnsKeyPath = optStr('APNS_KEY_PATH');
  const apns: ApnsConfig | null =
    !dev && apnsKeyPath
      ? {
          keyPath: apnsKeyPath,
          keyId: str('APNS_KEY_ID', ''),
          teamId: str('APNS_TEAM_ID', ''),
          bundleId: str('APNS_BUNDLE_ID', ''),
          host: str('APNS_HOST', 'api.push.apple.com'),
        }
      : null;

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
  };
}
