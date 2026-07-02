// SSRF guard for user supplied push endpoints. A UnifiedPush endpoint is an arbitrary URL
// the relay POSTs to when it wakes an offline device, so an attacker could register an
// endpoint that points at internal infrastructure (cloud metadata, localhost admin ports,
// private ranges) and use the relay as a confused deputy. Every endpoint is checked twice:
// a cheap syntactic check at registration time, and a full check that resolves the host and
// rejects private addresses right before the request is sent (which also defeats DNS
// rebinding, where a name resolves public at registration and private at send time).

import { isIP } from 'node:net';
import { lookup } from 'node:dns/promises';

function ipv4IsPrivate(addr: string): boolean {
  const parts = addr.split('.').map((p) => Number.parseInt(p, 10));
  if (parts.length !== 4 || parts.some((n) => !Number.isInteger(n) || n < 0 || n > 255)) return true;
  const [a, b] = parts as [number, number, number, number];
  if (a === 10) return true; // 10.0.0.0/8
  if (a === 127) return true; // loopback
  if (a === 0) return true; // 0.0.0.0/8 unspecified
  if (a === 169 && b === 254) return true; // link local, includes 169.254.169.254 metadata
  if (a === 172 && b >= 16 && b <= 31) return true; // 172.16.0.0/12
  if (a === 192 && b === 168) return true; // 192.168.0.0/16
  if (a === 100 && b >= 64 && b <= 127) return true; // 100.64.0.0/10 CGNAT
  if (a >= 224) return true; // multicast and reserved
  return false;
}

function ipv6IsPrivate(addr: string): boolean {
  const a = addr.toLowerCase();
  if (a === '::1' || a === '::') return true; // loopback, unspecified
  // IPv4 mapped (::ffff:a.b.c.d): judge by the embedded IPv4.
  const mapped = a.match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/);
  if (mapped) return ipv4IsPrivate(mapped[1]!);
  if (a.startsWith('fe8') || a.startsWith('fe9') || a.startsWith('fea') || a.startsWith('feb')) return true; // fe80::/10 link local
  if (a.startsWith('fc') || a.startsWith('fd')) return true; // fc00::/7 unique local
  return false;
}

function addressIsPrivate(addr: string): boolean {
  const kind = isIP(addr);
  if (kind === 4) return ipv4IsPrivate(addr);
  if (kind === 6) return ipv6IsPrivate(addr);
  return true; // not a parseable address: refuse
}

// Cheap check with no network I/O: must be an https URL whose host is not localhost and, if
// the host is a literal IP, not a private one. Used to reject obviously hostile endpoints at
// registration time.
export function isSyntacticallyPublicHttpsUrl(raw: string): boolean {
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    return false;
  }
  if (url.protocol !== 'https:') return false;
  const host = url.hostname.replace(/^\[|\]$/g, '');
  if (!host) return false;
  if (host === 'localhost' || host.endsWith('.localhost')) return false;
  if (isIP(host) !== 0) return !addressIsPrivate(host);
  return true;
}

// Full check used right before sending: syntactic, then resolve the hostname and reject if
// any resolved address is private. Returns false on any resolution failure.
export async function isSendablePushUrl(raw: string): Promise<boolean> {
  if (!isSyntacticallyPublicHttpsUrl(raw)) return false;
  const host = new URL(raw).hostname.replace(/^\[|\]$/g, '');
  if (isIP(host) !== 0) return !addressIsPrivate(host); // literal IP already vetted above
  try {
    const results = await lookup(host, { all: true });
    if (results.length === 0) return false;
    return results.every((r) => !addressIsPrivate(r.address));
  } catch {
    return false;
  }
}
