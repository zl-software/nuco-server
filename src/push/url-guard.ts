// SSRF guard for user supplied push endpoints. A UnifiedPush endpoint is an arbitrary URL
// the relay POSTs to when it wakes an offline device. On Workers there is no resolver API
// for a pre-send DNS check, so the guard is syntactic: https only, no localhost, no
// private literal IPs. The runtime itself cannot reach Cloudflare internal or link local
// addresses from fetch, which covers the rebinding class the old Node resolver check
// existed for.

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
  const mapped = a.match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/);
  if (mapped) return ipv4IsPrivate(mapped[1]!);
  if (a.startsWith('fe8') || a.startsWith('fe9') || a.startsWith('fea') || a.startsWith('feb')) return true; // fe80::/10
  if (a.startsWith('fc') || a.startsWith('fd')) return true; // fc00::/7 unique local
  return false;
}

const IPV4_RE = /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/;

// Must be an https URL whose host is not localhost and, if the host is a literal IP, not a
// private one. Checked at registration time and again right before every send.
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
  if (IPV4_RE.test(host)) return !ipv4IsPrivate(host);
  if (host.includes(':')) return !ipv6IsPrivate(host);
  return true;
}
