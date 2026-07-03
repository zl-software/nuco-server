// Content free UnifiedPush wake: a tiny fixed body POSTed to the endpoint the device
// registered with its distributor. The endpoint is untrusted input; it is re-checked with
// the SSRF guard on every send, not only at registration.

import { isSyntacticallyPublicHttpsUrl } from './url-guard';

export async function sendUnifiedPushWake(endpoint: string): Promise<boolean> {
  if (!isSyntacticallyPublicHttpsUrl(endpoint)) return false;
  try {
    const res = await fetch(endpoint, {
      method: 'POST',
      headers: {
        'content-type': 'application/octet-stream',
        ttl: '2419200',
        urgency: 'high',
      },
      body: 'nuco-wake',
      signal: AbortSignal.timeout(10_000),
    });
    return res.ok;
  } catch {
    return false;
  }
}
