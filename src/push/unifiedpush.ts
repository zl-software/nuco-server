// UnifiedPush sender. The relay acts as the application server and POSTs a tiny content
// free body to the device's registered distributor endpoint. No library is needed.
//
// The UnifiedPush spec expects a non empty body (1 to 4096 bytes), so a fixed placeholder is
// sent rather than an empty body, which some push servers reject. The body carries no
// message content.

import type { PushSender } from './sender.js';
import type { DeviceRecord } from '../storage/interface.js';
import { isSendablePushUrl } from './url-guard.js';

const WAKE_BODY = 'nuco-wake';
const REQUEST_TIMEOUT_MS = 10_000;

export class UnifiedPushSender implements PushSender {
  async sendWake(device: DeviceRecord): Promise<boolean> {
    if (device.push.kind !== 'unifiedpush' || !device.push.endpoint) return false;
    // Refuse endpoints that resolve to private/loopback/link-local addresses, so the relay
    // cannot be aimed at internal services.
    if (!(await isSendablePushUrl(device.push.endpoint))) return false;
    try {
      const response = await fetch(device.push.endpoint, {
        method: 'POST',
        headers: {
          'content-type': 'application/octet-stream',
          // Best effort delivery hints honored by common distributors such as ntfy.
          TTL: '2419200',
          Urgency: 'high',
        },
        body: WAKE_BODY,
        // Without a timeout a slow or hanging endpoint would pin a connection indefinitely.
        signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
      });
      return response.ok;
    } catch {
      return false;
    }
  }
}
