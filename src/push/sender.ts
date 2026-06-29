// Push fan out. When a recipient has no live socket, the relay sends a content free wake
// so the device opens its WebSocket and pulls the queued ciphertext. The wake carries no
// message content and no cleartext sender identity.
//
// The concrete senders (APNs over HTTP/2, UnifiedPush POST) are wired in the push
// milestone. In dev mode, or when no real sender is configured, the mock logs the wake.

import type { DeviceRecord } from '../storage/interface.js';

export interface PushSender {
  // Send a content free wake to the device. Implementations must never include message
  // content. Returns true if the wake was dispatched.
  sendWake(device: DeviceRecord): Promise<boolean>;
}

export class PushFanout {
  constructor(
    private readonly apns: PushSender | null,
    private readonly unifiedPush: PushSender | null,
    private readonly mock: PushSender | null,
  ) {}

  async wake(device: DeviceRecord): Promise<boolean> {
    if (this.mock) return this.mock.sendWake(device);
    if (device.push.kind === 'apns' && this.apns) return this.apns.sendWake(device);
    if (device.push.kind === 'unifiedpush' && this.unifiedPush) return this.unifiedPush.sendWake(device);
    return false;
  }
}
