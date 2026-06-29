// Dev mode push sender: logs the wake instead of contacting Apple or a UnifiedPush
// distributor, so contributors can run end to end without any push credentials.

import type { PushSender } from './sender.js';
import type { DeviceRecord } from '../storage/interface.js';

export class MockPushSender implements PushSender {
  public readonly sent: Array<{ handle: string; kind: string }> = [];

  async sendWake(device: DeviceRecord): Promise<boolean> {
    this.sent.push({ handle: device.handle, kind: device.push.kind });
    console.log(`[push:mock] content free wake for ${device.handle} via ${device.push.kind}`);
    return true;
  }
}
