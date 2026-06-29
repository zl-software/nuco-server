// APNs push sender. Sends a content free background wake directly to Apple over HTTP/2 with
// an ES256 provider JWT signed by the .p8 key (jose). No Firebase, no third party library
// for the transport. The payload carries no message content and no sender identity.

import { connect, constants, type ClientHttp2Session } from 'node:http2';
import { readFileSync } from 'node:fs';

import { importPKCS8, SignJWT } from 'jose';

import type { ApnsConfig } from '../config.js';
import type { PushSender } from './sender.js';
import type { DeviceRecord } from '../storage/interface.js';

const TOKEN_TTL_MS = 45 * 60 * 1000; // refresh well under Apple's 1 hour limit

export class ApnsPushSender implements PushSender {
  private session: ClientHttp2Session | null = null;
  private signingKey: Awaited<ReturnType<typeof importPKCS8>> | null = null;
  private token: { value: string; mintedAt: number } | null = null;

  constructor(private readonly config: ApnsConfig) {}

  private async getSigningKey(): Promise<Awaited<ReturnType<typeof importPKCS8>>> {
    if (!this.signingKey) {
      const pem = readFileSync(this.config.keyPath, 'utf8');
      this.signingKey = await importPKCS8(pem, 'ES256');
    }
    return this.signingKey;
  }

  private async getToken(now: number): Promise<string> {
    if (this.token && now - this.token.mintedAt < TOKEN_TTL_MS) return this.token.value;
    const key = await this.getSigningKey();
    const value = await new SignJWT({})
      .setProtectedHeader({ alg: 'ES256', kid: this.config.keyId })
      .setIssuer(this.config.teamId)
      .setIssuedAt(Math.floor(now / 1000))
      .sign(key);
    this.token = { value, mintedAt: now };
    return value;
  }

  private ensureSession(): ClientHttp2Session {
    if (this.session && !this.session.closed && !this.session.destroyed) return this.session;
    const session = connect(`https://${this.config.host}`);
    session.on('error', () => session.destroy());
    session.on('goaway', () => session.close());
    this.session = session;
    return session;
  }

  async sendWake(device: DeviceRecord): Promise<boolean> {
    if (device.push.kind !== 'apns' || !device.push.token) return false;
    const token = await this.getToken(Date.now());
    const session = this.ensureSession();
    const topic = device.push.apnsTopic ?? this.config.bundleId;
    const payload = JSON.stringify({ aps: { 'content-available': 1 } });

    return new Promise<boolean>((resolve) => {
      const req = session.request({
        [constants.HTTP2_HEADER_METHOD]: 'POST',
        [constants.HTTP2_HEADER_PATH]: `/3/device/${device.push.token}`,
        [constants.HTTP2_HEADER_AUTHORIZATION]: `bearer ${token}`,
        'apns-topic': topic,
        'apns-push-type': 'background',
        'apns-priority': '5',
      });
      let status = 0;
      req.on('response', (headers) => {
        status = Number(headers[constants.HTTP2_HEADER_STATUS] ?? 0);
      });
      req.on('error', () => resolve(false));
      req.on('end', () => {
        if (status === 410) {
          // The device token is no longer valid. The caller may prune it.
          console.log(`[push:apns] token gone for ${device.handle} (410)`);
        }
        resolve(status >= 200 && status < 300);
      });
      req.setEncoding('utf8');
      req.on('data', () => {
        // Drain any error body; we only act on the status.
      });
      req.write(payload);
      req.end();
    });
  }

  close(): void {
    this.session?.close();
    this.session = null;
  }
}
