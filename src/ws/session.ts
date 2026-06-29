// Per connection state for one WebSocket.

import type { WebSocket } from 'ws';
import type { ServerMessage } from '@nuco/protocol';

export class Session {
  handle: string | null = null; // claimed via connect, confirmed via authenticate
  authenticated = false;
  challenge: string | null = null;
  alive = true; // heartbeat liveness

  constructor(
    public readonly ws: WebSocket,
    public readonly ip: string,
  ) {}

  send(msg: ServerMessage): void {
    if (this.ws.readyState === this.ws.OPEN) {
      this.ws.send(JSON.stringify(msg));
    }
  }
}
