// A thin HTTP layer for health checks. Prekey operations run over the WebSocket, so this
// stays tiny and dependency free. WebSocket upgrades attach to the returned server.

import { createServer as createHttpServer, type Server } from 'node:http';
import { createServer as createHttpsServer } from 'node:https';
import { readFileSync } from 'node:fs';

import { PROTOCOL_VERSION } from '@nuco/protocol';
import type { Config } from '../config.js';

export function createServer(config: Config): Server {
  const handler = (req: import('node:http').IncomingMessage, res: import('node:http').ServerResponse): void => {
    if (req.method === 'GET' && req.url === '/health') {
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ status: 'ok', protocolVersion: PROTOCOL_VERSION }));
      return;
    }
    res.writeHead(404, { 'content-type': 'application/json' });
    res.end(JSON.stringify({ status: 'not_found' }));
  };

  if (config.tls) {
    return createHttpsServer(
      { cert: readFileSync(config.tls.cert), key: readFileSync(config.tls.key) },
      handler,
    ) as unknown as Server;
  }
  return createHttpServer(handler);
}
