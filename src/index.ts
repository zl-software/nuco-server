// Bootstrap the Nuco relay: config, storage, push fan out, HTTP health, and the
// WebSocket server.

import { mkdirSync } from 'node:fs';
import { dirname } from 'node:path';

import { PROTOCOL_VERSION_STRING } from '@nuco/protocol';
import { loadConfig } from './config.js';
import { SqliteStorage } from './storage/sqlite.js';
import { PushFanout } from './push/sender.js';
import { MockPushSender } from './push/mock.js';
import { ApnsPushSender } from './push/apns.js';
import { UnifiedPushSender } from './push/unifiedpush.js';
import { RelayServer } from './ws/server.js';
import { createServer } from './http/server.js';

function main(): void {
  const config = loadConfig();

  if (config.sqlitePath !== ':memory:') {
    mkdirSync(dirname(config.sqlitePath), { recursive: true });
  }
  const storage = new SqliteStorage(config.sqlitePath);

  // In dev mode the relay logs the wake instead of sending. In production it sends APNs (if
  // a .p8 is configured) and UnifiedPush directly.
  const mock = config.dev ? new MockPushSender() : null;
  const apns = config.apns ? new ApnsPushSender(config.apns) : null;
  const unifiedPush = new UnifiedPushSender();
  const fanout = new PushFanout(apns, unifiedPush, mock);

  const httpServer = createServer(config);
  const relay = new RelayServer(config, storage, fanout);
  relay.attach(httpServer);

  httpServer.listen(config.port, config.host, () => {
    const scheme = config.tls ? 'wss' : 'ws';
    console.log(
      `nuco-server: protocol ${PROTOCOL_VERSION_STRING}, ${scheme}://${config.host}:${config.port}` +
        (config.dev ? ' (dev mode: no TLS, push mocked)' : ''),
    );
  });

  const shutdown = (): void => {
    console.log('nuco-server: shutting down');
    relay.close();
    httpServer.close();
    storage.close();
    process.exit(0);
  };
  process.on('SIGINT', shutdown);
  process.on('SIGTERM', shutdown);
}

main();
