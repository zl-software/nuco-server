# nuco-server

The untrusted store and forward relay, running on Cloudflare Workers. One `MailboxDO`
Durable Object per handle owns that handle's device record, message queue (co-located
SQLite), and live hibernated WebSocket. It transports sealed ciphertext, sends content
free push wakes, and mints TURN credentials for calls. It can never read messages and,
since protocol 2.0, holds no Signal key material at all (prekeys travel only inside the
QR contact card; registration carries just the transport auth key and push routing). See
`../CLAUDE.md` for the whole project and `../protocol/PROTOCOL.md` for the contract.

Rules and invariants:
- Never log ciphertext, TURN credentials or keys, or full who to whom maps beyond what an
  operation needs. No readable message content anywhere.
- Minimal, auditable dependencies only: `jose` plus the platform (WebCrypto, fetch,
  Durable Objects). `ws` exists as a devDependency for the Node test clients only.
- The relay never does content crypto and never holds private keys. Socket auth verifies a
  client Ed25519 signature over a challenge with WebCrypto (`src/auth.ts`).
- The only cross handle operation is DO to DO RPC `deliver`; everything a handle owns
  stays inside its own mailbox object. Delivery is at least once: ack deletes, reconnect
  redelivers, dedupe by envelope id.
- The static heartbeat ping (`{"type":"ping","ts":0}`) is answered by the runtime auto
  response so hibernation is never broken by keepalives; do not make the ping dynamic.
- APNs goes over plain fetch (the edge negotiates HTTP/2 to Apple in production; wrangler
  dev cannot, so DEV mode mocks push). node:http2 does not exist on Workers.
- No em dashes or en dashes. Commits look human authored (no AI attribution), conventional.

Run and verify:
- Dev: `npm run dev` (wrangler dev with DEV=1: local workerd, push mocked, `/debug/state`).
- `npm run typecheck`, `npm test` (WebSocket smoke test), `npm run test:e2e` (two headless
  clients exchange real sealed messages and call signaling; it imports app crypto from
  `../nuco-messenger/src`). Both tests boot their own wrangler dev with fresh state.
- Deploy: `wrangler deploy` (custom domain nuco-server.zlsoftware.at in `wrangler.jsonc`;
  the zone must be on the account). Secrets via `wrangler secret put`: TURN_KEY_ID,
  TURN_KEY_SECRET, APNS_KEY (p8 PEM), APNS_KEY_ID, APNS_TEAM_ID, APNS_BUNDLE_ID.
- Voice calls: TURN credentials come from Cloudflare Realtime TURN (`src/turn.ts`);
  without the secrets the relay answers CALLS_UNAVAILABLE and messaging is unaffected.
