# nuco-server

The untrusted store and forward relay. It transports sealed ciphertext, hosts public prekey
bundles, and sends content free push wakes. It can never read messages and holds no private
keys. See `../CLAUDE.md` for the whole project and `../protocol/PROTOCOL.md` for the contract.

Rules and invariants:
- Never log ciphertext or full who to whom maps beyond what an operation needs. No readable
  message content anywhere.
- Minimal, auditable dependencies only: `ws`, `jose`, `better-sqlite3`, plus Node built ins
  (`node:http`, `node:http2`). Do not add heavy frameworks.
- The relay never does content crypto and never holds private keys. Socket auth verifies a
  client Ed25519 signature over a challenge with Node built ins (`src/auth.ts`).
- Storage sits behind `src/storage/interface.ts`; the SQLite impl is the default. Keep all
  key and ciphertext columns opaque.
- No em dashes or en dashes. Commits look human authored (no AI attribution), conventional.

Run and verify:
- Dev: `npm run dev` (RELAY_DEV=1: no TLS, in memory SQLite, push mocked). Health at
  `/health`.
- `npm run typecheck`, `npm test` (WebSocket smoke test), `npm run test:e2e` (two headless
  clients exchange a real sealed message; it imports app crypto from
  `../nuco-messenger/src`, so it is excluded from `tsc` and validated by running).
- Self hosting: `Dockerfile`, `docker-compose.yml` (with Caddy for TLS), see `README.md`.
- APNs sending is `src/push/apns.ts` (node:http2 plus a jose ES256 JWT); runs without a `.p8`
  if none is configured. UnifiedPush is a plain HTTPS POST.
- Voice calls: `src/turn.ts` issues short lived TURN credentials (TURN REST scheme, HMAC via
  node:crypto, random usernames so handles never reach coturn logs). Without RELAY_TURN_*
  configured the relay answers CALLS_UNAVAILABLE. coturn is an opt in compose profile
  (`docker compose --profile calls up -d`); see README "Voice calls (TURN)". Never log a
  credential, username, or the secret.
