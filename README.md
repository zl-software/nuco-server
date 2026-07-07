# nuco-server

The Nuco relay: an untrusted store and forward server for sealed ciphertext, content free
push wakes, and TURN credentials for voice calls. It runs on Cloudflare Workers: one
Durable Object per handle holds that handle's device record, message queue, and live
WebSocket (hibernated while idle). It can never read messages and holds no key material
at all beyond the transport auth public key (since protocol 2.0 all Signal keys travel
only inside the in person QR contact card).

See `../protocol/PROTOCOL.md` for the wire contract this server implements.

## Trust model

The relay only ever sees ciphertext plus routing metadata. It cannot see message content,
display names in messages, or any private key. It can see which handles are in contact,
timing, and a padded message size bucket. Because the relay runs on Cloudflare Workers,
that metadata (plus client IPs and, for calls, TURN allocation timing and volume) is
visible to Cloudflare as the infrastructure operator; sealed content and DTLS-SRTP call
media remain unreadable. Self hosting means deploying this Worker on your own Cloudflare
account. The app states all of this plainly on its About and Privacy screen.

## Architecture

- `src/worker.ts`: entry. `/health`, WebSocket routing (the client carries its handle in
  the URL query since protocol 1.4), dev only `/debug/state`.
- `src/mailbox.ts`: `MailboxDO`, one Durable Object per handle. Co-located SQLite holds
  the device record and inbox; the socket is a hibernatable WebSocket (the static
  heartbeat ping is answered at the edge without waking the object). The only cross
  handle operation (`send`) is DO to DO RPC. A per object alarm sweeps expired queued
  messages.
- `src/auth.ts`: Ed25519 challenge verification via WebCrypto.
- `src/push/`: APNs (ES256 JWT via jose, sent with fetch) and UnifiedPush (plain POST,
  SSRF guarded). Payloads are content free.
- `src/turn.ts`: voice call TURN credentials minted by Cloudflare Realtime TURN.

## Requirements

- Node 24 LTS and npm (for tooling; the relay itself runs on Workers).
- A Cloudflare account on the Workers paid plan (Durable Objects).
- The shared [`@nuco/protocol`](https://github.com/zl-software/nuco-protocol) package in a
  sibling folder named `protocol` (the `file:../protocol` dependency resolves against that
  exact path). Clone both repos side by side and build the protocol once:

  ```
  git clone https://github.com/zl-software/nuco-server
  git clone https://github.com/zl-software/nuco-protocol protocol
  npm --prefix protocol install && npm --prefix protocol run build
  ```

## Development

```
npm install
npm run dev        # wrangler dev with DEV=1: local workerd, push mocked, debug endpoints
```

Dev mode listens on `ws://localhost:8787`. Point the app at it with
`EXPO_PUBLIC_RELAY_URL=ws://<LAN_IP>:8787`. Run the tests (each boots its own wrangler dev
with fresh state):

```
npm run typecheck
npm test           # server level WebSocket smoke test
npm run test:e2e   # two headless clients exchange real sealed messages and call signaling
```

`npm test` is self contained (it needs only the sibling protocol build). `npm run
test:e2e` additionally imports the real app crypto and transport from a sibling
`nuco-messenger` checkout; that repo is not public yet, so outside contributors cannot
run the e2e harness. Typecheck and the smoke test cover the server on its own.

## Deployment

Self hosting (the top level config in `wrangler.jsonc`): a bare deploy ships to your
account's workers.dev subdomain with no config edits.

```
npx wrangler login
npx wrangler deploy
curl https://nuco-server.<your-subdomain>.workers.dev/health
```

Then point the app at `wss://nuco-server.<your-subdomain>.workers.dev` (Settings, then
Server). For a custom domain, add a `routes` entry with `custom_domain: true` to the top
level of `wrangler.jsonc` (the zone must be on your account; Cloudflare provisions the
DNS record and certificate on deploy).

The reference deployment at `nuco-server.zlsoftware.at` lives in the `production` env of
the same config and deploys with `npx wrangler deploy --env production`; its secrets are
set with `wrangler secret put <NAME> --env production`.

The app's default server is `wss://nuco-server.zlsoftware.at`; a custom server can be set
in the app's Settings.

## Voice calls (TURN)

Calls need TURN: the app forces relay only media so peers never learn each other's IP.
The relay mints short lived credentials from Cloudflare Realtime TURN; without a key it
answers CALLS_UNAVAILABLE, the app disables calling, and messaging is unaffected.

1. Create a TURN key: dashboard (Realtime, TURN) or
   `POST /accounts/{account_id}/calls/turn_keys`. Save the key id and the secret.
2. `npx wrangler secret put TURN_KEY_ID` and `npx wrangler secret put TURN_KEY_SECRET`.
3. Optional: adjust `TURN_TTL_SECONDS` in `wrangler.jsonc` (default 7200; the TTL caps how
   long an established call can refresh its allocation, so it also bounds call length; the
   Cloudflare maximum is 48 hours).

TURN usage is billed by Cloudflare per outbound GB; an hour of Opus voice is roughly
100 MB. Media through TURN stays end to end encrypted (DTLS-SRTP).

## iOS push (APNs)

The relay sends the wake directly to Apple with an ES256 provider token; the payload
carries no content. To enable it:

1. Create an APNs Auth Key in the Apple Developer portal and download the `.p8`.
2. `npx wrangler secret put APNS_KEY` (paste the full PEM content of the `.p8`), then
   `APNS_KEY_ID`, `APNS_TEAM_ID`, and `APNS_BUNDLE_ID` the same way.
3. `APNS_HOST` in `wrangler.jsonc` selects production or sandbox
   (`api.sandbox.push.apple.com` for development builds).

Transport caveat: Apple's provider API requires HTTP/2. Deployed Workers negotiate HTTP/2
to Apple at the edge (the established pattern for APNs from Workers), but Cloudflare does
not contractually guarantee the outbound protocol, and local `wrangler dev` cannot speak
HTTP/2 outbound at all, so dev mode mocks push sending. Verify APNs against a deployed
Worker; if the behavior ever changes, fall back to a small external push proxy.

If no key is configured the relay runs fine without iOS push; clients still receive
messages whenever they are connected.

## Android push (UnifiedPush)

No server configuration. The app registers an endpoint URL with its distributor and the
relay POSTs a tiny content free body to it. Endpoints are SSRF checked at registration and
again before every send.

## Configuration

Vars (in `wrangler.jsonc`): `QUEUE_MAX` (1000), `QUEUE_TTL_SECONDS` (30 days),
`RATE_MAX_PER_MIN` (600, per handle), `MAX_MESSAGE_BYTES` (131072), `TURN_TTL_SECONDS`
(7200), `APNS_HOST`. Secrets (via `wrangler secret put`): `TURN_KEY_ID`,
`TURN_KEY_SECRET`, `APNS_KEY`, `APNS_KEY_ID`, `APNS_TEAM_ID`, `APNS_BUNDLE_ID`. The `DEV`
and `TURN_TEST` vars exist only for `wrangler dev` and the tests; never set them on a
deployment.

## Security notes

- The relay logs operational events only, never ciphertext, credentials, or full who to
  whom maps. TURN credentials and the TURN key are never logged.
- Rate limiting is a per handle token bucket inside each mailbox object; Cloudflare's own
  DDoS and WAF layers sit in front of it.
- Message queues live per handle in that handle's Durable Object (SQLite), capped by
  `QUEUE_MAX` and swept by a per object alarm after `QUEUE_TTL_SECONDS`.
- Delivery stays at least once: rows are deleted only on client ack and are redelivered
  on every reconnect until then.

## License

MIT, see [LICENSE](LICENSE).
