# nuco-server

The Nuco relay: an untrusted store and forward server. It transports sealed ciphertext,
hosts public prekey bundles, and sends content free push wakes. It can never read messages
and holds no private keys. Minimal, auditable dependencies: `ws`, `jose`, and
`better-sqlite3`, plus Node built ins for HTTP and HTTP/2.

See `../protocol/PROTOCOL.md` for the wire contract this server implements.

## Trust model

The relay only ever sees ciphertext plus routing metadata. It cannot see message content,
display names in messages, or any private key. It can see which handles are in contact,
timing, and a padded message size bucket. Operators and users should treat that metadata as
visible to whoever runs the relay. The app states this plainly on its About and Privacy
screen.

## Requirements

- Node 24 LTS (Node 22 also works). The Docker image pins Node 24.
- The shared `@nuco/protocol` package, which lives in a sibling `protocol` folder and is
  referenced through `file:../protocol`. Clone both repos side by side.

## Development

```
# build the shared protocol once
npm --prefix ../protocol install
npm --prefix ../protocol run build

npm install
npm run dev        # RELAY_DEV=1: no TLS, in memory SQLite, push mocked (logged)
```

Dev mode listens on `ws://localhost:8787`. Run the tests:

```
npm test           # server level WebSocket smoke test
npm run test:e2e   # two headless clients exchange a real sealed message end to end
```

## Production with Docker and Caddy

The provided `docker-compose.yml` runs the relay behind Caddy, which terminates TLS with an
automatic Let's Encrypt certificate and upgrades the WebSocket. Edit `Caddyfile` to use your
domain, then:

```
docker compose up -d
```

Point the app's Server setting (custom) at `wss://your-domain`. The relay stores its SQLite
database on a named volume, so it survives restarts.

If you prefer to terminate TLS in the relay process instead of using a reverse proxy, set
`RELAY_TLS_CERT` and `RELAY_TLS_KEY` to your certificate and key paths and expose the port
directly.

## iOS push (APNs)

iOS background wakes require a paid Apple Developer account and an APNs Auth Key (.p8). The
relay sends the wake directly to Apple over HTTP/2 with an ES256 JWT; no Firebase is
involved, and the payload carries no content. To enable it:

1. Create an APNs Auth Key in the Apple Developer portal and download the `.p8`.
2. Mount the `.p8` into the container (see the commented volume in `docker-compose.yml`) and
   set `APNS_KEY_PATH`, `APNS_KEY_ID`, `APNS_TEAM_ID`, and `APNS_BUNDLE_ID`.
3. Use `APNS_HOST=api.push.apple.com` for production or `api.sandbox.push.apple.com` for
   development builds.

If no `.p8` is configured the relay runs fine without iOS push; iOS clients still receive
messages whenever they are connected.

## Android push (UnifiedPush)

No server configuration is needed. The app registers an endpoint URL with its chosen
UnifiedPush distributor (for example ntfy) and sends that URL to the relay. The relay POSTs
a tiny content free body to that endpoint to wake the device.

## Configuration

All settings are environment variables; see `.env.example`. Key ones:

- `RELAY_DEV`, `RELAY_HOST`, `RELAY_PORT`
- `RELAY_TLS_CERT`, `RELAY_TLS_KEY` (in process TLS, optional)
- `RELAY_SQLITE_PATH`, `RELAY_QUEUE_MAX`, `RELAY_QUEUE_TTL_SECONDS`
- `RELAY_RATE_MAX_PER_MIN`, `RELAY_MAX_MESSAGE_BYTES`
- `APNS_*` (optional iOS push)

## Storage

Storage sits behind a small `Storage` interface (`src/storage/interface.ts`) with a
`better-sqlite3` implementation as the default. Swap in Postgres or Redis later without
touching the relay logic. All key and ciphertext columns are opaque to the relay.

## Security notes

- The relay logs operational events only, never ciphertext or full who to whom maps beyond
  what an operation needs.
- Rate limiting is in process (token bucket per connection). Behind multiple instances, move
  limits and queues to a shared store.
- Keep the `.p8` and any TLS keys out of git and mount them as secrets.
