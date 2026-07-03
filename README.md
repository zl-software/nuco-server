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

Voice calls extend this by exactly one dimension: call signaling is sealed content the
relay cannot read, but the TURN server (run by the same operator) sees both endpoints' IP
addresses, allocation times, duration, and byte counts. The media payload it forwards is
DTLS-SRTP ciphertext it cannot decrypt. See PROTOCOL.md "Voice calls".

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

## Voice calls (TURN)

Calls need a TURN server: the app forces relay only media so peers never learn each
other's IP address. The stack ships coturn as an opt in compose profile, and the relay
issues short lived credentials for it (TURN REST scheme, nothing stored server side). If
TURN is not configured the relay answers CALLS_UNAVAILABLE, the app disables calling, and
messaging is unaffected.

1. Create a DNS A record for a turn subdomain (for example `turn.your-domain`) pointing at
   the same host.
2. Generate a shared secret: `openssl rand -hex 32`.
3. Copy `coturn/turnserver.conf.example` to `coturn/turnserver.conf` (gitignored), set
   `static-auth-secret` to the secret and `realm` to your turn subdomain. On a cloud VM
   behind 1:1 NAT, also set `external-ip`.
4. In `.env`, set `TURN_SECRET` and `RELAY_TURN_SECRET` to the same secret, and
   `RELAY_TURN_URLS` to
   `turn:turn.your-domain:3478?transport=udp,turn:turn.your-domain:3478?transport=tcp`.
   Uncomment the RELAY_TURN lines in `docker-compose.yml`.
5. Open the firewall: 3478 udp and tcp, plus the relay media range 49160 to 49360 udp.
6. Start everything: `docker compose --profile calls up -d`.

Notes:

- `RELAY_TURN_TTL_SECONDS` (default 7200) is the credential lifetime. coturn stops
  refreshing an allocation once the embedded expiry passes, so the TTL also caps how long
  a single call can last. Credentials are fetched per call.
- Media stays end to end encrypted (DTLS-SRTP) regardless of the TURN transport, so plain
  `turn:` on 3478 is the default. `turns:` (TLS) only helps traverse restrictive networks;
  if you enable it, remember coturn does not reload renewed certificates, restart it after
  each renewal.
- The example config denies relaying into private, loopback, and link local ranges so the
  TURN server cannot be used as a pivot into your network, and bounds bandwidth with
  quotas (`total-quota`, `user-quota`, `max-bps`).

For local call testing against a dev relay, run a throwaway coturn on your LAN:

```
docker run --rm --network host coturn/coturn:4 --use-auth-secret \
  --static-auth-secret=devsecret --realm=nuco.dev --no-tls --no-dtls --fingerprint --no-cli
```

and start the relay with `RELAY_TURN_SECRET=devsecret` and
`RELAY_TURN_URLS=turn:<LAN_IP>:3478?transport=udp`. A dev relay without these vars simply
reports calls unavailable.

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
- `RELAY_TURN_SECRET`, `RELAY_TURN_URLS`, `RELAY_TURN_TTL_SECONDS` (optional voice calls)
- `APNS_*` (optional iOS push)

## Storage

Storage sits behind a small `Storage` interface (`src/storage/interface.ts`) with a
`better-sqlite3` implementation as the default. Swap in Postgres or Redis later without
touching the relay logic. All key and ciphertext columns are opaque to the relay.

## Security notes

- The relay logs operational events only, never ciphertext or full who to whom maps beyond
  what an operation needs. TURN credentials, usernames, and the shared secret are never
  logged; the issued usernames are random ids rather than handles so coturn's own logs do
  not accumulate a handle to call time map.
- Rate limiting is in process (token bucket per connection). Behind multiple instances, move
  limits and queues to a shared store. TURN credential requests share the same per ip
  bucket; that is deliberate. A full call setup costs about five frames, and hoarding
  credentials grants nothing (they are derived, not stored, and each expires on its own).
  Actual relay bandwidth abuse is bounded where it happens, by coturn's quotas.
- Keep the `.p8`, `coturn/turnserver.conf`, and any TLS keys out of git and mount them as
  secrets.
