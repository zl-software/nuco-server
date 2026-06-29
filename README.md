# nuco-server

The Nuco relay: an untrusted store and forward server that transports sealed ciphertext,
hosts public prekey bundles, and sends content free push wakes. It can never read messages
and holds no private keys. Self hostable with a minimal, auditable dependency set
(`ws`, `jose`, `better-sqlite3`, and Node built ins for HTTP and HTTP/2).

Full setup, configuration, TLS, APNs credentials, and Docker instructions are documented as
the server is built out. See `../protocol/PROTOCOL.md` for the wire contract this server
implements.
