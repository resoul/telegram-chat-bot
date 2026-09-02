# wireauth

A small, dependency-free Go package implementing a server-side handshake
that establishes an encrypted channel over any message-based transport
(WebSocket, TCP, etc.): RSA-signed challenge/response, ECDH (P-256) key
exchange, and an AES-256-GCM secured channel afterward. It also includes an
HMAC-based proof for verifying session-resume requests.

This is **transport security**, not end-to-end encryption between users —
it protects the link between a client and your server (like TLS does), and
is meant to sit alongside your existing auth, not replace it. If you need
E2E encryption between users, this package is not that; look at the Signal
protocol / libsignal instead.

The exact wire format (byte layout of every message) is documented in
[`HANDSHAKE_SPEC.md`](./HANDSHAKE_SPEC.md) — read that if you're
implementing a client in another language, or auditing the protocol.

> **Security note (protocol v2):** the handshake now signs the full
> transcript — both nonces *and* both ECDH public keys — closing a gap in
> the original protocol where the RSA signature covered only the nonces,
> leaving the ECDH exchange itself unauthenticated against an active
> network attacker. See the security advisory at the top of
> `HANDSHAKE_SPEC.md`. **v2 is the default; the old protocol is available
> only via the explicit `AllowLegacyV1()` option for staged client
> migrations, and must never run outside TLS.** If every client you talk
> to already speaks v2, do nothing — `Perform` handles both stages
> internally. If you have existing v1 clients, see "Migrating from v1"
> below before upgrading this package.

## Install

```
go get gitlab.com/resoul/wireauth
```

Requires Go 1.22+ (uses `crypto/ecdh`, standard library only — no
third-party dependencies).

## Quick start

You need an RSA keypair on the server. Clients only ever see the **public**
key (used to verify the server's signature) — it is not a secret, so you
don't need to protect it, just make sure clients get the authentic one
(pin it, ship it in your client's config, etc.). The **private** key stays
server-side.

```bash
openssl genrsa -out server.key 2048
```

```go
package main

import (
	"context"
	"log"
	"net/http"

	"gitlab.com/resoul/wireauth"
	"github.com/gorilla/websocket"
)

var upgrader = websocket.Upgrader{}

func main() {
	privateKey, err := wireauth.LoadPrivateKeyRSA("server.key")
	if err != nil {
		log.Fatal(err)
	}

	// Build once, reuse across every connection — it's just config,
	// no per-connection state lives on it.
	handshakeServer := wireauth.NewServer(privateKey)

	http.HandleFunc("/ws", func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close()

		// conn (*websocket.Conn) already satisfies wireauth.MessageReadWriter —
		// no wrapping needed.
		session, err := handshakeServer.Perform(context.Background(), conn)
		if err != nil {
			log.Println("handshake failed:", err)
			return
		}

			// Session keys are direction-separated. The server decrypts incoming
			// packets with ClientToServerKey and encrypts replies with ServerToClientKey.
		for {
			_, packet, err := conn.ReadMessage()
			if err != nil {
				return
			}
			plaintext, seq, err := wireauth.DecryptAESGCM(session.ClientToServerKey, packet)
			if err != nil {
				log.Println("decrypt failed:", err)
				return
			}
			log.Printf("got message #%d: %s", seq, plaintext)

			reply, _ := wireauth.EncryptAESGCM(session.ServerToClientKey, []byte("ack"), seq)
			conn.WriteMessage(websocket.BinaryMessage, reply)
		}
	})

	log.Fatal(http.ListenAndServe(":8080", nil))
}
```

That's the whole server side. The client side (whatever language it's
written in) needs to speak the protocol described in
[`HANDSHAKE_SPEC.md`](./HANDSHAKE_SPEC.md) — stage 1 (send a nonce, verify
the server's RSA signature), stage 2 (ECDH exchange), then use the derived
AES key for `AES-256-GCM` on both sides.

## API reference

```go
// Load your RSA private key from a PEM file (PKCS#1 or PKCS#8).
privateKey, err := wireauth.LoadPrivateKeyRSA("server.key")

// Build a handshake server. Reusable across all connections.
srv := wireauth.NewServer(privateKey,
    wireauth.WithTimeout(10 * time.Second), // optional, default 10s
)

// Run the handshake over any conn satisfying MessageReadWriter
// (ReadMessage() (int, []byte, error) + WriteMessage(int, []byte) error —
// *websocket.Conn already qualifies).
session, err := srv.Perform(ctx, conn)
// session.ClientToServerKey []byte, 32 bytes — decrypt client packets
// session.ServerToClientKey []byte, 32 bytes — encrypt server packets
// session.ServerNonce []byte, 16 bytes — needed later for resume proofs

// Encrypt/decrypt messages on the now-secure channel.
// seq must be unique and monotonically increasing per direction
// (e.g. a simple counter) — it's used as AEAD associated data.
packet, err := wireauth.EncryptAESGCM(session.ServerToClientKey, plaintext, seq)
plaintext, seq, err := wireauth.DecryptAESGCM(session.ClientToServerKey, packet)

// Verify a session-resume proof a returning client presents, without
// re-running the full handshake.
ok := wireauth.VerifyResumeProof(masterKey, sessionSalt, authKeyIDBytes, serverNonce, proofB)
```

## Migrating from v1

This package now speaks protocol v2 by default (see the security note
above) and will reject a v1 client hello unless you opt in explicitly:

```go
// Only during a migration window — remove once every client has moved
// to v2. Logged handshakes on this server should be watched so you know
// when it's safe to remove.
srv := wireauth.NewServer(privateKey, wireauth.AllowLegacyV1())
```

Rollout order matters: ship client-side v2 support first (clients can
usually try v2 and fall back to v1 based on the server's response, or you
can stage by client version), confirm v2 traffic before removing
`AllowLegacyV1()` from the server, then remove v1 support from clients.
Don't flip the server to v2-only before any client can speak it — that
just breaks every connection.

The wire format itself changed (see `HANDSHAKE_SPEC.md`): v1 and v2 use
different `cmd` values (`1`/`2` vs `101`/`102`) and different message
sizes, so this is not a drop-in, config-only change on the client side —
client implementations (Web, Swift, etc.) need their own update to speak
v2, following the updated spec.

## What you get / what you're responsible for

**Handled by this package:**
- RSA challenge/response (proves the server holds the private key)
- ECDH key exchange (derives a fresh shared secret per connection)
- AES-256-GCM framing helpers for the resulting secure channel
- Resume-proof verification (HMAC chain)

**Left to you:**
- Transport itself (accepting connections, TLS termination if any, etc.)
- Per-message sequencing: maintain a strictly increasing receive counter per
  direction and reject any unexpected sequence number; this provides replay
  protection above AES-GCM's authentication of the field.
- Key storage/rotation for the RSA private key
- Distributing the RSA **public** key to clients authentically (this
  package doesn't handle key pinning or distribution — that's inherently
  app-specific)
- Everything above the secure channel: authentication of *who* the user is,
  authorization, rate limiting, etc. This package only secures the pipe.

## Logging

The package does no logging internally. Wrap the `Perform` call yourself if
you want visibility:

```go
start := time.Now()
session, err := srv.Perform(ctx, conn)
log.Printf("handshake took %s, err=%v", time.Since(start), err)
```

## Errors

`Perform`, `EncryptAESGCM`, and `DecryptAESGCM` return sentinel errors you
can check with `errors.Is`: `wireauth.ErrHandshakeReadFailed`,
`wireauth.ErrInvalidClientPubKey`, `wireauth.ErrDecryptionFailed`, etc. — see
`transport.go` for the full list.

## FAQ

**Is this the Signal protocol / Double Ratchet?**
No. No forward secrecy across messages (the same AES key is used for the
whole connection's lifetime), no per-user identity keys, no E2E. It's a
transport-security handshake — closer in spirit to a lightweight custom TLS
than to Signal. If you need E2E, use libsignal or similar instead.

**Can I use this over plain TCP instead of WebSocket?**
Yes — implement `wireauth.MessageReadWriter` (two methods) around your
`net.Conn`, framing messages however you like (e.g. length-prefixed). If
your type also has `SetReadDeadline(time.Time) error`, wireauth will use it
to enforce the handshake timeout automatically.

**What if my `MessageReadWriter` doesn't support deadlines?**
`Perform` checks for that method via a type assertion; if it's absent, no
deadline is set and you're responsible for enforcing your own timeout
(e.g. via context cancellation upstream, or your own watchdog).

**Do I need to change my client code to use this?**
If your client already speaks protocol v2 (see `HANDSHAKE_SPEC.md`), no.
If it speaks the older v1 protocol, yes — v1 and v2 use different `cmd`
values and message sizes, and v1 is no longer accepted unless the server
opts in via `AllowLegacyV1()`. See "Migrating from v1" above.

**Where's the client-side code?**
This package is server-only. If you need a reference client implementation,
port the logic in `HANDSHAKE_SPEC.md` to your client language — it's a
small, self-contained protocol (a few dozen lines per stage).
