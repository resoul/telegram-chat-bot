# Changelog

All notable changes to this project are documented in this file.

## [2.0.0] - Unreleased

### Security

- Introduced protocol v2, which signs the complete handshake transcript:
  both nonces and both ECDH public keys. This prevents an active attacker
  from replacing an ECDH public key without invalidating the signature.
- Derived separate client-to-server and server-to-client AES-256-GCM keys
  for v2 using an HMAC-SHA-256 HKDF construction.

### Changed

- Protocol v2 is now the default. Servers reject legacy v1 client hellos
  unless constructed with `AllowLegacyV1()`.
- `Session` now exposes `ClientToServerKey` and `ServerToClientKey` instead
  of a single `AESKey`.
- Validated handshake packet type, command, and exact message length before
  processing it, and validate server RSA keys when creating a server.

### Deprecated

- Protocol v1 remains available only as a temporary, explicit migration
  option. It does not authenticate the ECDH exchange and must be used only
  inside TLS.

### Migration notes

- Update clients to use v2 command identifiers `101` and `102` and to verify
  the server signature over the full transcript before trusting the shared
  secret.
- During a rolling migration, opt in with `AllowLegacyV1()` only until all
  clients support v2; then remove the option.
