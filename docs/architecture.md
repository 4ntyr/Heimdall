# Architecture

Heimdall is a terminal-only, peer-to-peer, end-to-end encrypted messenger. It is
written in Go using **only the standard library**, so it compiles to a single
self-contained static executable for Windows and Linux with **zero runtime
dependencies** (no Python/Node/Java, no system services, no package manager).

## Design principles

1. **Security first.** The cryptographic protocol is designed (and documented,
   see `docs/protocol.md`) before the implementation. Cryptography never
   depends on the CLI, and the CLI never touches cryptographic primitives.
2. **Modularity.** Every layer has a single responsibility and a narrow API.
   Every layer except the `main` package (the repository root) can be tested
   without a terminal and without real network connections.
3. **No custom cryptography.** Only well-established constructions provided by
   the Go standard library are used: X25519 (`crypto/ecdh`), Ed25519
   (`crypto/ed25519`), AES-256-GCM (`crypto/aes`+`crypto/cipher`),
   HKDF-SHA-256 (`crypto/hkdf`), PBKDF2-SHA-256 (`crypto/pbkdf2`) and the OS
   CSPRNG (`crypto/rand`).
4. **Safe by default.** Private keys are stored encrypted; nothing secret is
   ever logged; unknown identities are *not* trusted automatically; changed
   identity keys produce a prominent warning instead of silent acceptance.

## Layer overview

```
CLI (main, repository root)
 │
 ├── Peer Manager                 internal/session   (connections, lifecycle)
 │       └── Trust Store          internal/peers    (known keys, verification)
 │
 ├── Session Manager              internal/session + internal/proto.Session
 │
 ├── Authentication / Identity    internal/identity (Ed25519 keys, fingerprints)
 │
 ├── Cryptographic Protocol       internal/proto (handshake, ratchet, framing)
 │       └── Primitives           internal/crypto (AEAD, HKDF, CSPRNG)
 │
 ├── Secure Storage               internal/identity (identity file),
 │                                internal/peers (trust store file)
 │
 └── Network Transport            internal/transport (TCP listener/dialer,
                                                      length-prefixed frames)
```

Dependency direction is strictly top-down. Notable rules:

- `internal/proto` (the cryptographic protocol) imports only `internal/crypto`,
  `internal/identity` and the standard library. It has **no knowledge of the
  CLI or the network**.
- `internal/transport` moves opaque bytes only. It has **no knowledge of
  terminal rendering or cryptography**.
- The `main` package talks to `internal/session` through a small
  channel-based event interface, so session logic is fully testable
  headlessly.

## Layer responsibilities

| Package | Responsibility | Explicit non-responsibility |
|---|---|---|
| `internal/crypto` | Thin wrappers over stdlib primitives: random bytes, AES-256-GCM seal/open, HKDF key separation | protocol logic |
| `internal/identity` | Long-term Ed25519 identity, human-readable name, stable SHA-256 fingerprint, passphrase-encrypted at-rest storage | networking, sessions |
| `internal/peers` | Persistent record of peer identity public keys, verification state, detection of identity-key changes | transport, UI |
| `internal/proto` | Wire format, authenticated handshake (X25519 + Ed25519-signed transcript), session ratchet, replay protection, key rotation | sockets, terminal |
| `internal/transport` | TCP listen/dial, length-prefixed framed messages, I/O deadlines | protocol semantics |
| `internal/session` | Connection lifecycle: inbound/outbound, handshake driving, keepalive, disconnect detection, automatic reconnect, per-peer send queues | rendering |
| `main` (repository root) | CLI wiring: flags, REPL, event printing | logic |

## Security properties (summary)

- **Authenticated key exchange & mutual authentication:** Noise-style
  `XX`-pattern handshake; both peers sign the full transcript with their
  long-term Ed25519 identity keys.
- **End-to-end AEAD:** AES-256-GCM; the protocol header is authenticated as
  additional data — nothing is trusted before authentication.
- **Forward secrecy:** the long-term key only *authenticates*; encryption keys
  come from ephemeral X25519 and are advanced by a symmetric ratchet
  (every message) and a full key rotation (every 1000 messages).
- **Replay/ordering protection:** monotonically increasing sequence numbers
  with a sliding acceptance window; duplicates and too-old packets are dropped.
- **MITM / impersonation protection:** peers are identified by the SHA-256
  fingerprint of their Ed25519 public key, never by their display name;
  unexpected key changes are flagged `UNTRUSTED` with a prominent warning.

See `docs/threat-model.md` for what is and is not protected.
