# Heimdall (HMDL)

**Heimdall** (production name **HMDL**) is a terminal-only, peer-to-peer,
end-to-end encrypted messenger for Windows and Linux. No central server, no
runtime dependencies — it compiles to a single self-contained executable
using **only the Go standard library**. Peers authenticate by cryptographic
identity fingerprints (Ed25519), never by display name.

## Why Heimdall?

- **No servers, no accounts, no metadata collection.** Messages travel
  directly between peers over TCP; there is no central infrastructure to
  trust, shut down, or compel.
- **Real end-to-end encryption.** A Noise-style authenticated handshake
  (X25519 + Ed25519-signed transcripts), AES-256-GCM for every message, a
  per-message symmetric ratchet for forward secrecy, and periodic key
  rotation. No custom cryptography — only well-established primitives from
  the Go standard library.
- **Identity you can verify.** Every user is identified by the SHA-256
  fingerprint of their long-term Ed25519 key. Unexpected key changes trigger
  a prominent `SECURITY WARNING` and the connection is marked `UNTRUSTED`
  — never silently accepted.
- **Zero dependencies, zero install.** One static binary you can put on a
  USB stick and run anywhere.

## Current capabilities (v1)

- Interactive terminal chat with multiple simultaneous peers:
  `/connect`, `/msg`, `/all`, `/peers`, `/verify`, `/help`, `/quit`
  (bare text broadcasts to everyone).
- **Mutually authenticated key exchange** — Noise `XX`-pattern handshake;
  both peers sign the full transcript with their identity keys, so MITM
  attempts fail the handshake.
- **End-to-end AEAD** — AES-256-GCM per message; the protocol header is
  authenticated as additional data, and unauthenticated plaintext is never
  displayed.
- **Forward secrecy** — ephemeral X25519 session keys, a per-message
  ratchet, and full key rotation every 1000 messages; session keys live only
  in memory and are zeroised on termination.
- **Replay & ordering protection** — monotonic sequence numbers with a
  1024-message sliding acceptance window; duplicates and stale frames are
  dropped.
- **Trust-on-first-use with verification** — persistent trust store
  (`peers.json`), out-of-band fingerprint comparison via `/verify`, and loud
  detection of identity-key changes.
- **Encrypted identity at rest** — the private key is stored in
  `~/.heimdall/identity.hmdl`, encrypted with a passphrase
  (PBKDF2-SHA-256, 600k iterations + AES-256-GCM, file mode 0600).
- **Robust sessions** — keepalive (ping/pong), clean disconnects, automatic
  reconnect with a fresh handshake, and per-peer send queues.
- **Cross-platform** — builds for Windows and Linux (and anything else Go
  targets) with `go build`; no CGO, no third-party modules.

## Quick start

Requires **Go 1.24+**.

```sh
git clone https://github.com/4ntyr/heimdall.git
cd heimdall

# First run — creates your identity (asks for a passphrase)
go run . -name alice

# Or build a self-contained executable
go build -o hmdl .
./hmdl
```

Chat with a friend (one side listens, the other connects):

```sh
# Peer A (listener, default port 7331)
./hmdl

# Peer B
./hmdl -connect <A's IP>:7331
```

Both sides should compare the identity fingerprints printed at startup
out-of-band and then run `/verify <name>`. See
[docs/deployment.md](docs/deployment.md) for the full step-by-step guide,
flags, cross-compilation, and troubleshooting.

## Documentation

| Document | Contents |
|---|---|
| [docs/protocol.md](docs/protocol.md) | Full wire-protocol specification (handshake, key derivation, ratchet, framing) — written *before* the implementation |
| [docs/threat-model.md](docs/threat-model.md) | What Heimdall protects against — and what it explicitly does not |
| [docs/architecture.md](docs/architecture.md) | Layered design, package responsibilities, security properties |
| [docs/deployment.md](docs/deployment.md) | Build, install and usage guide for non-Go users |
| [dev-logs/](dev-logs/) | Design explorations (e.g. NAT-traversal options) |

## Roadmap / future plans

The cryptographic protocol and the network layer are deliberately decoupled
(`internal/proto` knows nothing about sockets), so connectivity improvements
can be added without touching the end-to-end encryption.

Planned, roughly in priority order (see
[dev-logs/networking.md](dev-logs/networking.md) for the full analysis):

1. **Relay / rendezvous mode** — optional public meeting point so peers
   behind NATs can connect without manual port-forwarding; the relay only
   forwards opaque encrypted frames and never sees plaintext. *This is the
   primary next milestone.*
2. **IPv6-first direct connections** — polished support and documentation
   for peers with globally routable IPv6.
3. **Automatic port mapping** — UPnP / NAT-PMP / PCP support to automate
   router port-forwarding where available.
4. **NAT hole punching** — true serverless connectivity through NATs,
   paired with relay fallback (the largest, longest-term effort).

Explicit non-goals for v1: anonymous routing, traffic-analysis resistance,
offline message queueing, and group chats.

## Security

Heimdall is designed security-first: the protocol was specified before it
was implemented, private keys are encrypted at rest, nothing secret is ever
logged, and unknown or changed identities are never trusted silently. That
said, it has not yet undergone an independent security audit — please read
[docs/threat-model.md](docs/threat-model.md) before relying on it for
high-stakes communication, and report vulnerabilities responsibly by
opening a private security advisory.

## License

No license file has been published yet; all rights reserved by the author
until one is added.
