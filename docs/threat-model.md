# Threat Model

This document defines what Heimdall is designed to protect against and what it
explicitly **cannot** protect against. Heimdall does not claim absolute
security; it aims for the properties expected from a modern secure messenger,
using only well-established cryptographic constructions (see
`docs/protocol.md`).

## Assets

| Asset | Sensitivity |
|---|---|
| Long-term identity private key (Ed25519) | Critical — never leaves the device, stored encrypted at rest |
| Peer identity public keys + verification state | High — tampering enables MITM |
| Session keys / ratchet state | Critical — exist only in memory, never persisted, never logged |
| Message plaintext | High — exists only in memory and (optionally) in the in-memory history |
| Configuration (name, listen address) | Low |

## Adversary model

We assume an adversary who can:

- **Passively observe** all network traffic (ISP, LAN, compromised routers).
- **Actively modify, inject, drop, reorder, duplicate and replay** traffic.
- **Impersonate any display name** and control any number of malicious clients.
- **Attempt man-in-the-middle attacks** on every connection, including key
  substitution during the handshake.
- **Compromise network infrastructure** entirely (DNS, routers, NATs).
- Obtain a peer's **long-term identity key after the fact** (e.g. stolen
  backups) and try to decrypt previously captured traffic.
- Collude with **untrusted/malicious peers** that a user talks to.

## Protected against

| Threat | Mitigation |
|---|---|
| Passive network interception | All payloads encrypted end-to-end with AES-256-GCM; keys never on the wire |
| Active network interception / modification | AEAD authentication tags; any modified bit → decryption failure → message dropped |
| MITM attacks | Handshake transcript signed with both peers' long-term Ed25519 keys; attacker cannot forge either signature without the private key |
| Peer impersonation ("I am alice") | Identity = Ed25519 public key, not the display name; names are never proof of identity; `/fingerprint` and `/verify` provide out-of-band comparison |
| Key substitution | Trust store records each peer's key; a changed key triggers a prominent `!!! SECURITY WARNING !!!` and marks the connection UNTRUSTED — never silently accepted |
| Message modification | AEAD tag + signed handshake; header fields are authenticated as additional data |
| Message replay | Per-session monotonic sequence numbers + sliding replay window; duplicates rejected |
| Duplicate message injection | Same replay window; already-seen sequence numbers are dropped |
| Message ordering manipulation | Sequence-number window detects gaps/out-of-order delivery beyond the window; too-old messages rejected |
| Session hijacking | An attacker who did not complete the signed handshake has no session keys; injected packets fail AEAD authentication |
| Compromised network infrastructure | All security is end-to-end between the two endpoints; relays/routers see only ciphertext |
| Malicious relay operator | A relay forwards opaque frames. It cannot read messages, learn either peer's identity key, name or fingerprint, or man-in-the-middle a session — it can only relay the signed handshake unmodified. It cannot impersonate a peer on first contact either, because an invite code is confirmed end-to-end (`docs/rendezvous.md` §4) |
| TLS-intercepting proxy on the path to a relay | Nothing to gain: relay TLS is not a security boundary, and the session inside it is already end-to-end encrypted and authenticated |
| Compromised/untrusted peers | Unverified peers are displayed as `SECURE / UNVERIFIED`; peers whose key changed are `UNTRUSTED` and their traffic is surfaced with warnings; users can `/disconnect` them |
| Compromised long-term identity keys | Forward secrecy: sessions are keyed by ephemeral X25519 and advanced by a symmetric ratchet; stealing an identity key does not decrypt previously captured sessions (but does allow future impersonation — hence fingerprint verification) |
| Local key theft (offline) | Identity file encrypted with PBKDF2-SHA-256 (600k iterations) + AES-256-GCM with a random per-file salt; file permissions 0600 |

## The relay: what it costs you

Using a rendezvous relay is optional and off by default. When it is used, it is
a **metadata position** — the one real cost of the feature, stated plainly:

| The relay learns | The relay does not learn |
|---|---|
| That two IP addresses were connected, and when | Either peer's identity key, fingerprint or display name |
| A random, single-use rendezvous id, unlinkable to any identity | The invite code or the pairing key derived from it |
| How many bytes flowed, and when | Any plaintext, or either peer's candidate addresses |

This is roughly what any on-path observer already sees, concentrated in one
place. Run your own relay if that concentration matters to you; Heimdall ships
no relay address and contacts none unless you pass `-relay`.

### Why relay certificates are deliberately not trusted

Heimdall accepts a relay TLS certificate it cannot verify, and falls back to a
cleartext rung if 443 is blocked. This is a deliberate design decision, not an
oversight, and it must not be "fixed" by adding certificate pinning.

The relay is an untrusted byte pipe by construction: confidentiality,
integrity and authentication are all end-to-end, and first contact through an
invite code is confirmed with a channel binding the relay cannot forge. There
is therefore nothing for a relay certificate to protect. What the tolerance
buys is real: Heimdall keeps working on networks with an intercepting
corporate proxy, where applications that pin certificates simply fail.

Users who would rather fail than tolerate interception can pass
`-relay-verify`; users running a self-signed relay can pass `-relay-pin`.

If the pairing confirmation of `docs/rendezvous.md` §4 is ever weakened or made
optional, this tolerance must be removed at the same time. The two are a pair.

## Not protected against

Heimdall cannot protect against:

- **Fully compromised endpoint.** Malware with access to process memory can read
  keys and plaintext. No application-level cryptography can prevent this.
- **Keyloggers / screen capture.** Input and displayed output are outside the
  cryptographic boundary.
- **Compromised operating system or hardware** (malicious kernel, hypervisor,
  firmware).
- **The user voluntarily trusting a malicious fingerprint.** `/verify` is only
  as strong as the out-of-band channel used to compare fingerprints.
- **Physical compromise of an unlocked device** while the application is
  running (session keys are in memory).
- **Traffic analysis.** An observer can see *that* two IP addresses communicate,
  connection timing and approximate message sizes. No padding/mixing is
  provided. A relay, when used, sees the same for the pair it is relaying.
- **A network that blocks the relay outright.** A network permitting only a
  whitelist of destinations can still block an unknown relay host. Hosting the
  relay on a domain the network already permits is an operational answer, not
  a protocol one. Resistance to active probing of a relay endpoint is not
  attempted.
- **Denial of service.** An attacker can drop packets or exhaust resources;
  availability is not guaranteed.
- **Endpoint display-name confusion.** Two peers may pick the same name; the
  fingerprint — not the name — is the identity. The UI always shows trust
  state next to peers.

## Logging policy

Debug logging must never include private keys, session keys, plaintext
cryptographic secrets, or authentication credentials (passphrases). Logging is
safe by default: only non-secret metadata (connection events, peer names,
fingerprints, errors) may be logged.

The relay holds itself to the same rule and one more: it never logs rendezvous
ids, circuit tickets, invite codes or payload bytes, and keeps no persistent
state.
