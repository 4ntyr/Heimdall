# Heimdall Protocol Specification

Version: 1

This document defines the wire protocol **before** the implementation. It is
the contract for the handshake, identity authentication, key exchange, session
establishment, key derivation, message format, sequence numbers, replay
protection, session termination, key rotation, error handling, identity
changes and peer verification.

The protocol is transport-independent: it assumes a reliable, ordered, opaque
byte stream (TCP on port `TCP/8471` by default) with a length-prefixed framing
layer underneath (see §10).

## 1. Cryptographic primitives

All primitives come from the Go standard library. **No custom cryptography.**

| Purpose | Primitive |
|---|---|
| Identity keys / signatures | Ed25519 (`crypto/ed25519`) |
| Ephemeral key exchange | X25519 (`crypto/ecdh`) |
| Authenticated encryption | AES-256-GCM, 32-byte keys, 12-byte random nonces |
| Key derivation | HKDF-SHA-256 (`crypto/hkdf`) |
| Protocol transcript hash | SHA-256 |
| Randomness | OS CSPRNG (`crypto/rand`) |
| Identity storage KDF | PBKDF2-SHA-256, 600 000 iterations, 16-byte random salt |

Explicit key separation: every derived key uses a distinct HKDF `info` label
(§5). Keys for different purposes are never reused.

## 2. Identity

A client identity consists of:

- **Identity key pair:** long-term Ed25519 key pair. The private key never
  leaves the device and is stored encrypted (PBKDF2 + AES-256-GCM, mode 0600).
- **Name:** human-readable, chosen by the user. *A name is never proof of
  identity.*
- **Fingerprint:** `SHA256(identity public key)` rendered as
  `SHA256: AB:CD:…` (uppercase hex, colon-separated). Users compare
  fingerprints out-of-band and then `/verify <peer>`.

## 3. Handshake (authenticated key exchange)

The handshake is a Noise-style `XX` pattern: ephemeral X25519 Diffie–Hellman,
then **both** parties authenticate by signing the full transcript hash with
their long-term Ed25519 keys. The initiator is the TCP dialer ("client"); the
acceptor is the listener ("server"). Roles affect only ordering, not trust.

```
Initiator (A)                                   Responder (B)
--------------                                  -------------
ea := X25519 ephemeral
msg1 = HandshakeInit{ ea_pub }
        --------------------------------------->
                                                eb := X25519 ephemeral
                                                h := SHA256(proto || ea_pub || eb_pub)
                                                shared := X25519(eb, ea_pub)
                                                msg2 = HandshakeAuth{
                                                  id_pub_B, name_B,
                                                  Sig_B(h),
                                                  Enc_k(msg2)(eb_pub)
                                                }
        <---------------------------------------
h := SHA256(proto || ea_pub || eb_pub)
shared := X25519(ea, eb_pub)          ← keys derived BEFORE trust decisions
verify Sig_B(h) with id_pub_B         ← abort on failure (MITM detection)
msg3 = HandshakeAuth{ id_pub_A, name_A, Sig_A(h), Enc_k(msg3)(∅) }
        --------------------------------------->
                                                verify Sig_A(h) with id_pub_A
                                                ← abort on failure
```

`Enc_k` denotes AES-256-GCM under `k(msgN)` (§5) with the message header as
additional data. The responder's ephemeral public key is encrypted so a passive
observer learns neither party's ephemeral key until authentication succeeds,
and the transcript hash binds both ephemeral keys to the signatures — an
active attacker cannot substitute either key without invalidating a signature.

**Handshake failures** (bad signature, malformed message, timeout) abort the
connection immediately with no retry of the same material. Ephemeral keys are
zeroised after use.

### 3.1 Why this prevents MITM

To sit in the middle, an attacker must present its own ephemeral key to each
side; but the transcript hash `h` covers both ephemeral keys, and each peer
signs `h` with its long-term identity key. The attacker cannot produce
`Sig_B(h)` without B's private key, and cannot make A accept a different `h`
for B without breaking the signature. The only thing an attacker can do is
relay the handshake unmodified — in which case it learns nothing and cannot
forge messages afterwards.

## 4. Session establishment & security state

After both signatures verify, each side:

1. Records the peer in the trust store (`internal/peers`):
   - **New identity** → stored, marked `UNVERIFIED` (connection is
     `SECURE / UNVERIFIED`).
   - **Known, same key** → keeps existing verification state
     (`SECURE / VERIFIED` if the user verified the fingerprint).
   - **Known, different key** → `IDENTITY CHANGED` → connection marked
     `UNTRUSTED`, and the UI shows a prominent warning (§9). The key record is
     **not** overwritten silently; the user must explicitly `/verify` the new
     fingerprint to trust it again.
2. Derives session keys (§5) and constructs a `Session`.

## 5. Key derivation (HKDF-SHA-256)

```
root     := HKDF(shared, salt=h, info="heimdall v1 root")
k(msg2)  := HKDF(shared, salt=h, info="heimdall v1 hs2")
k(msg3)  := HKDF(shared, salt=h, info="heimdall v1 hs3")
send_A   := HKDF(root, info="heimdall v1 send A→B")   // per-direction chains
send_B   := HKDF(root, info="heimdall v1 send B→A")
```

Directional chains mean sender and receiver keys are independent. `h` (the
transcript hash) is used as the salt, binding every key to this exact
handshake — no cross-session key reuse is possible.

## 6. Message format

Every session message (§10 framing aside) is:

```
offset  size  field
0       1     version        = 1
1       1     type           (see §7)
2       8     session_id     random 64-bit, derived per session
10      8     sequence       monotonically increasing per direction
18      4     rotation       key-rotation epoch (see §8)
22      ..    ciphertext     AES-256-GCM(nonce, key, plaintext, aad=header[0:22])
                where nonce = 12 random bytes, prepended inside ciphertext
```

`aad = header[0:22]` authenticates version, type, session id, sequence and
rotation with the ciphertext. **No header field is trusted before the tag
verifies.** On any authentication failure the frame is dropped and counted;
repeated failures terminate the session.

The inner plaintext of a `TypeChat` frame is `ChatPayload{ text }`
(length-prefixed UTF-8, max 4096 bytes). Display happens **only after**
successful authentication and decryption — unauthenticated plaintext is never
shown.

## 7. Message types

| Type | Name | Meaning |
|---|---|---|
| 1 | `TypeChat` | User chat message |
| 2 | `TypePing` | Keepalive / liveness probe |
| 3 | `TypePong` | Keepalive response |
| 4 | `TypeClose` | Clean session termination |

`Ping/Pong/Close` participate in the same ratchet and replay window as chat
messages, so control traffic cannot be replayed or injected either.

## 8. Replay protection, ordering, and key rotation

**Sequence numbers.** Each direction has a counter starting at 0, incremented
per message. The receiver keeps a sliding window of the last 1024 accepted
sequence numbers:

- `seq > highest` → accept, slide window.
- `highest - 1024 < seq <= highest` → accept only if that slot has **not** been
  seen (duplicate → drop as replay).
- `seq <= highest - 1024` → drop (too old).

**Ratchet (per-message).** After each message in a direction, that direction's
chain key advances: `chain' := HKDF(chain, info="heimdall v1 ratchet")`, and
the message key is `HKDF(chain, info="heimdall v1 msg")`. Old chain keys are
discarded, so compromise of the current state does not expose earlier messages
(forward secrecy within a session), and each message uses a unique key.

**Key rotation (epoch).** Every 1000 sent messages the sender performs a full
re-key: both directions' chains are re-derived from `HKDF(root, info="… rotate
<n>")` where `n` is the new epoch. The `rotation` header field tells the
receiver which epoch the message belongs to; the receiver keeps the current
and previous epoch's chains and rejects epochs outside that range. Rotation
bounds the amount of data encrypted under any chain and heals the state if a
chain key were ever leaked.

**Session termination.** Either side may send `TypeClose`; after sending it, a
side sends nothing further. Receiving `TypeClose`, a transport EOF, or a
timeout ends the session; all keys are zeroised. Session state is never
persisted — reconnecting performs a fresh handshake with fresh ephemeral keys.

## 9. Identity changes & peer verification

The trust store maps a peer's stable record (name + fingerprint + key) to a
verification state. Rules:

1. A name is only a label; two peers may share a name. The key is the identity.
2. On connect, if the presented key differs from the stored key for that peer,
   the connection is `UNTRUSTED` and the UI prints:

```
!!! SECURITY WARNING !!!

The identity key for 'alice' has changed.

Previous fingerprint:  SHA256: <old>
New fingerprint:       SHA256: <new>

Possible MITM attack or legitimate key replacement.
Connection marked UNTRUSTED.
```

3. `/verify <peer>` marks the **currently stored** fingerprint as verified
   after the user compares it out-of-band. `/fingerprint <peer>` shows it.
4. The stored key is replaced only by explicit user action, never silently.

## 10. Transport framing (not part of the cryptographic protocol)

`internal/transport` provides length-prefixed frames over TCP:

```
4 bytes  big-endian uint32 payload length (max 1 MiB; larger → connection dropped)
N bytes  opaque payload (a §3 handshake message or a §6 session frame)
```

The transport enforces read/write deadlines and a maximum frame size. It knows
nothing about cryptography or the UI; the protocol knows nothing about sockets.

## 11. Error handling summary

| Condition | Action |
|---|---|
| Malformed frame / handshake message | Drop; abort handshake or count toward session error budget |
| Bad handshake signature | Abort connection immediately (possible MITM) |
| AEAD authentication failure | Drop frame; after threshold, terminate session |
| Replay / duplicate / too-old sequence | Drop frame |
| Invalid rotation epoch | Drop frame |
| Identity key changed | Mark UNTRUSTED, warn user, keep old record until user acts |
| Timeout | Close connection; session manager may reconnect with a fresh handshake |

## 12. Explicit non-goals

No padding/traffic-analysis resistance, no anonymous routing, no offline
message queueing, no group chats, no NAT traversal in v1 (the networking layer
is deliberately separated so hole-punching/relays can be added without touching
the cryptographic protocol).
