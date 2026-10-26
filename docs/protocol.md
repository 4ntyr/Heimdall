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
send_A   := HKDF(root, info="heimdall v1 send A-to-B")   // per-direction chains
send_B   := HKDF(root, info="heimdall v1 send B-to-A")
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
| 5 | `TypePairConfirm` | Proof of holding an invite code (`docs/rendezvous.md` §4) |
| 6 | `TypeFileOffer` | Offer to send a file (§13) |
| 7 | `TypeFileAccept` | Agreement to receive an offered file (§13) |
| 8 | `TypeFileChunk` | One slice of a file's contents (§13) |
| 9 | `TypeFileDone` | End of a file, with its digest (§13) |
| 10 | `TypeFileCancel` | Abandon a transfer in either direction (§13) |

`Ping/Pong/Close/PairConfirm` participate in the same ratchet and replay window
as chat messages, so control traffic cannot be replayed or injected either. So
do the file types: a transfer is carried entirely inside the established
session and is encrypted, sequenced and replay-protected exactly as chat is.

A receiver drops any type it does not recognise. Because the version byte is
asserted rather than negotiated (§6), an older peer treats types 6–10 as
malformed and silently discards them; §13 explains how a sender detects that
rather than waiting forever.

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
| Malformed file payload (§13) | Cancel that transfer; the session continues |
| File chunk offset not the expected one (§13) | Cancel that transfer; discard the partial file |
| File exceeds its declared size or the local cap (§13) | Cancel that transfer; discard the partial file |
| File digest mismatch at `TypeFileDone` (§13) | Discard the partial file; never publish it; report to the user |
| `TypeFileCancel` for an unknown transfer | Ignore (never answer with a cancel of your own) |

## 12. Relationship to NAT traversal

NAT traversal is specified separately in `docs/rendezvous.md`: invite codes, a
rendezvous/relay server, TCP hole punching, and the connection ladder that gets
a relay connection through restrictive networks.

That layer sits strictly **below** this one and does not modify it. A relay
circuit carries exactly the §10 frames a direct TCP connection carries, and the
relay sees only ciphertext — it is precisely the "attacker who can only relay
the handshake unmodified" of §3.1.

One addition touches this document: frame type 5, `TypePairConfirm` (§7). It
carries `HKDF(pairingKey, salt=h, info="heimdall v1 pairing confirm")`, where
`pairingKey` comes from an invite code and `h` is the §3 transcript hash. It
authenticates *first contact* over an untrusted relay, and is mandatory
whenever the local side used an invite code. It changes neither the handshake
nor the session keys; see `docs/rendezvous.md` §4.

## 13. File transfer

A file is carried as ordinary session frames (§6) — the same AEAD, the same
sequence numbers, the same replay window and the same key rotation that chat
uses. There is no second connection, no separate key schedule and no change to
the handshake. The transport's 1 MiB frame ceiling (§10) is irrelevant here:
`MaxPlaintext` (4096) binds first, so a file is split across many frames and
reassembled by the receiver.

### 13.1 Payload formats

All integers are big-endian. Each payload must fit `MaxPlaintext`.

| Type | Payload |
|---|---|
| `TypeFileOffer` | `transfer_id(8) \| size(8) \| name_len(2) \| name(name_len)` |
| `TypeFileAccept` | `transfer_id(8) \| start_offset(8)` |
| `TypeFileChunk` | `transfer_id(8) \| offset(8) \| data(1..4080)` |
| `TypeFileDone` | `transfer_id(8) \| sha256(32)` |
| `TypeFileCancel` | `transfer_id(8) \| reason(1)` |

`transfer_id` is 64 random bits chosen by the sender, scoped to one session and
one direction. `name` is at most 255 bytes of valid UTF-8 and is **never** a
path — see §13.5. A chunk carries at most `MaxPlaintext - 16` = 4080 bytes.

### 13.2 Exchange

```
Sender                                          Receiver
------                                          --------
TypeFileOffer{id, size, name}
        --------------------------------------->
                                                decide (§13.5); on refusal
                                                TypeFileCancel{id, reason}
        <---------------------------------------
                                                on acceptance
                                                TypeFileAccept{id, start_offset}
        <---------------------------------------
TypeFileChunk{id, offset, data}   (repeated)
        --------------------------------------->
TypeFileDone{id, sha256}
        --------------------------------------->
                                                verify digest, publish or discard
```

The sender **must not** send chunks before an Accept. Two reasons: a receiver
that refuses would otherwise have already been sent the data, which over a relay
spends a byte budget that cannot be reclaimed (`docs/rendezvous.md` §6); and
because the protocol version is asserted rather than negotiated (§6), an Accept
that never arrives is the only way a sender can learn the peer is too old to
understand types 6–10. A sender that gets no Accept and no Cancel within a
bounded time abandons the offer and tells its user the peer does not support
file transfer.

The digest travels in `TypeFileDone`, not in the offer, so the sender hashes
incrementally as it reads. Hashing up front would require reading the whole file
twice and would describe the bytes as they were *before* the transfer rather
than the bytes actually sent.

`start_offset` lets a future version resume a partial file; it is the receiver's
to choose, because only the receiver knows how much it already holds. This
version always sends 0, and a sender rejects any value other than 0.

### 13.3 Chunk ordering is a requirement, not a hint

The underlying stream is reliable and ordered (§10), so `offset` is not needed
for reassembly. It is carried so that the receiver can *enforce* placement
rather than trust it. For every chunk the receiver requires:

- `offset` equals the number of bytes it has already written for this transfer;
- `data` is non-empty;
- `offset + len(data)` is within both the offer's declared `size` and the
  receiver's own cap.

Any violation cancels the transfer and discards the partial file. A receiver
never seeks: a peer cannot direct a write to an arbitrary position, and a
declared `size` is an upper bound to check, never an allocation to make.

### 13.4 Forward compatibility

Decoders **must** ignore bytes trailing the fields defined above; encoders
**must not** rely on their absence. A later version may therefore append fields
to any of these payloads without a new type or a version bump. This is the only
sanctioned extension mechanism for file transfer, and it is the reason no
reserved padding is defined.

`TypeFileChunk` is the one exception, and it cannot be otherwise: everything
after its 16-byte header *is* the chunk data, so there is no trailing region to
extend into. A future version that needs a per-chunk field must introduce a new
type for it. The four control payloads are where extension room exists, and they
are where it is needed.

Strictness applies to everything else: a payload shorter than its fixed fields,
a `name_len` that overruns the payload, a name that is not valid UTF-8, or an
empty chunk is malformed and cancels the transfer.

### 13.5 What the receiver decides

Accepting a file means writing attacker-chosen bytes under an attacker-chosen
name to local disk, so the receiver — not the sender — owns every such decision:

- A peer whose identity key has changed (§9) is refused outright. That state is
  an unresolved MITM warning; it is not a state in which to write files.
- The name is treated as a label, never a path, and is sanitised to a single
  filename before use. An existing file is never overwritten.
- Size, count and inactivity limits are the receiver's own, independent of
  anything the sender declares.
- A completed file is published only after its digest matches §13.1's `sha256`.

`docs/threat-model.md` states which of these are security boundaries and which
are merely hygiene.

### 13.6 Cancellation

Either side may send `TypeFileCancel` at any time; `reason` is advisory and for
display. A `TypeFileCancel` naming a transfer the receiver does not know is
**ignored** — answering it with another cancel would let two peers volley
forever. Cancelling a transfer never ends the session, and losing the session
cancels every transfer on it: no transfer state survives a reconnect.

## 14. Explicit non-goals

No padding/traffic-analysis resistance, no anonymous routing, no offline
message queueing, no group chats. File transfer is not resumable across a
dropped session, and `start_offset` (§13.2) is reserved but unused.
