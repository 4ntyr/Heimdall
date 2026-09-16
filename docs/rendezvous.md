# Heimdall Rendezvous & Relay Specification

Version: 1

This document defines the rendezvous and relay protocol **before** the
implementation, in the same spirit as `docs/protocol.md`. It is the contract
for invite codes, peer pairing, candidate exchange, hole-punch coordination,
relay circuits, and the connection ladder used to traverse restrictive
networks.

This protocol sits **below** the cryptographic protocol of `docs/protocol.md`
and does not modify it. A relay circuit carries exactly the same
length-prefixed frames (§10 of that document) that a direct TCP connection
carries. The end-to-end handshake, session keys and message encryption are
untouched and unaware of how the bytes travel.

## 0. Governing requirement

Two peers must be able to talk **on any network**, without manual router
configuration, and without a firewall in between being able to block it.

Everything here follows from that. Direct connections and NAT hole punching
are *opportunistic optimisations*: they lower latency and relay load when they
work, and nothing depends on them, because they cannot be made to work
everywhere. The relay circuit is the path that always works.

The guarantee holds **once a relay is configured**. Relays are self-hosted;
Heimdall ships no relay address. "Works on any network" therefore means "works
on any network, against a relay you or your correspondent runs".

## 1. Why this traverses firewalls

Four properties. Each is a constraint on everything that follows.

### 1.1 Never require inbound connectivity

Every connection Heimdall makes is outbound. The listener (`-listen`) is
optional: `-listen ""` disables it entirely. A peer with no listener, no
forwarded port, and a default-deny personal firewall is fully usable. This
alone removes the most common cause of failure.

### 1.2 Look exactly like HTTPS, on port 443

A relay connection is:

1. TCP to the relay on port 443;
2. a real **TLS 1.3** handshake (`crypto/tls`), with SNI;
3. a real **HTTP/1.1 WebSocket upgrade** (RFC 6455): `GET <path>` with
   `Upgrade: websocket`, `Connection: Upgrade`, `Sec-WebSocket-Key` and
   `Sec-WebSocket-Version: 13`, answered with `101 Switching Protocols` and a
   correct `Sec-WebSocket-Accept`;
4. RFC 6455 **binary frames** carrying either control messages (§3) or circuit
   payload bytes (§5).

Not "TLS-like" and not a custom `Upgrade` token: layer-7 inspecting proxies
routinely permit a genuine HTTPS WebSocket and drop anything else. To a
middlebox this is a long-lived HTTPS WebSocket — the most universally
permitted flow on the internet.

Because the server side is an ordinary `net/http` handler that hijacks the
connection, a relay can be mounted at a path on a domain the operator already
serves (`https://example.com/hmdl`), beside a real website on the same port.
On networks that only permit a whitelist of destinations, this is the
difference between reachable and not.

### 1.3 Relay TLS is deliberately not a security boundary

All security is end-to-end: the Ed25519-signed handshake transcript
(`docs/protocol.md` §3.1) and the pairing confirmation of §4 below. The relay
is an untrusted byte pipe **by construction** — it sees ciphertext, never
plaintext, never an identity key, and cannot impersonate either peer.

Consequently the client may accept a TLS certificate it cannot verify, and
loses nothing by doing so. This is not a weakness worked around; it is a
capability:

- A corporate proxy that intercepts and re-signs TLS does not break Heimdall.
  Applications that pin certificates fail on exactly these networks.
- A relay operator can use a self-signed certificate with no CA at all.

Certificate handling:

| Mode | Behaviour |
|---|---|
| default | verify against system roots; **on verification failure, retry once without verification** |
| `-relay-pin <base64-sha256-spki>` | accept only a certificate whose SubjectPublicKeyInfo hashes to the pin; no fallback |
| `-relay-verify` | strict verification against system roots; no fallback |

The default is safe *only because* §4 is mandatory. An implementation that
weakens §4 must also remove the unverified fallback.

### 1.4 Survive middleboxes that reap connections

Proxies drop idle sockets aggressively, often after 60 seconds. Therefore:

- WebSocket `Ping` every 20 s on the relay control connection;
- `proto.TypePing` keepalive every 20 s on every peer session, dropping the
  session after 3 missed `Pong`s;
- automatic reconnection of the control connection with exponential backoff,
  re-publishing any invite codes that are still pending, so a reaped
  connection heals instead of silently failing.

### 1.5 The connection ladder

The ladder is walked **once**, when the control connection is established. The
rung that worked is remembered for the lifetime of the process, and circuit
connections (§5) reuse it, so the cost is paid a single time.

| Rung | Path | Defeats |
|---|---|---|
| A | TLS + WebSocket to `relay:443`, direct | home, mobile, most corporate networks |
| B | Same, through an HTTP `CONNECT` proxy | networks where direct outbound is blocked and a proxy is mandatory |
| C | Same, over port 80 without TLS (plain HTTP WebSocket upgrade) | networks that block 443 but pass 80 |

Rung B takes the proxy from `-proxy`, else `HTTPS_PROXY`, else `https_proxy`,
and supports `Proxy-Authorization: Basic`. Rung C is acceptable precisely
because of §1.3: dropping TLS costs metadata hygiene, not confidentiality —
the payload is already end-to-end encrypted.

Each rung is given ~5 seconds before the next is tried.

### 1.6 What this does not defeat

- A **destination whitelist** that permits only approved domains can still
  block an unknown relay host. The mitigation is operational, not protocol:
  host the relay on a domain and path the network already permits (§1.2).
- **Active probing** of the relay endpoint by a censor is out of scope.

Everything short of these is covered.

## 2. Invite codes

A rendezvous is addressed by a short-lived invite code, never by an identity.
The relay never learns a fingerprint, a name, or a long-term key.

`/invite` generates 20 bytes from the OS CSPRNG and renders them as unpadded
base32 (RFC 4648), grouped in fours for transcription:

```
K7QM-2R4T-9XJD-BW5N-HC3P-8YFA-6ZE2-VS4K
```

Both peers derive two independent values with HKDF-SHA-256
(`internal/crypto.DeriveKey`) from the decoded 20 bytes:

```
rendezvousID := HKDF(code, info="heimdall v1 rendezvous id", 16 bytes)
pairingKey   := HKDF(code, info="heimdall v1 pairing key",   32 bytes)
```

- `rendezvousID` **is sent to the relay**. It is the only thing the relay pairs
  on. It reveals nothing about either peer.
- `pairingKey` is **never sent to the relay**, and never leaves the two
  endpoints. It seals the candidate exchange (§3.3) and keys the pairing
  confirmation (§4).

Codes are single-use and expire; see §6.

## 3. Control protocol

Control messages are JSON objects, one per WebSocket binary frame, capped at
8 KiB. JSON is used rather than a binary encoding because the control plane
carries **no secrets** — everything sensitive is an opaque sealed blob — so
inspectability is worth more than compactness here.

Binary fields (`rid`, `cand`, `peer_cand`, `ticket`) are standard base64.

Replies echo the `rid` they concern. A client may have several rendezvous
outstanding at once on one control connection, and the echo is what lets it
route each reply to the right one.

### 3.1 Messages

| `type` | Direction | Fields |
|---|---|---|
| `publish` | client → relay | `rid`, `cand` |
| `published` | relay → client | `rid`, `observed` |
| `claim` | client → relay | `rid`, `cand` |
| `paired` | relay → client | `rid`, `role`, `peer_cand`, `peer_observed`, `punch_in_ms`, `ticket` |
| `circuit` | client → relay | `ticket` |
| `circuit_ok` | relay → client | — |
| `error` | relay → client | `reason` |
| `bye` | either | `reason` |

### 3.2 Flow

```
Peer A (publisher)                  Relay                  Peer B (claimer)
------------------                  -----                  ----------------
publish{rid, candA}      ------->
                         <-------   published{observedA}
   (A prints the invite code; the user sends it out-of-band to B)

                                             <-------   claim{rid, candB}
                                             ------->   published{observedB}
                         <-------   paired{role=publisher,
                                           peer_cand=candB,
                                           peer_observed=observedB,
                                           punch_in_ms, ticket=Ta}
                                             ------->   paired{role=claimer,
                                                               peer_cand=candA,
                                                               peer_observed=observedA,
                                                               punch_in_ms, ticket=Tb}
```

`observed` is the TCP source address the relay sees. It is the
server-reflexive candidate, and the reason no STUN implementation is required.
Behind a `CONNECT` proxy (rung B) the observed address belongs to the proxy,
so punching is skipped and the relay circuit carries the session.

`punch_in_ms` is a **relative** delay, not an absolute timestamp: peer clocks
are not synchronised, and a relative delay needs no clock agreement. Each peer
starts punching that many milliseconds after receiving `paired`.

**Roles.** The publisher is the handshake responder; the claimer is the
handshake initiator. Roles come from the rendezvous, not from which socket won,
so both peers agree even when punching yields two connections (§7).

### 3.3 Candidate exchange

`cand` and `peer_cand` are `crypto.Seal(pairingKey, …)` over a JSON candidate
list. The relay forwards an opaque blob and learns no endpoints beyond the TCP
source addresses it observes anyway.

```json
{"candidates":[{"addr":"192.168.1.20:7331","kind":"host"}]}
```

Candidates are **untrusted input even after they decrypt**, because the peer
supplying them may be hostile. A receiver must:

- accept at most 8 candidates, and at most 2 private-range candidates;
- reject loopback, link-local (unicast and multicast), multicast, broadcast
  and unspecified addresses;
- rate-limit and time-bound punch attempts (§7).

A TCP SYN offers an attacker no amplification, but these caps keep Heimdall
from being usable as a packet source against a third party.

## 4. Pairing confirmation (channel binding) — mandatory

An invite code is used for **first contact**, where the trust store holds no
key to compare against. Without a binding to the code, a hostile relay could
answer the claim itself and become a trust-on-first-use man-in-the-middle.

After the `docs/protocol.md` §3 handshake completes on a path established
through a rendezvous, each side sends a `TypePairConfirm` (frame type 5) frame
inside the encrypted session, carrying:

```
confirm := HKDF(pairingKey, salt=transcript_hash, info="heimdall v1 pairing confirm", 32 bytes)
```

where `transcript_hash` is the §3 handshake transcript `h`. The value is
compared with `crypto/subtle.ConstantTimeCompare`.

Rules:

1. Whenever the local side used an invite code, the confirm frame is
   **required** within the handshake deadline. Absence is a failure, not a
   fallback — otherwise an attacker downgrades by simply omitting it.
2. On mismatch or absence the connection is dropped, a security warning is
   surfaced, and the peer is **not** written to the trust store.
3. Only after the confirmation succeeds is the peer recorded and the session
   handed to the chat layer.

This composes HKDF with a constant-time comparison over material the handshake
already produces. It introduces no new cryptographic construction and does not
alter the §3 handshake. It is what makes §1.3 safe.

## 5. Relay circuits

A circuit is a **separate connection**, dialled up the same ladder rung that
the control connection proved to work. After the WebSocket upgrade the client
sends `circuit{ticket}`; the relay validates the one-time ticket, answers
`circuit_ok`, and switches that connection into splice mode.

When both tickets of a pair have arrived, the relay copies bytes in both
directions and nothing else. It never parses, buffers whole messages, or
inspects payload.

Inside the WebSocket the circuit is a plain byte stream, so the existing
length-prefixed framing and the existing handshake run over it unchanged.

Each side gets a **distinct** ticket (`Ta`, `Tb`) for the same circuit, so a
ticket disclosed by one peer cannot be used to occupy the other's slot.

## 6. Relay behaviour, limits and abuse resistance

The relay **never initiates an outbound connection** and only ever splices two
paired circuits. It cannot be used as a general proxy or as a reflector.

| Limit | Default |
|---|---|
| Invite code TTL | 5 min |
| Claims per code | 1 |
| Control frame size | 8 KiB |
| Pending codes (global) | 4096 |
| Concurrent circuits (global) | 512 |
| Circuit idle timeout | 90 s |
| Circuit lifetime | 12 h |
| Circuit bytes (each direction) | 256 MiB |
| Connections per source IP | 32 |
| Publishes per source IP | 30 / min |

Exceeding a limit yields `error{reason}` and a close. The relay keeps no
persistent state and writes no logs containing rendezvous IDs, tickets or
payload.

## 7. Hole punching (opportunistic)

Both peers bind their punch listener to the **same local port** they used for
the relay control connection, so the NAT mapping that connection already
created can be reused. This requires `SO_REUSEADDR` (and `SO_REUSEPORT` on
Linux and the BSDs) on both the listening and the dialling socket.

At `punch_in_ms` after `paired`, each peer simultaneously:

- dials the peer's observed endpoint from that local port, retrying every
  250 ms for at most 5 s; and
- accepts on that same local port.

Either the outbound dial completes (a true TCP simultaneous open) or the
listener accepts a SYN that the peer's NAT admitted because the local SYN had
already created a mapping. The first `net.Conn` obtained wins.

Success depends on the NAT performing endpoint-independent mapping for TCP. A
meaningful share of networks will never punch successfully. That is acceptable
here and only here: nothing depends on it, and the relay circuit is already
running.

### 7.1 Path selection

| Path | Started | Note |
|---|---|---|
| direct dial to host candidates | immediately | wins instantly on the same LAN or with working IPv6 |
| punch | at `punch_in_ms` | free when the NAT allows it |
| relay circuit | after a 1.5 s grace, and always if nothing else has completed | **the guarantee** |

All paths race to a *completed handshake*, not to a connected socket: a path
that connects but fails to authenticate loses. Losing paths are closed.

## 8. Duplicate resolution

Racing several paths — and punching in particular, where each peer dials the
other and both succeed — legitimately produces more than one connection to the
same identity. Both peers must independently discard the same one, or each
spends the session replacing the other's choice.

The rule, computed identically on both sides:

> Keep the connection with the **numerically smaller session ID**; close the
> other. A connection that has stopped answering keepalives is replaceable
> regardless.

The session ID is derived from the handshake transcript, so both ends of one
connection compute the same value and two different connections compute
different values. It is the only identifier the two peers genuinely agree on:

- **handshake roles cannot serve**, because the rendezvous fixes them
  identically on every competing path;
- **dial direction cannot serve**, because it is opposite on the two sides.

The keepalive exception exists so that a peer reconnecting over a
black-holed path is never refused by a connection that is dead but not yet
detected as such.

### 8.1 Settling before the user is told

Duplicate resolution is not enough on its own. Announcing the first path to
finish and then swapping it for one that finishes a moment later tears down a
socket that may already be carrying a message, and chat frames are not
acknowledged — so a user who connects and immediately types would lose what
they typed, silently.

Therefore a freshly authenticated connection waits **750 ms** before it is
announced. During that window duplicates resolve by the rule above, and only
the survivor is ever mentioned; a connection that loses never existed as far as
the user is concerned. Once a connection *has* been announced and is still
answering keepalives, it is never replaced: a second path finishing later is
redundant, and the session in progress matters more than using the
theoretically cheaper route.

The consequence is deliberate and worth stating: Heimdall does not migrate a
live session from the relay to a direct path. The relay circuit only opens
after a 1.5 s grace period, so a direct path that works has normally already
won before the relay is ever dialled.

## 9. What the relay learns

| The relay sees | The relay cannot see |
|---|---|
| Two IP addresses connected at a given time | Either peer's identity key, fingerprint or name |
| A rendezvous ID (random, single-use, unlinkable to identity) | The invite code or the pairing key |
| Circuit byte counts and timing | Any plaintext, or any candidate address list |
| Connection metadata already visible to any on-path observer | Which two identities are talking |

The relay cannot man-in-the-middle a session: it can only relay the handshake
unmodified, which is the case already analysed in `docs/protocol.md` §3.1, and
it cannot impersonate a peer on first contact because of §4.

Running a relay is nonetheless a metadata position. `docs/threat-model.md`
states this explicitly.

## 10. Non-goals

No UDP or QUIC transport, no mid-session migration from relay to direct, no
UPnP/NAT-PMP port mapping, no multi-relay failover, no domain fronting, no
resistance to active probing, and no anonymity against a relay operator
beyond what §9 describes.
