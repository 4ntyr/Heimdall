# Networking: options that can be built into XSGR

This file collects the NAT-traversal / no-manual-port-forwarding options
from `docs/deployment.md` ("Avoiding router port-forwarding") that can be
implemented inside the application itself.

Excluded: **overlay networks** (Tailscale, ZeroTier, WireGuard mesh, private
VPN). That option is external third-party networking software and cannot be
built into XSGR — it is a workaround users apply outside the application,
not an application feature.

Context: XSGR's layers are separated cleanly:

- `internal/proto` does not depend on sockets and can run over any
  reliable, ordered, opaque byte stream;
- `internal/transport` is currently a thin TCP dial/listen layer that
  provides that byte-stream contract with length-prefixed frames;
- `internal/session` only needs a connected `FrameIO`.

That means all of the following options can be added without changing the
end-to-end cryptographic protocol.

## Option A — Relay / rendezvous server (best built-in option)

Technique:

A rendezvous service gives peers a shared meeting point on the public
internet. Each side makes an outbound connection to the service, which
works on most NATs without router changes. From there, the service can
either:

- only introduce the peers and help them establish a direct session; or
- stay in the data path and relay encrypted frames between them.

For XSGR, the second form is the most straightforward first step. The
existing handshake can still run end-to-end between peers, while the
relay forwards opaque frames without access to the message plaintext.

How it helps in practice:

- both peers make outbound connections to a public server;
- the server either relays encrypted frames, or joins two outbound
  streams into one session;
- routers usually allow outbound connections, so no manual
  port-forwarding is needed.

Work needed in this repository: **medium to high**.

Likely implementation work:

1. Define the relay protocol: session identifiers, authentication,
   pairing, timeouts, and frame forwarding rules.
2. Add a small public service for peer rendezvous and/or frame relay.
3. Add a new client transport mode alongside direct TCP so
   `internal/session` still receives the same `FrameIO`-style channel.
4. Add CLI/user flows for publishing presence and connecting by code,
   invite token, or relay address instead of raw IP entry.
5. Define reconnect behavior, duplicate-session handling, and relay
   authentication so malicious third parties cannot trivially hijack a
   pending rendezvous.
6. Document the privacy model clearly: the relay learns connection
   metadata, but payloads remain end-to-end encrypted.

Why this fits the current design:

- the relay only needs to move opaque encrypted bytes;
- the existing handshake and message encryption can stay end-to-end.

Tradeoffs:

- most practical built-in solution;
- requires operating public infrastructure;
- adds metadata exposure to the relay (who connected and when, but not
  plaintext if the relay stays below the crypto layer).

## Option B — NAT hole punching (true peer-to-peer, but hardest)

Technique:

Hole punching tries to create a direct path between two peers behind
NATs without requiring manual forwarding. A public rendezvous server
first observes each peer's public address and port. It then tells each
peer where to send packets, and both sides transmit at roughly the same
time so their NAT devices create matching temporary mappings.

In practice, this is usually done with UDP, not raw TCP, because UDP
hole punching is far more widely supported by consumer NATs. That is an
important fit issue for XSGR: the protocol expects a reliable, ordered,
opaque byte stream, so a UDP path would need an adaptation layer that
provides stream-like reliability/ordering semantics, or the project
would need to adopt an equivalent transport such as QUIC.

How it helps in practice:

- both peers contact a rendezvous service first;
- the service tells each side the other's observed public endpoint;
- both sides attempt simultaneous outbound connections to create a
  direct path through NAT.

Work needed in this repository: **high**.

Likely implementation work:

1. Add a rendezvous/discovery service that records each peer's observed
   endpoint and coordinates connection attempts.
2. Add NAT probing and simultaneous-connect orchestration in the client.
3. Add a UDP-capable transport path, plus a reliability/ordering layer
   that turns it into the byte-stream contract required by
   `internal/proto`; alternatively, adopt a transport with those
   guarantees already built in.
4. Rework framing, keepalive, timeout, and reconnect behavior for a
   path that may change addresses or partially fail during setup.
5. Add relay fallback for NATs that cannot be punched, otherwise users
   would still have many failed connections.
6. Add extensive interoperability testing across common NAT types,
   because this feature's correctness depends as much on real networks
   as on local code.

Why this is expensive here:

- the current transport is TCP-only;
- successful hole punching depends heavily on router behavior;
- a production-quality design usually needs fallback relaying anyway.

Tradeoffs:

- preserves direct peer-to-peer connections when it works;
- most complex option to implement and support;
- least predictable across home routers and mobile networks.

## Option C — Prefer IPv6 when both peers have global IPv6

Technique:

IPv6 can remove the specific NAT problem entirely when both peers have
globally routable IPv6 addresses. Instead of punching through or
forwarding an IPv4 NAT, one peer simply listens on an IPv6 address and
the other connects to that address.

This is not universal internet reachability: local firewalls still need
to allow inbound traffic, and many networks either lack IPv6 entirely or
use policies that still make direct inbound access unreliable. But where
it exists, it is the cleanest direct-connection model.

How it helps in practice:

- if both sides have globally routable IPv6, one peer can listen on an
  IPv6 address and the other can connect directly.

Work needed in this repository: **low**.

Implementation plan:

1. Verify and document the exact address formats users should pass to
   `/connect` for IPv6 endpoints.
2. Add deployment guidance for checking whether an address is globally
   reachable rather than link-local or ULA-only.
3. Test listener and dialer behavior on dual-stack hosts to make sure
   the current TCP transport handles expected IPv6 cases cleanly.
4. Update troubleshooting text so users know IPv6 is a valid alternative
   when both networks support it.

Tradeoffs:

- simple where available;
- not universal, especially on some home and mobile providers;
- still requires local firewall rules to allow inbound traffic.

## Option D — Automatic port mapping (UPnP / NAT-PMP / PCP)

This does **not** truly avoid port-forwarding; it only automates it.

Technique:

These protocols let a program ask the local router to create a temporary
inbound mapping automatically. The application still relies on an
inbound public port; the difference is that the user does not have to
open the router admin page and configure the mapping manually.

This is best seen as a convenience feature for the existing direct-TCP
design, not as a new connectivity model.

Work needed in this repository: **medium**.

Implementation plan:

1. Add router discovery and mapping support for one or more of UPnP,
   NAT-PMP, or PCP.
2. Request and renew a mapping for the listen port while XSGR is
   running, then release it on shutdown when possible.
3. Surface mapping success, failure, lease duration, and discovered
   external address clearly in the CLI.
4. Add configuration flags so users can opt in or out instead of always
   opening ports automatically.
5. Document the security implications: this exposes a public inbound
   port and depends on trusting the local network and router behavior.

Tradeoffs:

- useful convenience feature;
- still depends on router support;
- does not help on restrictive networks where mapping is unavailable.

## Recommendation

For a built-in solution inside XSGR, a relay/rendezvous mode (Option A)
is the most practical next step. It gives the highest success rate with
the fewest protocol changes because the existing end-to-end handshake
and session encryption can remain unchanged.

NAT hole punching (Option B) is the most "pure" peer-to-peer approach,
but it is also the largest project and should usually be paired with
relay fallback, which makes it a later-phase optimization rather than
the first implementation target.

IPv6 (Option C) and automatic port mapping (Option D) are low/medium
effort improvements to the existing direct-connection model and can be
pursued independently.
