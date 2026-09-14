# Deployment Guide

This guide takes you from zero to chatting, step by step. No prior Go
experience is needed — just follow the instructions for your platform.

HMDL is a single self-contained executable: once built, it needs nothing
else to run (no Python, no Node, no services, no package manager).

---

## Step 1 — Install Go

HMDL is written in Go. You need **Go 1.24 or newer**.

1. Go to <https://go.dev/dl/> and download the installer for your system
   (Windows `.msi`, macOS `.pkg`, or Linux `.tar.gz`).
2. Run the installer with the default options.
3. Open a **new** terminal (Command Prompt / PowerShell on Windows) and
   check that it worked:

   ```sh
   go version
   ```

   You should see something like `go version go1.24.0 windows/amd64`.
   If you get "command not found", close and reopen your terminal, or
   reboot.

## Step 2 — Get the source code

If you have Git installed:

```sh
git clone https://github.com/4ntyr/heimdall.git
cd heimdall
```

If you don't have Git, download the ZIP from
<https://github.com/4ntyr/heimdall> (green **Code** button →
**Download ZIP**), extract it, and open a terminal inside the extracted
folder.

## Step 3 — Try it without installing anything

```sh
go run . -name alice
```

The first `go run` takes a minute while Go downloads and compiles
everything; later runs are instant.

On the **first run** you will be asked to choose a passphrase. This
passphrase encrypts your identity file (your private key) on disk —
don't forget it. HMDL then prints:

- your **identity fingerprint** — this is how other people verify it's
  really you;
- the address it is **listening** on.

Every later run is just `go run .` (no `-name` needed; your identity is
loaded from disk) plus your passphrase.

> **Tip:** to avoid typing the passphrase each time, set the environment
> variable `HMDL_PASSPHRASE`:
>
> ```sh
> # Linux / macOS
> export HMDL_PASSPHRASE='your-passphrase'
>
> # Windows PowerShell
> $env:HMDL_PASSPHRASE = 'your-passphrase'
> ```

## Step 4 — Build a real executable (recommended)

So you don't need the source code or `go run` every time:

```sh
# Linux / macOS — produces ./hmdl
go build -o hmdl .

# Windows (PowerShell or Command Prompt) — produces hmdl.exe
go build -o hmdl.exe .
```

Now you can run it directly:

```sh
./hmdl          # Linux / macOS
.\hmdl.exe      # Windows
```

The resulting file is fully self-contained — you can copy it to another
machine (or a USB stick) and it will just work.

### Cross-compiling for a friend on another OS (optional)

```sh
# Build a Windows exe from Linux/macOS (or vice versa)
GOOS=windows GOARCH=amd64 go build -o hmdl.exe .

# Build a Linux binary from Windows/macOS
GOOS=linux GOARCH=amd64 go build -o hmdl .
```

### Installing onto your PATH (optional)

```sh
go install github.com/4ntyr/heimdall@latest
```

This puts a binary named `heimdall` into your Go bin directory
(usually `~/go/bin`). Make sure that directory is on your `PATH` —
`go env GOBIN` or `go env GOPATH` tells you where it is.

## Step 5 — Chat with someone

Both you and your friend run HMDL. One of you needs to know the other's
**IP address and port**.

**Person A** (just listens; the default port is 7331):

```sh
./hmdl
# Listening for peers on [::]:7331
```

A tells B their address, e.g. `203.0.113.10:7331`. (On the same home
network, that's the local IP, e.g. `192.168.1.5:7331`. Over the internet,
the router must forward port 7331 to A's computer.)

**Person B** connects:

```sh
./hmdl -connect 203.0.113.10:7331
```

Both sides should now print `*** <name> connected`. Type a message and
press Enter — it's sent to everyone you're connected to.

### Commands you can type

| Command | What it does |
|---|---|
| `/connect <addr>` | connect to another peer, e.g. `/connect 192.168.1.5:7331` |
| `/msg <name> <text>` | send a message to one specific peer |
| `/all <text>` | broadcast to all connected peers (same as typing bare text) |
| `/peers` | list connected peers, their trust level and fingerprints |
| `/verify <name>` | mark a peer's fingerprint as verified |
| `/help` | show the full help |
| `/quit` | exit |

### Verifying a peer (important for security)

Encryption is always on, but to be sure you're talking to the right
person, compare **fingerprints** out-of-band (phone call, in person —
not over HMDL itself). Each side's fingerprint is printed at startup and
in `/peers`. If they match, both sides run:

```
/verify <name>
```

If a peer's key ever changes unexpectedly, HMDL shows a prominent
`SECURITY WARNING` and marks the connection `UNTRUSTED` — never ignore
it. See `docs/threat-model.md` for details.

## All command-line flags

```
hmdl -h
```

| Flag | Default | Meaning |
|---|---|---|
| `-name` | — | display name, **required on first run** only |
| `-listen` | `:7331` | address/port to listen on |
| `-connect` | — | peer to connect to on startup |
| `-data` | `~/.heimdall` | where the identity file and trust store live |

## Troubleshooting

- **`go: command not found`** — Go isn't installed or your terminal was
  open before installation. Reopen the terminal or reboot.
- **First run asks for `-name`** — you already have an identity, or you
  forgot it: `./hmdl -name yourname` once; afterwards just `./hmdl`.
- **"wrong passphrase or corrupted identity file"** — the passphrase you
  entered doesn't match the one you chose on first run.
- **Friend can't connect** — check the firewall allows inbound
  connections on the listen port (default 7331), and that you're giving
  out the right IP. Over the internet, the listener's router needs a
  port-forward for 7331.
- **`address already in use`** — another HMDL instance is already running
  on that port; close it or pick another with `-listen :7332`.

## Avoiding router port-forwarding

Today, direct internet connections assume one side can accept an inbound
TCP connection on the listen port. That usually means a router
port-forward.

The good news is that HMDL's layers are already separated cleanly:

- `internal/proto` does not depend on sockets and can run over any
  reliable, ordered, opaque byte stream;
- `internal/transport` is currently a thin TCP dial/listen layer that
  provides that byte-stream contract with length-prefixed frames;
- `internal/session` only needs a connected `FrameIO`.

That means most "no port-forwarding" options can be added without
changing the end-to-end cryptographic protocol.

### Option 1 — Use an overlay network (best short-term workaround)

Examples: Tailscale, ZeroTier, WireGuard mesh, a private VPN.

Technique:

An overlay network installs a virtual network interface on each device
and creates an encrypted mesh or hub-and-spoke network between members.
From HMDL's point of view, this usually looks like a normal private IP
network: each peer gets an address on the overlay, and `/connect` uses
that address exactly like a LAN address.

This avoids manual router configuration because the overlay software
handles peer discovery, NAT traversal, relay fallback, or coordination
itself. HMDL does not need to know which of those mechanisms the overlay
used; it only sees a working TCP path.

How it helps in practice:

- both users join the same overlay;
- each side gets a reachable private address;
- HMDL keeps using normal `/connect <addr>` over that overlay.

Work needed in this repository: **very low**.

Implementation plan:

1. Document overlay usage in the deployment and quick-start guides.
2. Add examples that use an overlay IP or overlay DNS name with
   `/connect`.
3. Optionally improve error/help text so "friend can't connect" suggests
   trying an overlay when public inbound access is unavailable.

Tradeoffs:

- easiest path for users today;
- depends on third-party networking software;
- not a built-in HMDL feature.

### Option 2 — Add a relay / rendezvous server (best built-in option)

Technique:

A rendezvous service gives peers a shared meeting point on the public
internet. Each side makes an outbound connection to the service, which
works on most NATs without router changes. From there, the service can
either:

- only introduce the peers and help them establish a direct session; or
- stay in the data path and relay encrypted frames between them.

For HMDL, the second form is the most straightforward first step. The
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

### Option 3 — NAT hole punching (true peer-to-peer, but hardest)

Technique:

Hole punching tries to create a direct path between two peers behind
NATs without requiring manual forwarding. A public rendezvous server
first observes each peer's public address and port. It then tells each
peer where to send packets, and both sides transmit at roughly the same
time so their NAT devices create matching temporary mappings.

In practice, this is usually done with UDP, not raw TCP, because UDP
hole punching is far more widely supported by consumer NATs. That is an
important fit issue for HMDL: the protocol expects a reliable, ordered,
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

### Option 4 — Prefer IPv6 when both peers have global IPv6

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

### Option 5 — Automatic port mapping (UPnP / NAT-PMP / PCP)

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
2. Request and renew a mapping for the listen port while HMDL is
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

### Recommendation

If the goal is "no manual router configuration" with the least product
work, use an overlay network as the immediate answer and document it.

If the goal is a built-in solution inside HMDL, a relay/rendezvous mode
is the most practical next step. It gives the highest success rate with
the fewest protocol changes because the existing end-to-end handshake and
session encryption can remain unchanged.

NAT hole punching is the most "pure" peer-to-peer approach, but it is
also the largest project and should usually be paired with relay
fallback, which makes it a later-phase optimization rather than the
first implementation target.
