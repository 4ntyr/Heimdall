# Deployment Guide

This guide takes you from zero to chatting, step by step. No prior Go
experience is needed — just follow the instructions for your platform.

XSGR is a single self-contained executable: once built, it needs nothing
else to run (no Python, no Node, no services, no package manager).

---

## Step 1 — Install Go

XSGR is written in Go. You need **Go 1.24 or newer**.

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
git clone https://github.com/4ntyr/xessenger_cli.git
cd xessenger_cli
```

If you don't have Git, download the ZIP from
<https://github.com/4ntyr/xessenger_cli> (green **Code** button →
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
don't forget it. XSGR then prints:

- your **identity fingerprint** — this is how other people verify it's
  really you;
- the address it is **listening** on.

Every later run is just `go run .` (no `-name` needed; your identity is
loaded from disk) plus your passphrase.

> **Tip:** to avoid typing the passphrase each time, set the environment
> variable `XSGR_PASSPHRASE`:
>
> ```sh
> # Linux / macOS
> export XSGR_PASSPHRASE='your-passphrase'
>
> # Windows PowerShell
> $env:XSGR_PASSPHRASE = 'your-passphrase'
> ```

## Step 4 — Build a real executable (recommended)

So you don't need the source code or `go run` every time:

```sh
# Linux / macOS — produces ./xsgr
go build -o xsgr .

# Windows (PowerShell or Command Prompt) — produces xsgr.exe
go build -o xsgr.exe .
```

Now you can run it directly:

```sh
./xsgr          # Linux / macOS
.\xsgr.exe      # Windows
```

The resulting file is fully self-contained — you can copy it to another
machine (or a USB stick) and it will just work.

### Cross-compiling for a friend on another OS (optional)

```sh
# Build a Windows exe from Linux/macOS (or vice versa)
GOOS=windows GOARCH=amd64 go build -o xsgr.exe .

# Build a Linux binary from Windows/macOS
GOOS=linux GOARCH=amd64 go build -o xsgr .
```

### Installing onto your PATH (optional)

```sh
go install github.com/4ntyr/xessenger_cli@latest
```

This puts a binary named `xessenger_cli` into your Go bin directory
(usually `~/go/bin`). Make sure that directory is on your `PATH` —
`go env GOBIN` or `go env GOPATH` tells you where it is.

## Step 5 — Chat with someone

Both you and your friend run XSGR. One of you needs to know the other's
**IP address and port**.

**Person A** (just listens; the default port is 7331):

```sh
./xsgr
# Listening for peers on [::]:7331
```

A tells B their address, e.g. `203.0.113.10:7331`. (On the same home
network, that's the local IP, e.g. `192.168.1.5:7331`. Over the internet,
the router must forward port 7331 to A's computer.)

**Person B** connects:

```sh
./xsgr -connect 203.0.113.10:7331
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
not over XSGR itself). Each side's fingerprint is printed at startup and
in `/peers`. If they match, both sides run:

```
/verify <name>
```

If a peer's key ever changes unexpectedly, XSGR shows a prominent
`SECURITY WARNING` and marks the connection `UNTRUSTED` — never ignore
it. See `docs/threat-model.md` for details.

## All command-line flags

```
xsgr -h
```

| Flag | Default | Meaning |
|---|---|---|
| `-name` | — | display name, **required on first run** only |
| `-listen` | `:7331` | address/port to listen on |
| `-connect` | — | peer to connect to on startup |
| `-data` | `~/.xessenger` | where the identity file and trust store live |

## Troubleshooting

- **`go: command not found`** — Go isn't installed or your terminal was
  open before installation. Reopen the terminal or reboot.
- **First run asks for `-name`** — you already have an identity, or you
  forgot it: `./xsgr -name yourname` once; afterwards just `./xsgr`.
- **"wrong passphrase or corrupted identity file"** — the passphrase you
  entered doesn't match the one you chose on first run.
- **Friend can't connect** — check the firewall allows inbound
  connections on the listen port (default 7331), and that you're giving
  out the right IP. Over the internet, the listener's router needs a
  port-forward for 7331.
- **`address already in use`** — another XSGR instance is already running
  on that port; close it or pick another with `-listen :7332`.

## Avoiding router port-forwarding

Today, direct internet connections assume one side can accept an inbound
TCP connection on the listen port. That usually means a router
port-forward.

The good news is that XSGR's layers are already separated cleanly:

- `internal/proto` does not depend on sockets and can run over any
  authenticated byte stream;
- `internal/transport` is currently a thin TCP dial/listen layer;
- `internal/session` only needs a connected `FrameIO`.

That means most "no port-forwarding" options can be added without
changing the end-to-end cryptographic protocol.

### Option 1 — Use an overlay network (best short-term workaround)

Examples: Tailscale, ZeroTier, WireGuard mesh, a private VPN.

How it helps:

- both users join the same overlay;
- each side gets a reachable private address;
- XSGR keeps using normal `/connect <addr>` over that overlay.

Work needed in this repository: **very low**.

- No protocol changes.
- No transport changes.
- Mostly documentation: explain that an overlay address can be used
  instead of a public IP.

Tradeoffs:

- easiest path for users today;
- depends on third-party networking software;
- not a built-in XSGR feature.

### Option 2 — Add a relay / rendezvous server (best built-in option)

How it helps:

- both peers make outbound connections to a public server;
- the server either relays encrypted frames, or joins two outbound
  streams into one session;
- routers usually allow outbound connections, so no manual
  port-forwarding is needed.

Work needed in this repository: **medium to high**.

Likely implementation work:

- add a small public service for peer rendezvous and/or frame relay;
- add a new transport mode alongside direct TCP;
- add CLI/user flows for publishing presence and connecting by code,
  name, or relay address;
- define failure handling, reconnect behavior, and relay authentication.

Why this fits the current design:

- the relay only needs to move opaque encrypted bytes;
- the existing handshake and message encryption can stay end-to-end.

Tradeoffs:

- most practical built-in solution;
- requires operating public infrastructure;
- adds metadata exposure to the relay (who connected and when, but not
  plaintext if the relay stays below the crypto layer).

### Option 3 — NAT hole punching (true peer-to-peer, but hardest)

How it helps:

- both peers contact a rendezvous service first;
- the service tells each side the other's observed public endpoint;
- both sides attempt simultaneous outbound connections to create a
  direct path through NAT.

Work needed in this repository: **high**.

Likely implementation work:

- add a rendezvous/discovery service;
- add NAT probing and connection-coordination logic;
- probably add a UDP transport path, because UDP hole punching is far
  more practical than TCP hole punching;
- adapt framing/keepalive/reconnect behavior for the new transport;
- keep a relay fallback for NATs that cannot be punched.

Why this is expensive here:

- the current transport is TCP-only;
- successful hole punching depends heavily on router behavior;
- a production-quality design usually needs fallback relaying anyway.

Tradeoffs:

- preserves direct peer-to-peer connections when it works;
- most complex option to implement and support;
- least predictable across home routers and mobile networks.

### Option 4 — Prefer IPv6 when both peers have global IPv6

How it helps:

- if both sides have globally routable IPv6, one peer can listen on an
  IPv6 address and the other can connect directly.

Work needed in this repository: **low**.

- Go's networking already supports IPv6 addressing.
- The main work is documentation and UX guidance.

Tradeoffs:

- simple where available;
- not universal, especially on some home and mobile providers;
- still requires local firewall rules to allow inbound traffic.

### Option 5 — Automatic port mapping (UPnP / NAT-PMP / PCP)

This does **not** truly avoid port-forwarding; it only automates it.

Work needed in this repository: **medium**.

- add router port-mapping support;
- surface mapping success/failure in the CLI;
- handle security concerns around automatically opening ports.

Tradeoffs:

- useful convenience feature;
- still depends on router support;
- does not help on restrictive networks where mapping is unavailable.

### Recommendation

If the goal is "no manual router configuration" with the least product
work, use an overlay network as the immediate answer and document it.

If the goal is a built-in solution inside XSGR, a relay/rendezvous mode
is the most practical next step. It gives the highest success rate with
the fewest protocol changes because the existing end-to-end handshake and
session encryption can remain unchanged.

NAT hole punching is the most "pure" peer-to-peer approach, but it is
also the largest project and should usually be paired with relay
fallback, which makes it a later-phase optimization rather than the
first implementation target.
