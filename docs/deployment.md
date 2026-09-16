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

## Step 6 — Chat without port forwarding (invite codes)

Step 5 needs one side to be directly reachable, which usually means
configuring your router. You can skip all of that with a **relay**.

A relay introduces two people who each connect *outward* to it — something
almost every network allows — and forwards encrypted frames between them when
they cannot reach each other directly. It never sees your messages, your name
or your identity key, and it cannot impersonate either of you. See
`docs/rendezvous.md` §9 for exactly what it does and does not learn.

You need a relay you or your friend runs (see "Running your own relay" below);
Heimdall ships no relay address and contacts none unless you ask it to.

**Person A:**

```sh
./hmdl -relay relay.example.com
# Relay relay.example.com reachable over tls; /invite and /join are available
```

Then type `/invite`:

```
/invite
Give this code to your peer; it is valid for five minutes:

    K7QM-2R4T-9XJD-BW5N-HC3P-8YFA-6ZE2-VS4K

Send it over a channel you trust — anyone who has it can answer it.
```

**Person B** runs the same command and joins:

```sh
./hmdl -relay relay.example.com
```

```
/join K7QM-2R4T-9XJD-BW5N-HC3P-8YFA-6ZE2-VS4K
```

Both sides print `*** <name> connected`. `/peers` shows how the connection was
made: `DIRECT` (straight to each other), `PUNCHED` (through both NATs), or
`RELAY` (via the relay). Heimdall tries all three at once and keeps the best
one, so a relay is used only when it is actually needed.

Neither side needs a listening port at all. If you want to be certain nothing
is listening, run with `-listen ""`.

**Send the code over a channel you trust.** Anyone who has the code within its
five-minute life can answer it, and they would then appear as a normal
unverified peer. Verify fingerprints afterwards as in Step 5 — a relay cannot
fake them.

### Commands you can type

| Command | What it does |
|---|---|
| `/invite` | publish an invite code for a peer to join with (needs `-relay`) |
| `/join <code>` | connect to whoever published an invite code (needs `-relay`) |
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
| `-relay` | — | relay to use for `/invite` and `/join`, e.g. `relay.example.com` or `https://example.com/hmdl` |
| `-relay-pin` | — | certificate pin for a self-signed relay (printed by `hmdl-relay` at startup) |
| `-relay-verify` | off | refuse a relay certificate that cannot be verified, instead of tolerating interception |
| `-proxy` | `$HTTPS_PROXY` | HTTP proxy to reach the relay through |

Passing `-listen ""` disables the listener entirely. Everything still works
through a relay, and nothing on your machine accepts inbound connections.

## Running your own relay

The relay is a second binary in the same repository:

```sh
go build -o hmdl-relay ./cmd/hmdl-relay
sudo ./hmdl-relay
```

By default it listens on `:443` (TLS) and `:80` (cleartext fallback), serving
at the path `/hmdl`. With no certificate supplied it generates a self-signed
one and prints the pin your users need:

```
Relay listening on :443/hmdl (TLS)
Self-signed certificate. Clients must pass:
  -relay-pin 9mE2v0i…=
```

With a real certificate — from Let's Encrypt or anywhere else — no pin is
needed:

```sh
./hmdl-relay -cert /etc/letsencrypt/live/example.com/fullchain.pem \
             -key  /etc/letsencrypt/live/example.com/privkey.pem
```

| Flag | Default | Meaning |
|---|---|---|
| `-addr` | `:443` | TLS listen address |
| `-http` | `:80` | cleartext listen address; `""` disables it |
| `-path` | `/hmdl` | URL path to serve at |
| `-cert` / `-key` | — | TLS certificate and key (PEM); omit to self-sign |
| `-quiet` | off | suppress connection logging |

**Put it on port 443, behind a hostname you already use.** The relay speaks
real TLS and a real WebSocket upgrade, so it is indistinguishable from ordinary
HTTPS traffic, and it is an ordinary HTTP handler — you can serve it at a path
on a domain that already hosts a website. On networks that only permit
approved destinations, that is the difference between reachable and not.

The relay keeps no persistent state and logs nothing sensitive. It is capped in
every direction it can be pushed (code lifetimes, circuit counts, bandwidth,
per-source rate limits); see `docs/rendezvous.md` §6.

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
- **Friend still can't connect, and you can't forward a port** — use a relay
  and invite codes (Step 6). No port forwarding, no listening port, no router
  configuration.
- **`relay … unreachable`** — check the hostname, and that you passed
  `-relay-pin` if the relay is self-signed. On a network with a mandatory
  proxy, set `HTTPS_PROXY` or pass `-proxy`. Heimdall also tries port 80
  automatically where 443 is blocked.
- **`/invite` says no relay configured** — start HMDL with `-relay <host>`.
- **`join failed: … no such invite code`** — the code was mistyped, already
  used, or older than five minutes. Codes are single-use; ask for a new one.
