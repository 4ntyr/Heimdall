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
