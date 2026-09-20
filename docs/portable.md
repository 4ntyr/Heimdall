# Heimdall Portable ("HMDL Go") — Design Plan

Version: draft 1

This document specifies a **portable branch** of Heimdall: a build and a set of
conventions that let HMDL run entirely from removable media (a USB stick) and
keep all of its own state on that media, writing as little as possible to the
host it is plugged into.

It is written **before** implementation, in the same spirit as
`docs/protocol.md` and `docs/rendezvous.md`. It changes no wire protocol and no
cryptography — a portable build speaks exactly the same handshake, frames and
session keys as an installed build. Portability is purely about **where state
lives and what touches the host filesystem**.

This is the standard "portable application" pattern (KeePass Portable, Tor
Browser on USB, the PortableApps.com launchers) applied to HMDL: self-contained,
relocatable, and tidy about the host. It is a privacy/usability feature for
someone running the tool on machines they don't want to leave their data on —
a shared workstation, a borrowed laptop, a second machine — not an
anti-forensics claim.

---

## 1. Goals

1. **Single removable root.** Everything HMDL reads or writes — the binary, the
   encrypted identity, the trust store, any config — lives under one directory
   on the stick. Unplug the stick and the tool and all its data are gone with
   it.
2. **Self-locating.** The binary finds its own data directory relative to
   itself, with no `-data` flag and no dependence on `$HOME`, the registry, or
   any host-specific path.
3. **Minimal host writes.** No files written outside the stick by HMDL itself:
   no dotfiles in `$HOME`, no temp files in the host temp dir, no logs, no
   shell history.
4. **Safe removal.** State is flushed to the stick durably (atomic write +
   `fsync`) so the stick can be pulled between sessions without corruption, and
   secrets never outlive the process in memory.
5. **Cross-platform, zero install.** Works on Windows and Linux from the same
   stick with no installer, no admin rights, and no runtime dependencies —
   consistent with HMDL's existing "single static binary" property.

## 2. Non-goals (state them honestly)

Heimdall's threat model (`docs/threat-model.md`) is explicit about what it
cannot defend against, and portable mode must be equally honest. "Near zero
trace" is **best-effort tidiness by the application**, not a guarantee against a
forensic examiner or a compromised host.

Portable mode does **not** claim to:

- **Hide that a USB device was attached.** The host operating system records USB
  attachment independently of anything HMDL does — Windows in the registry
  (`USBSTOR`, `MountedDevices`, `setupapi` logs) and Linux in the kernel log /
  `journald`. HMDL cannot and does not edit host logs.
- **Defeat a compromised or hostile host.** A host with a keylogger, a
  screen recorder, RAM-scraping malware, or a hypervisor can capture the
  passphrase, plaintext messages and session keys regardless of where HMDL
  stores its files. Running on an untrusted machine is outside the threat
  model, portable or not.
- **Prevent host-side memory persistence.** The OS may page process memory to
  disk (swap) or write it to disk on hibernation. HMDL zeroises session keys
  and the decrypted identity on exit, but it cannot guarantee those pages were
  never swapped. Mitigations are discussed in §7; guarantees are not offered.
- **Scrub what the host chooses to record.** Prefetch (Windows), file-access
  timestamps on the stick, antivirus scan logs, and "recently used" lists are
  the host's behaviour. Some are reduced by running the binary off the stick
  (see §7); none are under HMDL's full control.

The honest one-line summary for the README/threat-model: *HMDL Portable keeps
its own footprint on the stick and off the host; it does not erase the
independent traces an operating system keeps of any removable drive.*

## 3. Current state — how close is the code already?

Surprisingly close. The relevant facts from the current tree:

- `main.go` already accepts `-data <dir>` and puts **both** persisted files
  there: `identity.hmdl` and `peers.json` (`main.go`, `loadOrCreateIdentity`
  and `peers.OpenStore(filepath.Join(*data, "peers.json"))`). So all persistent
  state is already parameterised on one directory.
- `defaultDataDir()` resolves `~/.heimdall` via `os.UserHomeDir()`, falling
  back to `.heimdall` in the working directory. This is the **only** place a
  host-specific path enters, and it is the main thing portable mode overrides.
- Identity at rest is already encrypted (PBKDF2-SHA-256, 600k iterations,
  AES-256-GCM, mode `0600`) and written atomically (`identity.go`: temp file +
  rename, `MkdirAll(..., 0o700)`).
- Session keys and the decrypted identity are **memory-only and zeroised on
  termination** per the threat model — nothing to clean off disk there.
- HMDL runs its **own** REPL (`/connect`, `/msg`, …). It is not a host shell, so
  it leaves no shell history, unlike a bash-based tool.
- No CGO, no third-party modules (`go.mod`), so the binary is fully static and
  relocatable.

What's missing for a genuine portable experience: self-location (don't depend on
`$HOME`/cwd), a way to guarantee no writes leak to the host temp dir, durable
flush semantics tuned for a stick that gets yanked, and launcher ergonomics +
documentation.

## 4. Layout on the stick

```
HMDL/                         <- portable root (anywhere on the stick)
├─ hmdl.exe                   <- Windows amd64 static binary
├─ hmdl-linux                 <- Linux amd64 static binary
├─ run.bat                    <- Windows launcher (double-click / cmd)
├─ run.sh                     <- Linux launcher (chmod +x)
├─ hmdl.portable              <- marker file that turns portable mode on
└─ data/                      <- all state, created on first run (0700)
   ├─ identity.hmdl           <- encrypted identity (0600)
   ├─ peers.json              <- trust store
   └─ tmp/                    <- scratch dir; TMPDIR is pinned here
```

The `data/` directory is the entire persistent footprint. Back up the stick =
back up `data/`. Wipe the stick = destroy the identity.

## 5. Turning portable mode on

Three ways, in precedence order, so it works from a double-click, a shell, or a
script:

1. **`-portable` flag.** Explicit and scriptable.
2. **`HMDL_PORTABLE=1` environment variable.** For launchers.
3. **Marker file autodetect.** If a file named `hmdl.portable` sits next to the
   executable, portable mode turns on automatically. This is what makes a
   double-click "just work" with no arguments.

When portable mode is on:

- The data directory becomes `<dir-of-executable>/data`, computed from
  `os.Executable()` (resolving symlinks), **not** from `$HOME` or the current
  working directory. An explicit `-data` still wins if given, so power users can
  still relocate it.
- `TMPDIR` / `TEMP` / `TMP` are repointed at `<data>/tmp` for the process, so
  any incidental temp file (there are none today, but this future-proofs it)
  lands on the stick, not `/tmp` or `C:\Users\...\AppData\Local\Temp`.
- A short banner prints where state lives and reminds the user to eject before
  pulling the stick.

### Precedence for the data directory

```
-data <dir>            (explicit; always wins)
  else HMDL portable   -> <exeDir>/data
  else                 -> ~/.heimdall   (unchanged legacy behaviour)
  else                 -> .heimdall     (unchanged fallback)
```

Non-portable behaviour is untouched, so this is purely additive.

## 6. Confining writes to the stick

Inventory of everything the process could write, and the portable rule for each:

| Write | Today | Portable rule |
|---|---|---|
| `identity.hmdl` | `<data>` | `<exeDir>/data` — on the stick |
| `peers.json` | `<data>` | `<exeDir>/data` — on the stick |
| Temp files | none, but host `TMPDIR` if ever used | `TMPDIR` pinned to `<data>/tmp` |
| Logs | none (stdout/stderr only) | keep it that way; no log files, ever |
| Shell history | none (own REPL) | keep it that way |
| Core dumps | possible on crash | `setrlimit(RLIMIT_CORE, 0)` on Unix (§7) |

The design rule is a single choke point: **all filesystem paths derive from one
`rootDir`**, computed once at startup. Add a tiny `internal/portable` package
that resolves `rootDir` and exposes `DataDir()` / `TempDir()`; `main.go` calls
it instead of `defaultDataDir()`. A grep-able invariant ("no `os.WriteFile` /
`os.Create` / `os.MkdirTemp` outside a path rooted at `portable.DataDir()`")
becomes a reviewable rule and a test.

## 7. Reducing host-side residue (best-effort, documented limits)

These are the measures that *are* within the application's or the launcher's
reach. Each is paired with what it does and does not achieve.

- **Run the binary from the stick.** The executable image itself is on removable
  media, so it is not copied into the host's program directories. Note: the host
  may still record execution metadata (Windows Prefetch, `Amcache`,
  `ShimCache`); these are host artefacts HMDL cannot remove.
- **Pin `TMPDIR` to the stick** (§6) so no scratch data lands in host temp.
- **Disable core dumps on Unix** via `setrlimit(RLIMIT_CORE, 0)` at startup, so
  a crash cannot spill decrypted memory into `/var/crash` or the cwd. Build-tag
  a no-op on Windows.
- **Best-effort anti-swap for secrets.** Optionally `mlock` (Unix) /
  `VirtualLock` (Windows) the pages holding the decrypted identity and session
  keys so the OS avoids paging them to disk. This is **advisory**: it can fail
  without privileges and does not cover hibernation. Document it as reducing,
  not eliminating, memory-on-disk exposure. Keep it behind a build tag so the
  core stays standard-library-only where possible (this needs `x/sys` or raw
  syscalls; if we refuse the dependency, ship it as a documented Linux-only
  syscall wrapper).
- **Durable, atomic writes.** Keep the existing temp-file + rename pattern and
  add an explicit `fsync` of the file and its parent directory before returning,
  so a stick pulled immediately after a `/verify` or a new-peer write is never
  left with a half-written `peers.json`. This is about **integrity on a stick
  that gets yanked**, which matters more for portable use than for an installed
  copy.
- **Eject guidance, not eject magic.** HMDL prints "flushed — safe to eject" after
  state-changing writes and reminds the user to use the OS "safely remove" path.
  A userspace binary cannot force the OS to drop its write-back cache for the
  volume; telling the user to eject is the honest, correct mechanism.

What is explicitly **out of reach** and must be stated in the docs: host USB
enumeration logs, filesystem timestamps on the stick, host swap/hibernation
files, antivirus logs, and anything a hostile host records. See §2.

## 8. Filesystem and media notes

- **exFAT** is the pragmatic default for a cross-platform stick (Windows +
  Linux read/write without extra drivers). It has **no journaling and no POSIX
  permissions**, so:
  - The `0600` / `0700` modes HMDL sets are honoured on Linux native
    filesystems but are **cosmetic on exFAT/FAT**. Confidentiality of the
    identity therefore rests entirely on its passphrase encryption, not on file
    permissions — which is already true in HMDL's design, but must be called out
    for portable users.
  - The atomic-rename guarantee is weaker on FAT-family filesystems; the
    `fsync`-parent step in §7 is best-effort there. Document that a clean eject
    is required.
- **Wear:** `peers.json` is small and written rarely (on new/verified peers), so
  flash wear is a non-issue. No busy log or database file is introduced.
- For a user who controls both machines and wants real at-rest permissions and
  journaling, note that an ext4 or LUKS-encrypted stick works too; portable mode
  doesn't require exFAT, it just defaults to being friendly to it.

## 9. Launchers

Thin, transparent, no magic:

- **`run.sh`** (Linux): `#!/bin/sh` that `cd`s to its own directory, sets
  `HMDL_PORTABLE=1`, and `exec`s `./hmdl-linux "$@"`. No autorun; the user runs
  it.
- **`run.bat`** (Windows): sets `HMDL_PORTABLE=1` and launches `hmdl.exe` in the
  current console. **No `autorun.inf`** — modern Windows ignores USB autorun for
  security reasons, and shipping one would look like malware behaviour. Launch
  is always an explicit user action.

The marker-file autodetect (§5) means even running the bare binary without a
launcher lands in portable mode, so the launchers are ergonomics, not a
requirement.

## 10. Threat-model addendum

Add a "Portable operation" section to `docs/threat-model.md` capturing:

- **New assets on removable media:** the encrypted identity and trust store now
  travel physically. Loss/theft of the stick exposes them to offline attack;
  security reduces to the identity passphrase strength (unchanged crypto:
  PBKDF2 600k + AES-256-GCM). Recommend a strong passphrase explicitly for
  portable use, and consider raising the KDF cost or offering a `-kdf-iters`
  knob for portable identities.
- **Host trust boundary:** running on an untrusted host is out of scope
  (keyloggers, RAM scraping, swap). Portable mode narrows HMDL's *own* footprint
  but does not extend HMDL's trust to the host.
- **Residual host artefacts:** enumerate the §2/§7 items so users know exactly
  what "near zero trace" does and does not mean.

## 11. Implementation plan (small, additive, reviewable)

1. **`internal/portable` package**
   - `Root() (string, error)` — resolve `os.Executable()`, `EvalSymlinks`,
     return its directory.
   - `Enabled(flag bool) bool` — flag OR `HMDL_PORTABLE` OR marker file.
   - `DataDir()` / `TempDir()` — derived paths; `MkdirAll(0700)`.
2. **`main.go`**
   - Add `-portable` bool flag.
   - Compute `dataDir`: explicit `-data` wins; else portable → `Root()/data`;
     else `defaultDataDir()` (unchanged).
   - When portable, `os.Setenv` the temp vars to `TempDir()` and print the
     banner.
3. **Durable writes**
   - In `internal/identity` and `internal/peers`, add an `fsync` of file +
     parent dir to the existing temp-file+rename save paths.
4. **Hardening (build-tagged, optional)**
   - `rlimit_unix.go` (`//go:build unix`): `setrlimit(RLIMIT_CORE, 0)`.
   - `rlimit_other.go`: no-op.
   - Optional `mlock`/`VirtualLock` wrappers, clearly documented and behind a
     flag (`-lock-memory`), defaulting off so the core stays dependency-free.
5. **Launchers & assets:** `run.sh`, `run.bat`, `hmdl.portable` marker, a
   `dist/` layout, and a `make portable` / build script that cross-compiles
   `GOOS=windows,linux GOARCH=amd64` static binaries into the stick layout.
6. **Docs:** this file, plus a "Portable / USB" section in `docs/deployment.md`
   and the addendum in `docs/threat-model.md`.

Keep the diff small and the invariants testable; nothing here touches
`internal/proto`, `internal/crypto`, or the wire format.

## 12. Testing

- **Unit:** portable-detection precedence table; `DataDir()`/`TempDir()`
  resolution with a fake `os.Executable`; `-data` override still wins.
- **Write-confinement test:** run the binary under a temp "stick" dir with
  `$HOME` pointed at a canary dir and `TMPDIR` at another canary; assert that
  after create-identity + add-peer, **only** files under the stick changed and
  the canaries are untouched. This is the core guarantee, made into CI.
- **Yank-safety:** simulate interrupted writes (kill after temp-write, before
  rename) and assert `peers.json` / `identity.hmdl` are never left corrupt.
- **Cross-platform smoke:** build both targets; run each from a mounted exFAT
  image and confirm identity round-trips.
- **Permissions note test:** assert the code sets `0600/0700` and document that
  the mode is advisory on FAT-family filesystems.

## 13. Milestones

1. `internal/portable` + `main.go` wiring + precedence tests. *(portable data
   dir works; nothing writes to `$HOME`.)*
2. Write-confinement CI test + `fsync` durability. *(the core guarantee is
   enforced and yank-safe.)*
3. Launchers, cross-compile build script, stick layout. *(double-click to run.)*
4. Core-dump/`mlock` hardening behind build tags + flag. *(reduced memory
   residue, honestly scoped.)*
5. Docs: deployment section + threat-model addendum. *(users know exactly what
   "near zero trace" means.)*
