# Design decisions

Key design decisions in evidencelocker, each with the reasoning and what it would cost if it turned out wrong.
Format: `- <what> — <why> — <cost if wrong>`.

## Format and cryptography

- the bundle is a canonical tar stream in a single zstd frame, with the manifest, head and signature as the final three members — tar.zst is a widely supported container; putting metadata last lets sealing stream once without a second pass — a reader that needs the manifest first must scan the whole file (acceptable: verification reads everything anyway).
- the verifier enforces a byte-exact canonical tar layout by regenerating it, instead of trusting `archive/tar`'s parse — tar readers silently ignore padding and some header bytes, so "verify the content hashes" alone would leave bytes an attacker could change undetected; regenerating also localises any difference to a named region — bundles written by other tar implementations are rejected (by design: one producer, one format).
- also require the compressed bytes to be canonical (re-encode with the recorded encoder and compare) when the verifier's encoder matches; otherwise skip and say so — some zstd header edits (e.g. window descriptor) decode to identical content and pass the frame checksum — determinism depends on the pinned `klauspost/compress` version; a different version only loses this one extra check, never a false failure.
- RFC 9162 Merkle tree over manifest entries, with path and size bound into the leaf — enables O(log n) selective-disclosure proofs (`prove`) at the cost of one 32-byte root; binding path and size stops proofs being replayed for renamed or truncated files — slightly more complex than a flat hash list for no benefit if nobody uses proofs.
- sign a small `head.json` (tree size, root, manifest digest, key id) rather than the manifest itself, in the style of the Certificate Transparency STH — proofs can be checked without shipping the manifest — two layers to explain instead of one.
- domain-separated signatures (`evidencelocker/head-signature/v1\0`, `evidencelocker/custody-signature/v1\0`) — one key signs both heads and custody entries, so a signature must never be valid in the other context — none.
- ed25519 with standard PKCS#8/PKIX PEM files; private key files with group/other permission bits are refused — ed25519 is small, fast and deterministic; PEM interoperates with OpenSSL; refusing loose permissions prevents silently weak custody — users on shared or odd filesystems (e.g. FAT) must chmod or copy keys.
- `head.sig` and `head.json` must equal their canonical re-encoding, and base64 must be canonical — `encoding/hex` and `base64` accept multiple encodings of the same bytes (case, padding bits), which would let a flipped byte go unnoticed — none for our own output; hand-edited files are rejected.
- tar header mtime is fixed at the epoch and mode at 0644; real times live in the manifest and record files — makes archives reproducible and every header byte predictable — `tar -tv` shows 1970 dates, which may confuse a reader.

## Collection

- every collector reads through `pkg/fsroot` with chroot-style symlink resolution plus `os.Root` — required for configurable roots and fixtures, and it stops hostile or fixture symlinks (`/etc/passwd -> /etc/passwd`) from reading the examiner's own machine — slightly slower than direct `os` calls (one Lstat per path component).
- collectors degrade rather than fail (warnings plus `partial` status; `skipped` when the source is absent) and the runner isolates panics and timeouts — triage on a broken host must salvage everything it can — a collector bug can hide behind `partial` unless someone reads the warnings (they are counted in the manifest and printed by `collect`).
- `fsroot` refuses non-regular files before opening them (Lstat type check, `O_NONBLOCK` open, post-open Stat), and reports them as `ErrNotRegular` naming the file type; `persistence` turns that into a warning plus `partial`, while `accounts`/`users` fail that collector — opening a FIFO for reading blocks until a writer appears, so any unprivileged user could stall a root-run triage with `mkfifo ~/.bashrc`; a special file where a config file should be is itself worth an analyst's look, so it is surfaced rather than silently skipped — the FIFO or device is not recorded as a typed record, only as a warning and in the collector error.
- the per-collector timeout is enforced by the runner, not left to collectors: it selects on the result versus `ctx.Done()`, waits `AbandonGrace` (default 2s) for a cooperative return, then abandons the collector (status `error`, a warning, partial output discarded because the goroutine may still write to it) — a collector stuck in a call that ignores `ctx` must not hang the run, which is what "the runner isolates timeouts" promised — an abandoned goroutine leaks until process exit and stops counting against `Parallelism`; for a one-shot CLI that is acceptable, a long-running embedder should treat repeated abandonment as a bug in that collector.
- never read `/etc/shadow`, keychains or private keys; only public key material from `authorized_keys` — credential material is out of scope for triage and would make the tool dual-use — cannot spot password-hash tampering (an analyst can image shadow separately).
- procfs, sockets and utmp are Linux-only, parsed from files rather than syscalls or `ps`/`lsof` — file parsing is what makes `--root` and fixtures work, and avoids trusting binaries on a suspect host — no live process data on macOS (the collectors report `skipped`).
- process records are keyed by executable plus command line, not PID — PIDs churn between collections, so PID keys would make every diff noisy — two genuinely different processes with identical exe and argv collapse into one key (they are kept as a multiset and compared by digests).
- `filehash` digests exclude mtime; it captures raw only small files in `/tmp`-like staging directories (4 MiB per file, 64 MiB total by default) — mtime is forgeable and churns on updates; embedding every system binary would bloat bundles — a replaced binary is identified by hash only (re-collect with a custom config to capture it).
- persistence cron lines, SSH keys and preload entries are keyed by normalised content; units, plists and rc files are keyed by file — inserting a cron line must not mark all later lines changed, while rc files are free-form scripts best diffed as files (with line diffs from the captures) — whitespace edits inside a cron command show as "modified", and a semantically identical rewrite of a line shows as removed plus added.
- `--root` is recorded in the manifest as typed, not made absolute — avoids leaking the examiner workstation's directory layout into evidence — a relative path is less informative later (record the mount point in `--note`).

## Custody

- custody is enforced, not just logged; a transfer names the recipient's public key, and only that key may sign next — a log anyone can append to proves little — no delegation or multi-holder custody; a team must share a key or transfer explicitly.
- timestamps are fixed-width UTC strings (`...05.542176000Z`) compared lexicographically, and regressions are findings — RFC 3339 with variable fractional digits does not sort as strings — none.
- tail truncation is detectable only with an out-of-band head (`--expect-head`); no transparency log or timestamp authority is built in — those need network services, which the offline-first design excludes — users who never record heads cannot detect truncation (documented prominently in docs/CUSTODY.md).
- appends hold `flock` and re-verify the whole log first — prevents forked chains from concurrent appends, and avoids extending a log that has already been tampered with — Unix-only; O(n) per append (fine for custody logs with tens of entries).

## Diff

- generic key/digest diff for every collector, with per-collector severity rules in an extensible map and a generic fallback — plugins diff with no code changes, and a rule failure degrades to a generic finding plus a note instead of dropping the change — global mutable `baseline.Rules` must be set before `Compare` (documented).
- severities are opinionated (new UID 0 → critical; new persistence → high, critical with strong heuristic tags; executable in `/tmp` → high; new process → low unless suspicious) — triage needs a ranking more than precision — false positives (`curl` in a legitimate cron job) and misses (obfuscated commands); the severities were set using the same fixture they are tested on, which the README discloses.
- `diff` refuses bundles that fail verification — never analyse evidence of unknown integrity — a damaged-but-useful bundle cannot be diffed with the CLI (it can still be extracted with library code).
- default `--fail-on medium` exit code — scripting-friendly ("anything worth a look") — CI-style users may want `high`.

## Process and tooling

- the CLI lives in `pkg/cli` (not `internal/`) as an embeddable `App` taking a registry — a plugin author can ship a binary with extra collectors without forking — CLI flags become part of the public surface.
- fixtures are generated by `internal/fixtures` and committed; `TestFixturesUpToDate` checks they match — reviewers can browse them and the demo needs no generation step — setuid bits cannot be stored in git, so setuid handling is tested in temp dirs rather than fixtures.
- the only third-party dependency is `klauspost/compress` (zstd); no CLI framework — small, auditable dependency surface for a forensic tool — hand-rolled flag handling (interspersed flags are supported by a small helper).
- no `.env.example`; configuration is a JSON file (`configs/collect.example.json`) and flags — the tool reads no environment variables — none.
- coverage is measured per package over `./pkg/... ./internal/...` (not `-coverpkg` across packages) — the conservative number; the gate is 80% — some code exercised only cross-package (the CLI) counts once.
