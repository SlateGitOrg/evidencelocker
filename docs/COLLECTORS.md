# Collectors and the plugin interface

## Built-in collectors

All collectors read through `fsroot.Root`, so `--root DIR` makes DIR the
host's `/`. A collector returns `ErrNotApplicable` (status `skipped`) when its
source does not exist under the root.

### `processes` (Linux procfs)
* Reads `/proc/<pid>/status` (Name, State, PPid, real Uid), `cmdline`, the
  `exe` and `cwd` links, and `stat` (start time, parsed after the last `)` so
  comm values with spaces or parentheses are safe).
* Key: `exe + NUL + cmdline` (`[name]` for kernel threads). PIDs are excluded
  because they churn. Digest: exe, deleted flag, argv, uid.
* Processes that exit mid-scan are skipped silently. Other unreadable entries
  become warnings and the `partial` status.

### `sockets` (Linux procfs)
* Parses `/proc/net/{tcp,tcp6,udp,udp6}`. Addresses are little-endian 32-bit
  words and ports are big-endian hex. IPv4-mapped IPv6 addresses are unmapped.
* Records TCP `LISTEN` and unconnected UDP (state `07`). Set
  `include_established: true` to also record established TCP connections.
* Owners: socket inode ↔ `/proc/<pid>/fd/*` → `socket:[inode]`. A permission
  denial on other users' fd tables is counted and reported (run as root for
  full attribution).
* Key: `proto/addr:port`. Digest: key, owner exe, uid.

### `users` (glibc utmp)
* `/run/utmp` or `/var/run/utmp`, 384-byte records (x86_64 and aarch64
  glibc layout). Reports `USER_PROCESS` entries.
* Key: `user@line`. Digest: user, line, host, address.

### `accounts`
* `/etc/passwd` plus membership of `root, sudo, wheel, admin, adm, docker,
  lxd` from `/etc/group`. Both files are captured raw.
* **Never reads `/etc/shadow`.**
* Key: account name. Digest: uid, gid, home, shell, privileged groups.

### `persistence`

| Mechanism | Locations | Granularity |
|---|---|---|
| `cron` | `/etc/crontab`, `/etc/cron.d/*` (with user column); `/var/spool/cron/crontabs/*`, `/var/spool/cron/*`, `/usr/lib/cron/tabs/*`, `/var/at/tabs/*` (user = file name) | per job line |
| `cron-script` | `/etc/cron.{hourly,daily,weekly,monthly}/*` | per file |
| `systemd` | `.service/.timer/.socket/.path` under `/etc/systemd/system`, `/run/systemd/system`, `/usr/lib/systemd/system`, `/lib/systemd/system`, `/usr/local/lib/systemd/system`, user dirs; "enabled" if linked from a `*.wants`/`*.requires` dir | per unit file |
| `launchd` | `/Library/Launch{Agents,Daemons}`, `/System/Library/Launch{Agents,Daemons}`, `/Users/*/Library/LaunchAgents` (XML plists parsed; binary plists hashed and noted) | per plist |
| `shell-rc` | `/etc/profile`, `/etc/profile.d/*`, bash/zsh system rc files, `/etc/environment`, per-user `.bashrc .bash_profile .bash_login .bash_logout .profile .zshrc .zprofile .zshenv .zlogin` in `/root`, `/home/*`, `/Users/*`, plus `extra_shell_rc` globs | per file |
| `rc-local` | `/etc/rc.local` | per file |
| `ld-preload` | `/etc/ld.so.preload` | per library |
| `ssh-authorized-key` | `~/.ssh/authorized_keys{,2}` for the homes above (fingerprint, options, forced `command=`) | per key |

* Line-level entries are keyed by their normalised content, so editing one
  cron line never makes every following line look "changed". File-level
  entries change digest with the file hash.
* Every parsed file is captured raw (up to `max_file_size`, default 1 MiB;
  truncation marks the run `partial`).
* **Heuristic tags** (`heuristics.go`): `download-piped-to-shell`,
  `network-fetch`, `dev-tcp-redirect`, `base64-decode`, `writable-dir-exec`,
  `hidden-path`, `inline-interpreter`, `preload-injection`, `prompt-hook`,
  `sudo-alias`, `eval`. They are hints, deliberately simple and explainable.

### `filehash`
* Walks `dirs`. Directories that resolve to the same place (merged-`/usr`
  links such as `/bin -> usr/bin`) are walked once. Symlinks are recorded,
  never followed.
* Regular files are hashed with SHA-256 using `workers` goroutines. Output
  order is deterministic (`TestDeterministicAcrossWorkers`). Files larger than
  `max_file_size` are recorded with `skipped`. `max_files` bounds the walk.
* Files under `capture_dirs` (default `/tmp`, `/var/tmp`, `/dev/shm`) up to
  `capture_max_size` are embedded raw, within a `capture_total` budget.
* Key: path. Digest: type, mode (including setuid/setgid/sticky), sha256,
  link target, size. mtime is excluded because it is forgeable and churns.

Options and defaults are listed in
[configs/collect.example.json](../configs/collect.example.json).

## Writing a collector

```go
type Collector interface {
    Name() string                 // [a-z0-9-]+, unique
    Version() string
    Description() string
    Collect(ctx context.Context, env *collector.Env) (*collector.Output, error)
}
```

1. **Read only through `env.Root`.** Use `ReadFile`, `Glob`, `Walk`,
   `Readlink`, `OpenRegular`. Never call `os.*` with host paths, or `--root`
   and the fixtures stop working.
2. **Emit `Record`s** with a stable `Key()` and a `Digest()` over the
   attributes whose change matters. `collector.DigestOf(v)` hashes any
   JSON-encodable value.
3. **Put raw evidence in `Output.Captures`**. It lands under
   `files/<path>`.
4. **Degrade rather than fail.** Turn per-item problems into
   `out.Warnf(...)` and `out.Partial = true`. Return `ErrNotApplicable` when
   the source is absent. Return an error only when the collector's whole
   source is unreadable. Honour `ctx`, which carries the per-collector timeout.
   A collector that ignores `ctx` past its deadline is abandoned and its
   output is discarded. Read through `env.Root`, which refuses FIFOs and
   devices rather than blocking on them.
5. **Optional:** implement `collector.Configurable` (`Configure(json.RawMessage)
   error`, decoding with `collector.DecodeOptions` to reject unknown fields).
6. **Optional:** add a `baseline.Rule` to rank your collector's changes.
   Without one, the generic rule reports additions and modifications at
   `low` and removals at `info`.

Register the collector next to the built-ins and reuse the stock CLI:

```go
reg := builtin.Registry()
reg.MustRegister(HostsFile{})
baseline.Rules["hosts-file"] = hostsRule
os.Exit((&cli.App{Registry: reg, Clock: collector.SystemClock{}, Stdout: os.Stdout, Stderr: os.Stderr}).
    Run(context.Background(), os.Args[1:]))
```

[examples/customcollector](../examples/customcollector/main.go) is a complete,
tested example. It is an `/etc/hosts` override collector whose additions the
diff reports as `medium`.
