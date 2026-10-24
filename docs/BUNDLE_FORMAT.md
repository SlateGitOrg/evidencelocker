# Bundle format v1

A bundle is a single file, conventionally named `*.tar.zst`. It is a
**zstd frame** containing a **POSIX tar stream** with a fixed (canonical)
layout. This document describes what the verifier enforces. The code in
`pkg/bundle` is the reference.

## Container

* zstd, produced by `github.com/klauspost/compress/zstd` v1.20.1 with default
  level, encoder concurrency 1 and frame content checksum (CRC) enabled. The
  exact encoder identity is recorded in the manifest as `compression.encoder`.
  A verifier built with the same encoder re-compresses the decompressed stream
  and requires the result to equal the file byte for byte
  (`CONTAINER_NONCANONICAL` otherwise). Other verifiers skip this check and
  say so in the report notes.
* The decompressed stream must end exactly after the tar end-of-archive marker
  (two 512-byte zero blocks). Trailing data is `LAYOUT_NONCANONICAL`.

## Tar layout

Members appear in this order. Every member is a regular file:

```
<payload members, strictly ascending byte-wise by path>
manifest.json
head.json
head.sig
```

Every member header is exactly what Go's `archive/tar` writer emits for:

| Field | Value |
|---|---|
| Typeflag | `0` (regular file) |
| Name | member path (PAX extended header when USTAR cannot hold it) |
| Size | content length |
| Mode | `0644` |
| Uid/Gid | `0`, names empty |
| ModTime | Unix epoch 0 (the real collection time is in the manifest) |

The verifier regenerates this header for each member, along with the padding
to the next 512-byte boundary and the trailer, and compares the result byte
for byte with the archive.

### Payload paths

Paths must be valid UTF-8, relative, `path.Clean`-clean, contain no NUL and
no `.`/`..` components, be at most 4096 bytes, and not be one of the three
reserved names. Built-in producers use:

* `collectors/<name>.json`: one record file per collector run.
* `files/<host-absolute path>`: raw captures, for example
  `files/etc/crontab`.

## manifest.json

Indented JSON (`format: "evidencelocker/manifest/v1"`):

```json
{
 "format": "evidencelocker/manifest/v1",
 "case_id": "IR-2026-042",
 "examiner": "responder",
 "created_at": "2026-10-24T03:27:46.53Z",
 "host": {"hostname": "web01", "os": "Ubuntu 24.04.1 LTS", "root": "/", "live": true},
 "tool": {"name": "evidencelocker", "version": "0.1.0"},
 "compression": {"codec": "zstd", "encoder": "github.com/klauspost/compress/zstd@v1.20.1;level=default;concurrency=1;crc=1"},
 "collectors": [{"name": "persistence", "version": "1.0.0", "status": "ok", "started_at": "...", "duration_ms": 3,
                 "records": 19, "captures": 17, "warnings": 0}],
 "merkle": {"leaf_encoding": "evidencelocker/leaf/v1", "tree_size": 27, "root": "<hex>"},
 "entries": [{"path": "collectors/accounts.json", "size": 2817, "sha256": "<hex>"}]
}
```

`entries[i]` is Merkle leaf *i*. Entries are strictly sorted by path and must
correspond one-to-one with the payload members.

### Leaf encoding (`evidencelocker/leaf/v1`)

```
"evidencelocker/leaf/v1" 0x00 || u32be(len(path)) || path || u64be(size) || sha256(content)[32]
```

The leaf hash is SHA-256(0x00 ‖ leaf), the node hash is
SHA-256(0x01 ‖ left ‖ right), and the tree shape follows RFC 9162 §2.1.1.
Binding both the path and the size into the leaf means a proof cannot be
replayed for a renamed or truncated file.

## head.json (signed tree head)

Compact JSON, exactly one canonical encoding, with a trailing newline:

```json
{"format":"evidencelocker/head/v1","case_id":"IR-2026-042","created_at":"2026-10-24T03:27:46.53Z","tree_size":27,"merkle_root":"<hex>","manifest_sha256":"<hex>","key_id":"ed25519:<32 hex>"}
```

`key_id` = `"ed25519:"` + the first 16 bytes (as hex) of SHA-256 of the raw
32-byte public key.

## head.sig

Compact canonical JSON:

```json
{"format":"evidencelocker/sig/v1","alg":"ed25519","key_id":"ed25519:...","public_key":"<base64 32 bytes>","signature":"<base64 64 bytes>"}
```

The signature is ed25519 over `"evidencelocker/head-signature/v1" 0x00 ‖
head.json bytes`. The public key embedded here proves only integrity. Origin
requires the verifier to pin trusted keys (`--trusted-key`). Without pinning,
the report notes this.

## Record files (`collectors/<name>.json`)

```json
{
 "format": "evidencelocker/records/v1",
 "collector": "sockets", "version": "1.0.0", "status": "ok", "warnings": [],
 "records": [{"key": "tcp/0.0.0.0:4444", "digest": "<hex>", "data": {"proto": "tcp", "...": "..."}}]
}
```

Records are sorted by (key, digest, data). `data` is the collector's own typed
record. Diff rules decode it. Collectors without a rule are diffed on `key`
and `digest` alone.

## Inclusion proof (`evidencelocker/proof/v1`)

```json
{"format": "evidencelocker/proof/v1", "head": "<base64 of exact head.json bytes>",
 "signature": {"...": "head.sig contents"}, "entry": {"path": "...", "size": 88, "sha256": "..."},
 "index": 8, "audit_path": ["<hex>", "..."]}
```

To verify a proof: check the signature over `head`, take the root and tree
size from the head, recompute the leaf from `entry`, run RFC 9162 inclusion
verification, and optionally compare supplied content against `entry`.

## Versioning

Every JSON object carries a `format` string. A v1 verifier rejects any other
value. Any future change to the layout, leaf encoding or signed-message domain
will change the format strings rather than reinterpret v1 bundles.
