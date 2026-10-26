# Threat model

evidencelocker is a **defensive** tool. It collects triage data from hosts
that the operator is authorised to examine, and it makes the resulting
evidence tamper-evident. It contains no offensive capability: no exploitation,
no credential access (it never reads `/etc/shadow`, keychains or private keys
on the target), no stealth, and no network activity. All demos and tests run
against synthetic fixture trees committed in `testdata/hosts` (symlinks are listed in
`testdata/hosts/symlinks.txt` and created at test time). In those trees
the "malicious" binaries are inert shell scripts and the attacker addresses
come from the RFC 5737 documentation ranges.

## Assets

1. **Evidence content.** What was observed on the host at collection time.
2. **Evidence integrity.** The guarantee that the bundle analysed later is
   the bundle that was sealed.
3. **Custody record.** Who held the evidence and what they did with it.
4. **Signing keys.** The collector's key and each custodian's key.

## Adversaries and what happens

| # | Adversary | Capability | Outcome |
|---|---|---|---|
| A1 | Storage or transport corruption | random bit flips, truncation | Detected. zstd CRC, tar checksums, entry hashes and the canonical layout locate the damage (`make eval`: 100% of single-byte flips detected). |
| A2 | Tamperer without keys (insider, cloud storage admin) | edit, delete, insert or reorder bundle entries; edit custody lines | Detected and located. Content edits fail the entry hash. Manifest edits fail the signed digest. Head edits fail the signature. Header and padding edits fail the layout check. Custody edits fail the hash, signature or chain. |
| A3 | Tamperer who re-seals with their own key | build a fully consistent bundle and log signed by a key they control | Detected **only if** the verifier pins trusted keys (`--trusted-key` → `UNTRUSTED_KEY`, `SEALER_UNTRUSTED`). Without pinning, the report notes the signer is unpinned. |
| A4 | Former custodian with a valid key | append or alter entries after handing over custody | Appends are rejected or reported as `NOT_CUSTODIAN`. Rewriting history requires the current holder's key or the original keys, see A5. |
| A5 | Holder of the sealing key (or all keys) | re-seal altered evidence; rewrite the custody chain | **Not prevented.** Detected only through out-of-band anchors: a head hash recorded elsewhere (`--expect-head`), or the bundle digest written in a case file. Key custody is a procedural control. |
| A6 | Custodian who deletes the newest log entries | truncate the log | Detected only with `--expect-head` (see CUSTODY.md, limit 1). |
| A7 | Attacker controlling the **target host** at collection time | rootkits, LD_PRELOAD in the collector process, fake `/proc`, timestomping, files swapped mid-read | **Out of scope for integrity.** The bundle faithfully records what a userland tool was shown. Mitigations: collect from a mounted image with `--root`; `fsroot` never follows symlinks out of the root; `OpenRegular` detects files swapped between check and read; partial or failed collectors are recorded rather than hidden. |
| A8 | Hostile content in the evidence | malicious plist/XML, huge files, symlink loops, odd filenames | Parsers are bounded (plist nesting depth 64, per-file and total size caps, 40 symlink hops). They are fuzzed (`make fuzz`), and paths are validated before they go into the archive. Hostile file names are captured, never executed. |
| A9 | Hostile **bundle** handed to an analyst | decompression bomb, path traversal on extract | The verifier streams, buffers only capped metadata, and bounds the zstd window at 64 MiB. `extract` writes only to an explicit output file (`O_EXCL`) or to stdout; archive paths are never joined to a directory. |

## Trust assumptions

* The examiner's workstation and the evidencelocker binary are trustworthy.
* Private keys are kept secret. `LoadPrivate` refuses key files readable by
  group or others.
* Verifiers obtain trusted public keys through a channel that the evidence's
  adversary cannot influence.
* SHA-256 and ed25519 remain secure.

## Non-goals

* Confidentiality. Bundles are not encrypted. Wrap them with age/GPG or store
  them in encrypted storage if they contain sensitive data.
* Detection guarantees. The diff and its heuristic tags are triage aids that
  produce false positives and miss obfuscated tradecraft. They do not replace
  analysis.
* Remote or fleet collection, agents, or any network service.
