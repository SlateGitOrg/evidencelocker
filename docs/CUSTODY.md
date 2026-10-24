# Chain-of-custody model and its limits

Chain of custody answers three questions: who has held the evidence since it
was collected, what they did with it, and whether it is still the same
evidence. evidencelocker records the answers in a **signed, hash-chained log**
bound to the bundle. This document states exactly what the log proves and what
it cannot.

## The log

`<bundle>.custody.jsonl`, one canonical JSON object per line:

| Field | Meaning |
|---|---|
| `seq` | 0, 1, 2, … with no gaps |
| `prev` | `hash` of the previous entry (`000…0` for seq 0) |
| `time` | signer's clock, fixed-width RFC 3339 UTC (`2026-10-24T03:27:46.542176000Z`) |
| `action` | `seal` (seq 0 only), `transfer`, `access`, `verify`, `note` |
| `case_id`, `bundle_sha256`, `merkle_root` | binding to one specific bundle file; identical in every entry |
| `actor`, `actor_key` | custodian's name and ed25519 public key |
| `recipient`, `recipient_key` | transfers only: who receives custody |
| `note` | free text |
| `sig` | ed25519 by `actor_key` over `"evidencelocker/custody-signature/v1\0" ‖ entry without sig/hash` |
| `hash` | SHA-256 of the entry without `hash` (covers `sig`) |

### Custody rules

1. `collect` writes the **seal** entry, signed by the key that signed the
   bundle head. The seal records the SHA-256 of the whole compressed file and
   the Merkle root.
2. Each later entry must be signed by the **current custodian**. That is
   the sealer until the first transfer, then whoever was named in the most
   recent `transfer` by `recipient_key`.
3. `transfer` hands custody on. After it, the previous custodian's key can no
   longer append. `custody append` refuses, and a hand-crafted entry is
   reported as `NOT_CUSTODIAN` on its exact line.
4. Timestamps must not go backwards, and the bundle binding must not change.
5. `custody append` verifies the entire log first, refuses to extend a broken
   log, and holds an exclusive `flock` while appending.

### What verification reports

Each failure is reported with the 1-based line and seq it occurs on:

| Code | Cause |
|---|---|
| `ENTRY_UNPARSABLE` | not JSON, unknown fields, or not byte-identical to its canonical encoding |
| `HASH_MISMATCH` | content of the entry was edited |
| `SIGNATURE_INVALID` | signature does not verify for `actor_key` |
| `CHAIN_BROKEN` / `SEQUENCE_INVALID` | an entry was removed, inserted, reordered or replayed |
| `NOT_CUSTODIAN` | signed by someone who did not hold custody at that point |
| `TIME_REGRESSION` | clock went backwards between entries |
| `BUNDLE_BINDING` | binding differs between entries, or from the bundle being verified |
| `SEALER_UNTRUSTED` | seal entry not signed by a pinned key (`--trusted-key`) |
| `HEAD_MISMATCH` | an out-of-band head hash (`--expect-head`) is absent: the log was truncated or rewritten |
| `FIELD_INVALID` | malformed action, actor, time or recipient |

`TestFlipEveryLogByte` flips every byte of a 4-entry log with three masks and
requires a finding on the line containing the flipped byte.

## What the log proves

* **Integrity of the record.** An attacker without the private keys cannot
  edit, delete, insert or reorder entries that are already in the log without
  detection, and the verifier locates the change. The one exception is
  removing the newest entries; see limit 1. An attacker holding the keys can
  rewrite the whole chain consistently. That rewrite is caught only by a
  head hash recorded out of band after the original entry was written
  (limit 1).
* **Continuity of custody.** Each recorded action was signed by the key that
  held custody at that point. Custody moved only through transfers signed by
  the previous holder.
* **Binding to the evidence.** The bundle being verified is byte-identical to
  the one that was sealed. Its Merkle root is the one the custodians attested to.

## What the log does NOT prove (limits)

1. **Truncation of the newest entries is invisible without an anchor.**
   Removing the last *k* lines leaves a perfectly valid shorter log. The
   defence is to record the head hash somewhere the custodian cannot rewrite:
   the case-management system, an email to counsel, a ticket, or a printed
   evidence label. Then pass it to `--expect-head`. A transparency log or
   RFC 3161 timestamping service would automate this. Neither is implemented.
2. **Time is self-asserted.** `time` is whatever the signer's clock said.
   Monotonicity is enforced, so entries cannot go backwards, but nothing
   proves wall-clock accuracy. A trusted timestamp authority is on the roadmap.
3. **Keys are not people.** `actor` is a label chosen by the signer. The
   signature proves possession of `actor_key`, nothing more. Binding keys to
   identities requires an external PKI or key ceremony, for example keys
   issued on hardware tokens and registered in the case file.
4. **A custodian holding the current key can write anything going forward.**
   They can append false notes or transfer custody to a key they also control.
   The log makes such actions attributable and permanent, but it cannot
   prevent them.
5. **Collusion and key theft.** Whoever has a key can act as that custodian.
   There is no revocation list. A compromised key must be dealt with
   procedurally: record a note, re-seal, re-collect.
6. **The log is about the bundle, not the host.** Custody starts at sealing.
   It says nothing about whether the collector saw the truth on a
   compromised host (see [THREAT_MODEL.md](THREAT_MODEL.md)).
7. **Concurrency is local.** `flock` serialises appenders on one machine and
   one filesystem. Two copies of a log edited on different machines will fork.
   The fork is detectable, because the two heads differ, but not mergeable.

## Recommended practice

* Generate the collector key on the responder's workstation, never on the
  suspect host. Use `--root` against a mounted image when possible.
* Distribute `.pub` files to everyone who will verify. Always verify with
  `--trusted-key`.
* After every append, copy the new `head` hash into an external, timestamped
  system.
* Transfer custody explicitly. Do not share private keys between people.
