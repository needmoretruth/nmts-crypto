# NMTS Recovery Manifest v2 (NRM-2)

> **Status: LIVE AND STILL EVOLVING.** ⛔ The freeze this block used to announce — "the format
> freezes at the first mainnet mirror write" — did not happen. NMTS moved to mainnet on 2026-08-02
> and the format has moved twice since: NRM-3 (2026-08-17) and NRM-4 (2026-08-18), both recorded
> in §6.
> What actually governs a change is §6's own test, and it is stricter than a date: a field may be
> added only with a journalled decision, and the version number moves only when **the absence of
> the new form would change the meaning of something else**. A bump is a wall in front of every
> reader already shipped, never a courtesy. Nothing is ever renamed or removed.
> Decided 2026-07-08; the v2 bump followed on 2026-07-29. Companion section:
> **[`CRYPTO-FORMAT-NCF3.md`](CRYPTO-FORMAT-NCF3.md) §3** (the envelope this document's §1 uses).
>
> ⚠ **`v` is 2 as of 2026-07-29.** Every part now carries `part_index` and §2.1 states what a reader
> MUST do with it. NRM-1 lists stay readable — see §6 for what changed, and for exactly what an NRM-1
> list can and cannot promise a reader that an NRM-2 list can.
>
> ⚠ **The newest form is NRM-4 (2026-08-18): `padded_len`, a part sealed larger than the bytes it
> holds.** ⛔ A document still claims the version its CONTENTS need — `minimum_version` — so an
> ordinary list is still a v2 document and opens in every tool ever shipped. §2.2 is the field and
> §6 is what changed.
>
> ⚠ **The JSON schema in §2 was unchanged by NCF-3; the ENCRYPTION in §1 was not.** NCF-3 replaced NCF-1
> and NCF-2 outright on 2026-07-29 and renamed this envelope's AAD, so §1 and the sealed-hash note in
> §2 were corrected on that date. Anything below still saying "frozen NCF-1" would be describing a
> document that no longer binds anyone.

## 0. Purpose & durability model

The recovery manifest is the per-account, encrypted index that makes every file recoverable with **zero
NMTS infrastructure**: account code (→ `dataKey`) + the manifest + any public aggregator + the standalone
recovery tool = full recovery. It is layer 2 of the 3-layer durability story (spec §4.4): (1) NMTS DB,
(2) this manifest, (3) the human-readable Recovery Guide.

**Two places a manifest can live, and they are different promises:**

| Where | Costs | Survives NMTS disappearing | Survives the user losing things |
|---|---|---|---|
| **On the user's own device** — the `.nmtsmap` file of §5 | nothing | yes | only if they still have the file |
| **Mirrored to Walrus** — a blob, reachable by id | storage + 2 wallet signatures per refresh | yes | yes |

Both are optional and neither is on by default. The NMTS database is NOT a third option in this table: it
is the index the drive runs on day to day, and it disappears in precisely the scenario a recovery manifest
exists for. A product that counted it as durability would be measuring the wrong thing.

## 1. Encryption (inherits NCF-3)

- The manifest is UTF-8 JSON encrypted as **one NCF-3 §3 envelope**: `E(dataKey, "nmts/v3/recovery-map", utf8(json))`.
  ⚠ **The AAD was renamed** from `nmts/v1/recovery-manifest` (NCF-3 §2.4: three different objects were
  all called "manifest", and this one is the offline recovery LIST). The live constant is
  `AAD_RECOVERY_MAP` in `crypto/src/wrap.rs`.
- The envelope also gained a 32-byte key commitment (NCF-3 §3.2), so its overhead is
  `nonce(24) + commitment(32) + tag(16) = 72 bytes` rather than 40.
- Per NCF-3 §3 it MUST be a single envelope (never chunk-framed) — true of v1 and v2 alike. Practical
  soft cap ≈ 100k items (~30–50 MB JSON); beyond that needs a future version carrying chunk framing.
  Enforced app-side, not format-side.
- Stored on Walrus either as one small dedicated blob or as one quilt patch inside a cohort flush
  (mechanics = P4; see §4).

## 2. JSON schema

```jsonc
{
  "v": 2,                                  // NRM version (this document)
  "seq": 12,                               // monotonic per account, +1 per manifest written
  "prev_manifest_blob_id": "…" | null,     // manifest CHAIN: predecessor's Walrus blob ID (null for seq 1)
  "generated_at": "<RFC3339>",
  "account_id": "<base64url 16B>",         // public lookup id, NOT a secret
  "meta": {                                // OPTIONAL. what the document says about ITSELF — §2.3
    "product": "NMTS",
    "product_url": "https://nmts.me",
    "app_version": "0.63.0",               //   the release that wrote it
    "tool": "nmts-recovery",
    "tool_url": "https://github.com/needmoretruth/nmts-recovery",
    "spec_url": "<this document, in the published copy>",
    "storage": {
      "network": "walrus",                 //   the family, same word a part carries
      "chain": "mainnet",                  //   ⭐ WHICH chain issued the blob ids
      "aggregators": ["https://…"],        //   read endpoints the writer was using. HINTS.
      "chain_rpc": "https://…"             //   for sui_object_id lookups. never needed to READ
    },
    "totals": { "items": 412, "bytes": 10133000000 }
  },
  "items": [
    {
      "id": "<uuid>",                      // NMTS item id (informational only)
      "name": "<plaintext name>",          // safe: the whole manifest is encrypted
      "path": "/folder/sub",
      "kind": "file",
      "created_at": "<RFC3339>",           // OPTIONAL. when the file was created …
      "updated_at": "<RFC3339>",           // … and last changed. §2.3 — a reader STAMPS, never decides
      "size": 123456789,                   // total plaintext bytes
      "dek": "<base64url 32B>",            // the file DEK, raw (manifest is the recovery key store)
      "content_hash": "<base64url 32B>",   // OPTIONAL. sha256 of the whole plaintext, RAW
      "parts": [                           // ordered; single-part files have exactly one entry
        {
          "part_index": 0,                 // REQUIRED from v2. where this part belongs — see §2.1
          "blob_id": "<blob id, in this network's own naming>",  // absent ONLY for own-quilt (v3)
          "plaintext_len": 1073741824,     // the REAL bytes this part contributes to the file
          "padded_len": 1073745920,        // OPTIONAL, v4. what the SEALED header declares, when
                                           //   the part was padded. absent = not padded. §2.2
          "sui_object_id": "0x…",          // OPTIONAL. on-chain blob object; never needed to READ
          "network": "walrus"              // OPTIONAL on the wire. absent = "walrus" (bullets below)
        }
      ],
      "quilt": {                           // present iff stored via a quilt cohort. ONE of two forms:
        "quilt_blob_id": "…",              //   ABSOLUTE — a quilt named outright
        "patch_id": "…"
        // "identifier": "…"               //   OWN QUILT (v3) — "the quilt you read this document
        //                                 //   from"; then the item has exactly one part and that
        //                                 //   part has NO blob_id. See §6 for why. A record that is
        //                                 //   neither form, or both, is refused.
      }
    }
  ]
}
```

- `items` lists **live items only** (de-indexed/deleted items are dropped — the manifest is the current
  index, not a history). Folders are NOT items: an empty folder has nothing to recover, and a folder that
  holds files is reconstructed from those files' `path`.
- `seq` + `prev_manifest_blob_id` form a backward chain (new → old). Given the LATEST manifest, the whole
  history is walkable (integrity/debugging, and orphaned-blob discovery during recovery). **`seq`, not
  `generated_at`, orders the chain** — the writing device's clock is not trustworthy. `prev_manifest_blob_id`
  is serialized even when null, so a reader can distinguish the head of the chain from a writer that never
  implemented chaining.
- **The chain links MIRRORS only.** `prev_manifest_blob_id` is a Walrus blob ID, so a manifest the user
  merely downloaded to their own device has no address a successor could point back at: such a manifest
  carries `null` regardless of its `seq`. `seq` still increases across every manifest of either kind, so
  "which is newest" is always answerable; only "what came before it" is unavailable for the stretches that
  were never mirrored. This is a consequence of the two storage modes, not a defect to repair — a locally
  kept manifest has no public address by definition.
- **`content_hash` is RAW here, on purpose.** The live drive stores this same hash sealed
  (`nmts/v3/content-hash`, NCF-3 §2.2) so the server cannot use it as a cross-account fingerprint; inside a
  manifest that precaution is redundant — the whole document is already one envelope — and carrying it in
  the clear is what lets the standalone tool verify a reassembled file without re-deriving a sealing key.
- **`sui_object_id` is informational.** Reading a blob needs only `blob_id` (aggregators serve by blob ID),
  so recovery never depends on it; it is carried so the tool can inspect or extend the blob's storage
  on-chain with no NMTS server to ask.
- **`network` names WHICH network to ask.** A blob ID is only meaningful on the network that issued it,
  so this is the field that points the tool at an aggregator. It is a NAME (`"walrus"`), not a code:
  whoever parses this document may be doing so years from now with none of our code beside them, and a
  bare `1` is not something a stranger can look up. Codes and names are registered together in
  `CRYPTO-FORMAT-NCF2.md` §6 — ⚠ **deliberately still NCF-2**: NCF-3 does not carry a storage-network
  registry, so §6 of that superseded document remains the only written one.
  **Absent means `"walrus"`** — a fact rather than a fallback: every manifest written before this field
  existed describes bytes on the only network NMTS could write to. Readers must resolve it that way
  (`Part::network_name` in `crypto/src/manifest.rs`) rather than treating absence as "unknown", which
  in a recovery is the same as unrecoverable. Writers name it on **every** part, including Walrus, so
  new manifests are self-describing.
- **`size` is exactly the sum of the parts' `plaintext_len`, padding or no padding.** Not "about" —
  exactly. This is why `padded_len` is a second field rather than a new meaning for the first (§2.2). A writer MUST
  refuse to emit an item where the two disagree, and a reader MAY use the disagreement to reject an
  item outright. This is not bookkeeping: `size` is copied out of the account's own sealed file list,
  which the storage layer cannot write, while the part list is whatever the storage layer served. The
  equality is therefore the one arithmetic check available to a writer that has not fetched a single
  blob, and it is what catches a dropped tail, a repeated row with a different length, or a
  `plaintext_len` that was inflated to make a short file look whole.
- **`part_index` says where the part belongs.** `0` for the first, `1` for the second, and so on: it
  is the position the part must be concatenated at, and for an item's `parts` array it is always
  equal to that entry's own index in the array. It is REQUIRED from v2 (§6). §2.1 states what a
  reader has to do with it, and that section is the whole reason the field exists.

### 2.3 `meta` — what the document says about itself (added 2026-08-19)

A recovery list described the ACCOUNT thoroughly and itself barely at all. The person it exists for
is holding one file, years later, with no site to visit and no memory of what wrote it — and four
questions had no answer anywhere in the document: **which program reads this**, **where is that
program**, **where is the format written down**, and **which chain do these blob ids belong to**.
The whole block is a few hundred bytes and the document is sealed, so none of it is visible to
anyone without the account code. Measured: **449 bytes** for `meta` (whitespace stripped) plus
**73 bytes** per item for the two dates.
⚠ **Where those bytes land is not the same for every copy.** The three artefacts a person keeps on
their own device are not uploaded, so there the cost is zero. The SAME sealed document is also
written as the storage-network copy (§4), and there it is billed per byte along with the files it
rides with. It is carried there anyway, because that copy is the one somebody fetches with an
account code and nothing else — no device, no screen, no other context at all.

- **`storage.chain` is the field that changes behaviour.** A blob id is only meaningful on the
  network that issued it, and `network` says only the family (`"walrus"`) — so a list from testnet
  and a list from mainnet were the same kind of string, and the standalone program had to try both
  aggregators and let a wrong guess look like missing bytes. With `chain` present it asks the right
  one first (`recovery/src/source.rs::aggregators_for_chain`). This is the field the comment beside
  those defaults used to call "the real fix, in the next list version".
- **`aggregators` and `chain_rpc` are HINTS and are read last.** They are the endpoints one browser
  was using on one day — the first thing in the file to go stale — so a reader treats them as
  candidates AFTER its own built-in defaults, never as instructions.
- **`totals` is not an integrity check and a reader must not treat a disagreement as tampering.**
  The document is one authenticated envelope: nobody can edit `items` without the account code. It
  is for a RE-IMPLEMENTATION — a parser written years from now that drops records it does not
  recognise has no other way to notice it read 400 of 412 files. A reader that finds a disagreement
  SAYS so and continues.
- **Every field is a CLAIM, and every field is optional.** They are strings the writing build
  printed about itself and about other programs. A URL can die and a repository can move. ⛔ A
  reader must never REQUIRE any of them, and must never refuse a document for what they say.
- **`created_at` / `updated_at` on an item are the only values in it that nothing checks.** `name`,
  `size` and `dek` come out of a sealed file list; `parts` is constrained by `size` arithmetically.
  These two are simply what the storage layer said. A reader MAY stamp them onto the files it
  writes — a wrong modification date costs nothing, and a right one is most of what makes a
  restored folder usable — and MUST NOT order, compare, or decide anything with them. `seq` orders
  the chain, exactly as before.

⛔ **None of this moved the version, and it must not.** Every field is additive and its absence
changes no meaning, so `nmts-recovery` 0.1.0 and 0.2.x read a document carrying the block exactly
as they read one without it. That is not a hope: neither reader sets `serde(deny_unknown_fields)`.
A bump would have been the opposite of a favour — the version numbers are CEILINGS in every
published build, so raising one makes those builds refuse a file they could have read every byte
of. The rule this follows: **until a 1.0.0 of either NMTS or the recovery program exists, a format
may run ahead of the tools — but never in a way that makes an existing build refuse a file.**

Implementation: `web/src/lib/recovery/provenance.ts` (the values) ·
`web/src/lib/recovery/manifest-doc.ts` (the encoder) · `crypto/src/manifest.rs::Meta` (the reader) ·
shared fixture `crypto/tests/vectors/nrm-meta-sample.json`.

### 2.1 Part placement — the reader's obligation

A multi-part file is only its parts **in the right order**. Getting that order wrong does not fail
loudly: it produces a file of exactly the right length, made of exactly the right bytes, that is
silently not the file. So the rule is written here, in the document a recovery tool's author reads,
rather than left implicit in the array.

For each item, a reader assembling a file MUST, for every position `i` from `0` to `parts.length - 1`:

1. take `parts[i]` **at that position in the array as written** — see the MUST NOT below;
2. check `parts[i].part_index === i`, and refuse the item if it does not hold;
3. fetch `parts[i].blob_id`, parse the 72-byte NCF-3 stream header, and check that the header's own
   sealed `part_index` equals `i` **and** that its sealed `part_total` equals `parts.length`
   (CRYPTO-FORMAT-NCF3.md §4.1). The header fields are bound to the file key by the envelope's key
   commitment, so this is the only one of these checks that proves anything against an attacker who
   wrote the list's plaintext — steps 2 and 4 compare the list against itself;
4. check `parts[i].plaintext_len` against the header's own length, and refuse on a mismatch;
5. write the plaintext at that position, and **only after** steps 2–4 have passed for it.

⛔ **A reader MUST NOT sort `parts` by `part_index` before performing check 2.** Sorting first makes
every permutation pass, because after a sort the indices `0…n-1` each appear exactly once by
construction and the check compares a list against itself. The check has to compare the sealed value
against **the position the reader is about to write at**, which is the only quantity in the
comparison the reader chose. This is not hypothetical: the equivalent defect existed in the browser
download path in this codebase and had to be fixed there first.

⛔ **A reader MUST NOT treat a missing `part_index` in a `v: 2` document as "not recorded".** In
NRM-1 the field does not exist and its absence carries no information; in NRM-2 every part has one,
so a part without it is a document that was altered, not an old one. Refuse the item.

⚠ **What a writer can and cannot check.** The browser writes this list from the server's own dump of
the storage layer and never fetches a blob while doing so, so it can only check the list against
itself and against the sealed file list: that the numbering is a complete `0…n-1` run, and that the
lengths add up to `size`. It cannot check that the blob listed at position `i` really holds part `i`
— only step 3 above does that, and only at recovery time. `part_index` is recorded so that step 3
has something to be checked against instead of bare array order.

### 2.2 Padding — `padded_len` (v4)

A stored part may be sealed **larger than the bytes it contributes**, so that whoever can see the
stored object cannot read the file's real size off it. `plaintext_len` keeps its meaning — the real
bytes — and `padded_len` says what the sealed NCF-3 header will declare. Absent means the part was
not padded, and a part where the two would be equal MUST omit the field.

**Why the padding is inside the plaintext rather than appended to the stored bytes.** An NCF-3
header is authenticated but **not encrypted**: `plaintext_len` sits in the clear at offset 16 of a
public Walrus object (`CRYPTO-FORMAT-NCF3.md` §4.1). Anyone who fetches the blob reads the file's
exact original size, however many bytes were tacked on after the stream. Padding is therefore added
to the plaintext *before* sealing, which makes the header's number the padded one — and leaves the
real number with nowhere to live except this document.

**Why two numbers rather than one.** Fold the padding into `plaintext_len` and the §2 equality
(`size` = the sum of the parts) has to weaken from "exactly" to "at least", which accepts any `size`
below the real one: the file comes back short, and nothing says so unless the item happens to carry
a `content_hash`. Keeping them apart means every check that existed before padding keeps its exact
strength, and padding adds one more.

**A reader MUST:**

1. compare the part's sealed header against `padded_len` when present, and against `plaintext_len`
   otherwise — the same comparison as before, against whichever number the stream is supposed to
   declare;
2. decrypt the **whole** stream. The padding is inside the same AEAD as the file's own bytes, so the
   chunk tags, the final-chunk flag and the recovered length only add up if every byte goes through
   the decryptor. Reading a shorter prefix turns "this stream is intact" into "the front of this
   stream is intact";
3. write and hash only the first `plaintext_len` bytes of what it decrypted, and drop the rest.

**A writer SHOULD pad only a file's FINAL part** (NMTS does, from 2026-08-19). Every earlier part
is exactly the writer's own part size — a round number that says nothing about the file — so padding
one hides nothing, and leaving them unpadded buys something real: every reader can recover each
part's contributed length from the file's size and the parts' declared lengths alone,

    real_i = min(declared_i, size - Σ real_(<i))

which is what let padding ship with no new field in any of the places that hold a file's size. It is
a SHOULD and not a MUST because a document that padded an earlier part is still readable — this
format states both numbers per part — but the arithmetic above stops being unique, so anything
relying on it (NMTS's own download path does) must be given the real lengths another way.

**A reader MUST REFUSE** a `padded_len` in a document declaring `v` below 4, and one that is not
strictly greater than `plaintext_len`. Both are contradictions with no reading a parser may pick.

⛔ **What is deliberately NOT checked: how much padding there is.** The amount follows a setting a
person can change — a coarser unit, or a number typed in — so a tool that enforced today's rule
would refuse files padded under tomorrow's setting. What is checked is that the list and the sealed
header agree, which is the part somebody else could move.

Reference implementations: `crypto/src/manifest.rs::check_padding` (the rules),
`recovery/src/restore.rs::decrypt_part` (the reader), `web/src/lib/recovery/manifest-doc.ts` (the
writer). The shared fixture is `crypto/tests/vectors/nrm4-sample.json`.

### Who writes this JSON

Two independent implementations produce/consume this document and they must not drift:

| Side | Where | Role |
|---|---|---|
| Writer | `nmts/web` crypto worker | builds the JSON **inside the worker** — the document holds every file key, so it must never cross to the main thread in the clear |
| Reader | `nmts/crypto` `manifest.rs` | the types the standalone recovery tool parses |

The gate is the shared fixture **`nmts/crypto/tests/vectors/nrm2-sample.json`**: the Rust suite parses it
into the expected structs, and the web unit suite asserts its builder emits the same document. Adding a
field means touching both sides and that fixture in one change. **`nrm1-sample.json` sits beside it** and
is not history: the Rust suite parses that one too, which is how "an NRM-1 list still opens" stays a
tested fact rather than a belief. The two fixtures differ in `v` and in `part_index` and in nothing else.

**Where each side enforces what.** `part_index` is `Option<u64>` in Rust, not `u64` with a default — a
default would turn "this list never recorded where the part goes" into "this part goes first", which is a
claim nobody made and is wrong for every part after the first. `RecoveryManifest::from_json` is the one
place that decides when absence is legal: required from `v: 2`, absent in `v: 1`, and a *stated* index
that disagrees with its own array position is refused at either version. So after a successful parse,
`None` means exactly what §6 says it means — the list cannot tell you where this part goes — and the
compiler makes the recovery tool confront that instead of reading a zero.

The `size`-equals-the-sum rule of §2 is asymmetric on purpose, and the Rust side follows the wording:
`to_json` refuses to EMIT an item that breaks it (writer MUST), while a reader is offered
`Item::parts_add_up()` rather than stopped by it (reader MAY). A writer has fetched no blob and can
still rebuild, so for it the arithmetic is the whole defence and acting on it costs nothing; a reader is
in a recovery, is about to compare every `plaintext_len` against the part's own sealed header anyway
(§2.1 steps 3–4, strictly stronger on the same numbers), and refusing the document would cost that
person every other file in it.

## 3. Staleness semantics (honest limits — the Recovery Guide must state these)

- A downloaded Recovery Guide pins ONE manifest blob ID. Blobs are immutable, so a stale guide can never
  discover manifests written after it. **A guide recovers everything that existed when it was downloaded;
  files uploaded later need a newer guide or the live api.** There is deliberately NO server-independent
  "find the latest manifest" mechanism in v1: a deterministic account→blob lookup would need on-chain or
  third-party state and was rejected — voucher accounts have no wallet to enumerate, and it would
  weaken the "nothing but the code + the tool" recovery story with a dependency that can rot.
- Compensating UX (spec §4.4c): the Guide is re-offered for download whenever the manifest rotates
  (after upload sessions), so the newest guide is always one click away while NMTS is alive.
- Recovery precedence for the standalone tool: use the newest manifest available (highest `seq`); walk
  `prev_manifest_blob_id` only for diagnostics or to find blobs the newest manifest no longer lists.

## 4. The storage-network copy — SHIPPED 2026-08-17

- **Who pays/signs each mirror refresh:** user-paid accounts fold the manifest write into the next
  cohort/part flush (same wallet signatures, near-zero marginal cost); voucher accounts are
  treasury-written (implementation parked with P3). Until P4 wiring lands, manifests exist only in the
  NMTS DB (layer 1) and the Guide carries the file list directly.
- **Expiry invariant:** a mirrored manifest's Walrus expiry MUST be ≥ the longest-lived file it describes;
  if it rides inside a cohort quilt whose expiry undershoots that, an additional dedicated mirror is
  required (lifecycle-engine rule, P4).
- ✅ **Measured end to end on 2026-08-18.** A browser created an account, switched the copy on,
  paid with the wallet the account code derives, and uploaded a real quilt on Walrus testnet;
  the standalone recovery program was then given the account code and nothing else, found the
  list with `--find`, and restored both files byte for byte. That measurement is also what
  showed the feature could not work in the release it shipped in: the browser's compiled
  encryption engine predated the function that names the list inside a quilt, so the copy was
  never written. Two checks now compare what the site calls against what the compiled engine
  provides, and every message name against the text bundles.
- ✅ **The reason for the wait is spent, and the copy shipped on 2026-08-17.** It was deferred because
  the copy's promise ("recoverable even if you lose the file") could only be verified by a standalone
  recovery tool, and there was none. The tool now lives at `github.com/needmoretruth/nmts-recovery` and
  reads the copy with `--find`.
- ⛔ **It is OFF unless the person turns it on** (owner, 2026-08-17). The storage is paid for out of
  their own wallet, and a product may not spend somebody's money by omission. The screen recommends it
  and states four things before it is switched on: what it costs now, what it costs to keep, that the
  money goes to the storage network rather than to NMTS, and what it buys. The intention is
  `accounts.recovery_network_copy`; what EXISTS stays `accounts.recovery_manifest_kind = 2`, and the two
  are shown separately because they differ for anybody who switched it on and has not uploaded since.
- ⭐ **The mirror buys more than "you can lose the file", and this is the part to design around.** Blob
  objects are transferred to the uploading wallet's own address, and that address derives from the account
  code (§1.3 of the format document). So a mirrored list sitting at that same address is reachable from the
  account code ALONE: derive the address, ask any full node what it owns, and recognise the list by
  recomputing the envelope's key commitment. ⛔ An earlier note here proposed a SEPARATE recovery-only
  address for privacy; that argument is void, because the account's blob objects are already at the payment
  address and the two histories are linked with or without the list.
- ✅ **The one-cohort lag is solved by NRM-3, not accepted.** A list folded into a cohort flush cannot
  name the blob ids of the upload it rides along with — a quilt's blob id is a hash of its contents, this
  document included, so there is no fixed point. NRM-3 adds the own-quilt placement (§6): the item says
  "my patch is called X, in the quilt you found this document in", and the reader supplies the address it
  fetched from. ⛔ Accepting the lag was the alternative, and it is empty for the person who uploads once
  and never again — who is exactly who this exists for.
- ⚠ **Two limits that remain, both stated on screen.** An account paying with a browser-extension wallet
  or an imported key is not reachable this way (its address does not derive from the account code; the
  recovery program takes the address by hand instead). And a file of 64 MiB or more is stored on its own
  rather than in a quilt, so a list riding in a quilt does not travel with it.

## 5. The device-kept manifest file (`.nmtsmap`)

A manifest saved to the user's own device is wrapped in a small self-describing JSON envelope. On Walrus
the blob ID supplies the context; a file in someone's Downloads folder has none and must explain itself
years later.

```jsonc
{
  "format": "nmts-recovery-map",   // checked before anything is attempted
  "version": 2,                    // the WRAPPER's version, independent of `nrm`
  "nrm": 2,                        // NRM version of the sealed document
  "seq": 7,                        // which manifest this is; higher wins
  "generated_at": "<RFC3339>",
  "account_id": "<base64url 16B>", // so several files can be told apart
  "sealed": "<base64url>",         // EXACTLY the envelope a Walrus mirror would hold
  "min_tool": "0.1.0",             // lowest nmts-recovery version that reads this document
  "note": ["<English line>", "<Korean line>"],  // BOTH, always — v2
  "about": {                       // OPTIONAL. the same answers as `note`, for a PROGRAM
    "product": "NMTS",
    "product_url": "https://nmts.me",
    "app_version": "0.63.0",       //   the release that wrote this file
    "artifact": "recovery-list",   //   which of the three this is
    "tool": "nmts-recovery",
    "tool_url": "https://github.com/needmoretruth/nmts-recovery",
    "spec_url": "<this document, in the published copy>",
    "sealed": {                    //   what opens `sealed`, for a re-implementation
      "format": "ncf3",
      "context": "nmts/v3/recovery-map",   // the NCF-3 domain separator — unguessable, and a
      "encoding": "base64url",             // wrong guess is indistinguishable from a damaged file
      "opened_with": "nmts-account-code",
      "spec_url": "<CRYPTO-FORMAT-NCF3.md, in the published copy>"
    }
  }
}
```

- `sealed` is byte-for-byte the same envelope as the mirrored form, so the standalone tool reads **one**
  format from either source.
- **The plaintext header names nothing and counts nothing.** No file names, no item count, no total size —
  a leaked `.nmtsmap` must not disclose what an account holds, or how much of it.
- Filename: `nmts-recovery-map-<8-char account slug>-<zero-padded seq>.nmtsmap`. The sequence is in the name
  as well as the body so someone with three of them can tell which is newest without opening any.
- **`version` stayed at 1 for NRM-2.** The wrapper's own fields did not change; `nrm` is the field that
  says which document version is inside, and moving both together would tell a reader the shell had
  changed when it had not. It moved to **2 on 2026-08-03**, when `note` became an ARRAY carrying both
  languages regardless of the UI language the file was saved from — the person who finds this file
  years later must be able to read it, and which language they read is not something the moment of
  saving can know.
- ⭐ **`min_tool` (added 2026-08-19) names the lowest `nmts-recovery` version that reads this
  document.** It sits BESIDE `nrm` rather than replacing it, because the two answer different
  questions: `nrm` says which forms the document uses, which is what any reader needs — ours or a
  stranger's re-implementation — while `min_tool` is what the person holding the file needs, which is
  a number they can go and download. The refusal is still decided by `nrm`; `min_tool` is quoted back
  in the sentence so it names a version instead of only saying "newer".
  ⚠ It is a CLAIM about a different program, not something a reader can verify, and it is written
  from a small table (`map-file.ts::MIN_TOOL_FOR_NRM`) that has to be kept honest by hand.
  ⛔ **And it rescues nobody.** Knowing you need 0.2.0 does not help if 0.2.0 does not exist — which
  is why the standalone program still ships BEFORE a new form is switched on. What it buys is a
  refusal a person can act on, not one they can survive.
  ⚠ Adding it did NOT move `version`: a reader that does not know the field ignores it and behaves
  exactly as before, and bumping the shell would have made every build refuse the file outright.
- ⭐ **`about` (added 2026-08-19) is the machine-readable half of `note`.** `note` says what this
  file is in sentences a person reads; `about` says it in fields a program can act on. The same
  block goes in the file-list wrapper (`.nmtslist`, `artifact: "file-list"`, sealed under
  `nmts/v3/file-list`) and in the recovery kit's machine section (`artifact: "recovery-kit"`, which
  carries `contains: ["account-code","recovery-list"]` instead of `sealed` — a kit is a text file
  that EMBEDS an envelope rather than being one, and naming the code first is what lets a program
  warn somebody about the file they are holding).
  ⛔ **Nothing in it names or counts anything inside the file** — the plaintext rule above is
  unchanged, and the writer's test pins the whole key set so a new plaintext field has to be argued
  for rather than added.
  ⚠ Adding it did NOT move `version`, for the same reason `min_tool` did not: an unknown key is
  skipped, while a higher shell number makes every published build refuse the file outright.
- ⛔⛔ **A READER MUST NOT ACT ON ANYTHING IN `about`.** This header is not authenticated by
  anything — whoever holds the file can edit it — and the fields worth acting on are URLs. A build
  that quoted `about.tool_url` back in its "this list is newer than this program" refusal would
  hand whoever edited the file a way to send somebody mid-recovery to a download of their choosing.
  `nmts-recovery` therefore prints its own compiled-in URL there and reads the SEALED `meta` (§2.3)
  for everything it shows or decides; a test in `recovery/src/mapfile.rs` fails if that changes.
- Implementation: `nmts/web/src/lib/recovery/map-file.ts` (writer) ·
  `nmts/web/src/lib/recovery/provenance.ts` (the block) ·
  `nmts/recovery/src/mapfile.rs` (reader, and the one place the refusal sentence is composed).

## 6. Version history

### 2026-08-19 — the self-description, and NO version moved

`meta` (§2.3), per-item `created_at`/`updated_at` (§2.3), and the wrapper's `about` (§5) all shipped
on this date **without raising NRM, the wrapper version, or the kit version.** It is listed here
because a version history that only records bumps hides the more interesting decision.

**Why no bump.** Every version number in this format is a CEILING in every published build: a
document declaring a number higher than a build knows is REFUSED, unread. So a bump is not a
courtesy to old readers, it is a wall in front of them. The test is therefore not "did the format
change" but **"does the absence of the new form change the meaning of anything else"** — and here it
does not: a document without `meta` means exactly what it meant last week, and a reader that skips
the block behaves exactly as it did. The bumps that DID happen (NRM-2, -3, -4) each pass that test
the other way: without them, stripping `part_index` would have been a free downgrade, an own-quilt
placement would have been unreadable, and a padded part would have handed back padding as content.

**The standing rule.** Until a 1.0.0 of either NMTS or `nmts-recovery` exists, a format may run
ahead of the tools: someone holding an older list installs the build its `min_tool` names, and the
repository is public and AGPL so any version can be fetched. From 1.0.0 on, everything after it is
mutually compatible. ⛔ That permission is for when a change REQUIRES a bump — never a reason to
take one.

### NRM-4 (2026-08-18) — `padded_len`

**What it adds.** One optional part field, `padded_len` (§2.2): the part's stored stream was sealed
larger than the bytes it contributes, so that the file's real size cannot be read off the stored
object. `plaintext_len` is untouched and still means the real bytes.

**Why the number had to move.** The version marker is what makes the field's ABSENCE mean "this part
was not padded" instead of "this writer did not record it". A build that predates padding reads
`plaintext_len` as the whole stream; handed a padded list it would stop on the sealed header — a
correct refusal, but a confusing one. With the bump it stops on the version instead, before an
account code is ever asked for, and says the list is newer than the program.

**What still opens where.** An ordinary list is still a v2 document, because a writer stamps
`minimum_version` — the version its contents need — and an unpadded part carries no v4 form. Only a
list that actually holds padding is v4. ⛔ **This is why the standalone tool has to be published
before padding is switched on**: people are holding builds that cannot read a v4 document, and the
order "readers first, writer second" is what keeps a recovery working for them.

### NRM-3 (2026-08-17) — the own-quilt placement

**Added:** `quilt.identifier`, and `parts[].blob_id` became optional. **Changed:** `v` may be `3`.
Nothing was removed or renamed.

**The two placements.** A `quilt` record is exactly one of them, and a reader refuses anything that is
neither or both:

* **absolute** — `{quilt_blob_id, patch_id}`. Names a quilt anywhere on the network.
* **own quilt** — `{identifier}`. Means "the quilt this document was read out of", with the patch named
  by the identifier the writer chose. The item's single part carries NO `blob_id`; absence is legal
  here and refused everywhere else.

**Why it exists.** The storage-network copy of a list is written INTO the same quilt as the files it
describes. That quilt's blob id is a hash of its contents — this document included — so the document
cannot contain it. Without this form the copy would always be one upload behind, and for somebody who
uploads once and never again, one upload behind is empty.

**⚠ It is only meaningful to a reader that got the document out of a quilt.** A copy extracted to a
file cannot resolve it, and both implementations say so rather than guessing: guessing would mean
fetching some other quilt the account owns, which returns a stranger's ciphertext and fails as
"damaged" — the wrong story entirely.

**⭐ A WRITER STAMPS THE VERSION THE CONTENT NEEDS, not the newest one it knows.** People already hold
copies of the standalone recovery program, and a build only knows the forms that existed when it was
made. The file a person downloads is built after an upload has finished, so every placement in it is
absolute and it is still a **v2 document** — every reader ever shipped goes on reading it. Only the
storage-network copy reaches v3. (`minimum_version` in `crypto/src/manifest.rs`; `minimumVersion` in
`web/src/lib/recovery/manifest-doc.ts`.)

**And NRM-3 lists in a reader written before NRM-3?** They refuse them, and that is correct: such a
reader would see a part with no `blob_id` and have no address for it. The refusal happens on the
version marker, before any parsing — which is the whole reason the number moved.

### NRM-2 (2026-07-29) — `part_index` on every part

**Added:** `part_index`, required on every entry of every item's `parts` array (§2). **Added:** §2.1,
the reader's positional obligation. **Changed:** `v` is `2`. Nothing was removed or renamed.

**Why it could not wait.** A list re-seals whenever it is rebuilt, but a person who builds one list and
never rebuilds keeps that one for as long as they keep the file — which is the entire point of the
artefact. So a field that a recovery years from now depends on had to be in the format before the
mainnet cutover, which was then expected to freeze it. What forced it was an adversarial review of this
path (2026-07-29): a list is built from the server's own dump, the
builder never fetches a blob, and before this change nothing in the document said where a part
belonged. A hostile server could permute or drop parts, the list would seal and report itself as good
— the byte total shown to the user is summed from the sealed file list, so it looks right even when a
part is missing — and the failure would surface years later, at the one moment it cannot be repaired.

**Why the version number moved for one additive field.** So that its absence means something. In an
NRM-1 list a part has no index and a reader has nothing to check the order against; in an NRM-2 list
every part has one, so a part missing it is an altered document. Without the bump, deleting the field
from every part would be a silent downgrade to NRM-1's guarantees and no reader could tell.

**Are NRM-1 lists still readable? Yes, unchanged.** A reader MUST keep parsing them: the fields NRM-1
defines mean exactly what they meant, `parts` is still in order, and a list somebody downloaded in
2026 is the only copy they have. What a reader MUST NOT do is pretend it performed §2.1 on one. On an
NRM-1 list, steps 1, 3, 4 and 5 of §2.1 still apply in full — the sealed NCF-3 headers carry
`part_index` and `part_total` regardless of the list's version, so a reader that fetches blobs can
still refuse a permutation. Only step 2, the list's own statement of placement, is unavailable: an
NRM-1 list cannot be checked against itself before any network I/O, and a reader must treat its array
order as a claim it has not yet verified rather than as a fact.

**And NRM-2 lists in a reader written before NRM-2?** They parse. Such a reader ignores fields it does
not know and never looked at `v`, so it sees precisely the NRM-1 view and behaves as it always did.
That is a property of that reader, not a promise the format makes — a future version that removes or
repurposes a field would break it, which is why the version number is there to be checked. The
current reader does check it: that is what turns "a `v: 2` part without `part_index` is a tampered
document" from a sentence in this file into a refusal.

**Implementations:** `web/src/lib/recovery/manifest-doc.ts` (the shape and its invariants),
`web/src/lib/recovery/build-map.ts` (the writer, and the two checks §2.1's last paragraph describes),
`crypto/src/manifest.rs` (the reader's structs, and the §2.1 step-2 refusal in `from_json`),
`web/test/recovery-map.test.ts` and `crypto/tests/api.rs` (the tests, against the two fixtures named
under "Who writes this JSON").
