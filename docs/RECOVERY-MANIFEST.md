# NMTS Recovery Manifest v2 (NRM-2)

> **Status: DRAFT-STABLE.** Field additions and renames are allowed only with a journalled decision
> while NMTS is testnet-only. The format **freezes at the first mainnet mirror write (P6 gate)** — after
> that, evolution happens as a NEXT version alongside, never by mutating this document.
> Decided 2026-07-08; the v2 bump followed on 2026-07-29. Companion section:
> **[`CRYPTO-FORMAT-NCF3.md`](CRYPTO-FORMAT-NCF3.md) §3** (the envelope this document's §1 uses).
>
> ⚠ **`v` is 2 as of 2026-07-29.** Every part now carries `part_index` and §2.1 states what a reader
> MUST do with it. NRM-1 lists stay readable — see §6 for what changed, and for exactly what an NRM-1
> list can and cannot promise a reader that an NRM-2 list can.
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
  "items": [
    {
      "id": "<uuid>",                      // NMTS item id (informational only)
      "name": "<plaintext name>",          // safe: the whole manifest is encrypted
      "path": "/folder/sub",
      "kind": "file",
      "size": 123456789,                   // total plaintext bytes
      "dek": "<base64url 32B>",            // the file DEK, raw (manifest is the recovery key store)
      "content_hash": "<base64url 32B>",   // OPTIONAL. sha256 of the whole plaintext, RAW
      "parts": [                           // ordered; single-part files have exactly one entry
        {
          "part_index": 0,                 // REQUIRED from v2. where this part belongs — see §2.1
          "blob_id": "<blob id, in this network's own naming>",  // absent ONLY for own-quilt (v3)
          "plaintext_len": 1073741824,
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
- **`size` is exactly the sum of the parts' `plaintext_len`.** Not "about" — exactly. A writer MUST
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
  "version": 1,                    // the WRAPPER's version, independent of `nrm`
  "nrm": 2,                        // NRM version of the sealed document
  "seq": 7,                        // which manifest this is; higher wins
  "generated_at": "<RFC3339>",
  "account_id": "<base64url 16B>", // so several files can be told apart
  "sealed": "<base64url>",         // EXACTLY the envelope a Walrus mirror would hold
  "note": "<one localized line for whoever finds this file>"
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
  changed when it had not.
- Implementation: `nmts/web/src/lib/recovery/map-file.ts`.

## 6. Version history

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
artefact. So a field that a recovery years from now depends on has to be in the format before the
format freezes at the mainnet cutover, not after. What forced it was an adversarial review of this
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
