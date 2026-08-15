//! Recovery manifest (NRM-2, `docs/RECOVERY-MANIFEST.md`): the encrypted index that makes
//! every file recoverable with only the account code and Walrus, and zero NMTS infrastructure.
//!
//! # Purpose
//! The manifest is a JSON document listing every item (name, path, size, per-file DEK, and
//! ordered Walrus blob IDs). Encrypted under the account `dataKey` with the
//! `nmts/v3/recovery-map` envelope, it — plus the account code — reconstructs the
//! whole drive from public aggregators. The standalone recovery tool parses exactly these
//! types.
//!
//! # Single-envelope rule (frozen)
//! A manifest is ALWAYS a single [`crate::wrap`] envelope — never chunk-framed. This
//! module only offers envelope (de)serialization, so there is no way to produce a
//! chunk-framed manifest. [`RecoveryManifest::decrypt`] additionally rejects input that looks
//! like an NCF-3 stream (defense-in-depth against a mis-encoded blob).
//!
//! # Manifest chain
//! Each write carries `seq` (+1 per manifest) and `prev_manifest_blob_id` (the one it
//! supersedes). Given the newest manifest a tool can walk backwards to find blobs an
//! intervening delete dropped from the current index. `seq` — not the timestamp — decides
//! which of two reachable manifests wins; clocks on the writing device are not trustworthy.
//!
//! # Part placement (NRM-2)
//! Every part of every item carries a `part_index` saying where it belongs, and this module
//! refuses a v2 document whose parts do not each sit at the position they claim
//! (RECOVERY-MANIFEST.md §2.1). The field exists because array order alone cannot be
//! CHECKED: the map is built from the storage layer's own dump, the builder never fetches a
//! blob, so before NRM-2 a map that listed a file's parts in the wrong order read exactly
//! like a correct one and the mistake surfaced years later, in a recovery, at the one moment
//! it could not be repaired. An adversarial review of the recovery-map path found it (2026-07-29).
//!
//! ⛔ There is deliberately no "sort the parts by `part_index`" helper here, and a caller must
//! not write one: after a sort the indices `0…n-1` each appear exactly once by construction,
//! so every permutation agrees with itself and the check proves nothing. The comparison has to
//! be against the position the reader is about to write at. That is not hypothetical — the
//! equivalent defect existed in the browser download path and had to be fixed there first.
//!
//! # Contract
//! Serde field names match `docs/RECOVERY-MANIFEST.md` §2 verbatim (`v`, `seq`,
//! `prev_manifest_blob_id`, `generated_at`, `account_id`, `items`, …). **The browser builds
//! this JSON itself** (the manifest holds every file key, so it is assembled inside the
//! crypto worker and never crosses to the main thread in the clear) — these structs are what
//! the standalone recovery tool parses, which makes them the two ends of one wire format.
//! `tests/vectors/nrm2-sample.json` is the shared fixture that keeps the two ends honest
//! (this crate parses it, and the web unit tests assert their builder emits exactly it), and
//! `tests/vectors/nrm1-sample.json` is kept beside it so the one-version-back document stays
//! parseable rather than merely believed to be.
//! Optional fields (`quilt`, `content_hash`, `sui_object_id`, `network`) are omitted when absent
//! so byte output stays canonical; `prev_manifest_blob_id` is the deliberate exception (see below).

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::framing::MAGIC;
use crate::wrap::{self, WrapError, AAD_RECOVERY_MAP};

/// The manifest format version (`"v"` field) this crate writes.
///
/// Raised 1 → 2 on 2026-07-29 when `part_index` became required on every part
/// (`docs/RECOVERY-MANIFEST.md` §6). The number moved for a single additive field so that the
/// field's ABSENCE means something: see [`MANIFEST_VERSION_WITH_PART_INDEX`].
pub const MANIFEST_VERSION: u32 = 2;

/// The first NRM version in which `part_index` is required on every part.
///
/// Written as its own constant rather than as `MANIFEST_VERSION`, because the two answer
/// different questions and will stop being equal at the next bump: this one is "from which
/// version does an absent `part_index` mean a tampered document rather than an old one", and
/// the answer stays `2` however far the format version travels past it.
pub const MANIFEST_VERSION_WITH_PART_INDEX: u32 = 2;

/// Errors from manifest (de)serialization and (de)cryption.
#[derive(Debug, thiserror::Error)]
pub enum ManifestError {
    /// JSON serialization/deserialization failed.
    #[error("manifest JSON error: {0}")]
    Json(#[from] serde_json::Error),
    /// Envelope encryption/decryption failed.
    #[error("manifest envelope error: {0}")]
    Wrap(#[from] WrapError),
    /// Decryption input began with the NCF-3 stream magic — a chunk-framed blob was
    /// supplied where a single envelope is required (violates the single-envelope rule).
    #[error("input is a chunk-framed stream, not a single-envelope manifest")]
    NotSingleEnvelope,
    /// A `v: 2` (or newer) document carried a part with no `part_index`.
    ///
    /// This is not an old document. NRM-1 is the version in which the field does not exist;
    /// a document that says it is NRM-2 and then omits it is one that was altered, and the
    /// only honest response is to refuse it rather than fall back to bare array order
    /// (RECOVERY-MANIFEST.md §2.1, second ⛔).
    #[error("item {item_id}: the part at position {position} carries no part_index, which v{v} requires")]
    PartIndexMissing {
        /// The item's NMTS id. Never its name — names are the plaintext this format protects.
        item_id: String,
        /// Position in the item's `parts` array.
        position: usize,
        /// The `v` the document declared.
        v: u32,
    },
    /// A part's `part_index` disagreed with the position it occupies in its item's array.
    ///
    /// A document that contradicts itself is refused whatever its version: in NRM-2 the field
    /// is required and equal to the position, and an NRM-1 writer that emitted one at all
    /// emitted the position. Which of the two to believe is not a question a parser should be
    /// answering on a stranger's behalf.
    #[error("item {item_id}: the part at position {position} says it is part {stated}")]
    PartIndexMisplaced {
        /// The item's NMTS id.
        item_id: String,
        /// Position in the item's `parts` array.
        position: usize,
        /// The `part_index` the part claimed.
        stated: u64,
    },
    /// An item's parts do not add up to the item's `size` — refused on the WRITE path.
    ///
    /// RECOVERY-MANIFEST.md §2 makes this a writer MUST and a reader MAY, and this crate
    /// takes it at its word; [`Item::parts_add_up`] is the reader's half. See
    /// [`RecoveryManifest::to_json`] for why the two sides are not symmetric.
    #[error("item {item_id} is {size} bytes but its {parts} parts hold {held}")]
    PartsDoNotAddUp {
        /// The item's NMTS id.
        item_id: String,
        /// `size`, as copied from the account's own sealed file list.
        size: u64,
        /// How many parts were listed.
        parts: usize,
        /// What their `plaintext_len`s actually sum to. Widened so an overflowing sum is
        /// reported as the number it is rather than wrapped into a plausible one.
        held: u128,
    },
}

/// One stored part of a (possibly multi-part) file, in order.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Part {
    /// Where this part belongs in the file: `0` for the first, and thereafter the position it
    /// must be concatenated at. Required from NRM-2 on; `None` is what NRM-1 looks like.
    ///
    /// # Why this is an `Option` and not a `u64`
    /// These structs both WRITE v2 documents and READ documents that may be v1, and the two
    /// versions disagree about whether the field exists. A `u64` with a serde default would
    /// turn "this map never recorded where the part goes" into "this part goes first" — a
    /// claim nobody made, indistinguishable at the type level from one somebody did, and
    /// wrong for every part after the first. `Option` makes absence representable, so the
    /// decision about when absence is legal is taken in exactly one place
    /// ([`RecoveryManifest::from_json`]) instead of being smuggled in by a default.
    ///
    /// The payoff lands on the recovery tool. After a successful parse, `None` here means
    /// precisely "this map cannot tell you where this part goes" — RECOVERY-MANIFEST.md §6's
    /// "a reader must treat its array order as a claim it has not yet verified" — and the
    /// compiler makes the tool confront that instead of reading a zero.
    ///
    /// ⚠ Do not sort an item's parts by this field. See the module docs.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub part_index: Option<u64>,
    /// Blob ID holding this part's NCF-3 stream, in [`Part::network_name`]'s own naming.
    pub blob_id: String,
    /// Plaintext byte length of this part.
    pub plaintext_len: u64,
    /// Which storage network holds `blob_id` — a NAME (`"walrus"`), never a code.
    ///
    /// A blob ID is only meaningful on the network that issued it, so this is what tells the
    /// standalone recovery tool whose aggregator to ask. Spelled as a word because whoever
    /// parses this document may be doing it years from now with none of our code beside them;
    /// a bare `1` would be unresolvable.
    ///
    /// `None` means Walrus — a fact rather than a fallback, since no other network has ever had
    /// an upload path (CRYPTO-FORMAT-NCF2.md §6). Use [`Part::network_name`] rather than
    /// unwrapping, so that assumption stays written down in exactly one place.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub network: Option<String>,
    /// On-chain Sui object ID of this part's blob, when the writing client captured it.
    ///
    /// Not needed to READ a blob (aggregators serve by blob ID), so recovery never depends
    /// on it — it is here so the standalone tool can inspect or extend the blob's storage
    /// on-chain without an NMTS server to ask. Absent for parts written before the client
    /// started recording it.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub sui_object_id: Option<String>,
}

/// The network name a manifest written before the `network` field implies.
///
/// Every such part is on Walrus by construction: it was the only network NMTS could write to.
pub const NETWORK_WHEN_UNRECORDED: &str = "walrus";

impl Part {
    /// The storage network holding this part, resolving an absent field to [`NETWORK_WHEN_UNRECORDED`].
    ///
    /// The recovery tool should route every fetch through this rather than reading `network`
    /// directly — an older manifest simply omits the field, and that must not read as "unknown".
    pub fn network_name(&self) -> &str {
        self.network.as_deref().unwrap_or(NETWORK_WHEN_UNRECORDED)
    }
}

/// Optional quilt placement, present iff the item was stored via a quilt batch.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Quilt {
    /// The quilt's Walrus blob ID.
    pub quilt_blob_id: String,
    /// The patch ID identifying this item within the quilt.
    pub patch_id: String,
}

/// A single recoverable item (file).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Item {
    /// NMTS item id (informational; a UUID string).
    pub id: String,
    /// Plaintext item name (safe: the whole manifest is encrypted).
    pub name: String,
    /// Logical path, e.g. `/folder/sub`.
    pub path: String,
    /// Total plaintext bytes across all parts.
    pub size: u64,
    /// Per-file data-encryption key, base64url of 32 bytes.
    pub dek: String,
    /// Item kind (e.g. `"file"`).
    pub kind: String,
    /// SHA-256 of the whole plaintext file, base64url of 32 RAW bytes.
    ///
    /// The live drive stores this hash SEALED (`nmts/v3/content-hash`) so the server cannot
    /// use it as a cross-account fingerprint. Inside a manifest that precaution is redundant —
    /// the entire document is already one envelope — so it is carried in the clear, which is
    /// what lets the standalone recovery tool verify a reassembled file WITHOUT re-deriving
    /// the account's sealing key. Absent for items committed before content hashes existed.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub content_hash: Option<String>,
    /// Ordered parts; single-part files have exactly one entry.
    pub parts: Vec<Part>,
    /// Quilt placement, present only when stored via a quilt.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub quilt: Option<Quilt>,
}

impl Item {
    /// Whether the parts' `plaintext_len`s sum to exactly this item's `size`.
    ///
    /// RECOVERY-MANIFEST.md §2 makes the equality a writer MUST and a reader MAY, and this is
    /// the reader's half — offered as a question rather than imposed as a parse failure,
    /// because the two sides are not in the same position. A writer is holding a `size` copied
    /// out of the account's own SEALED file list next to a part list the storage layer served,
    /// has fetched no blob, and can still rebuild: for it, this arithmetic is the whole defence
    /// against a dropped tail or an inflated length, and it can act on the answer. A reader is
    /// in a recovery, is about to fetch every part anyway, and will compare each
    /// `plaintext_len` against the part's own SEALED header — a strictly stronger check on the
    /// same numbers (§2.1 steps 3–4). Refusing the document on the weaker one would cost a
    /// person every other file in it for a fact they were about to establish properly.
    ///
    /// Summed in `u128` so a hostile list of lengths cannot wrap around into agreement.
    pub fn parts_add_up(&self) -> bool {
        self.parts_plaintext_total() == u128::from(self.size)
    }

    /// The parts' `plaintext_len`s, summed without wrapping.
    fn parts_plaintext_total(&self) -> u128 {
        self.parts.iter().map(|p| u128::from(p.plaintext_len)).sum()
    }
}

/// The recovery manifest document (RECOVERY-MANIFEST.md §2).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecoveryManifest {
    /// Format version — [`MANIFEST_VERSION`] for anything this crate writes.
    ///
    /// Read on the way in: it is what decides whether a part may omit its `part_index`, so a
    /// parser that ignored it would accept an NRM-2 document stripped of every placement and
    /// call it an old map (RECOVERY-MANIFEST.md §6).
    pub v: u32,
    /// Monotonic per account, +1 for every manifest written (NRM §2). The recovery tool
    /// picks the HIGHEST `seq` it can reach as the authoritative index.
    ///
    /// Defaults to 0 when parsing a document that predates the chain fields; 0 therefore
    /// means "unordered/unknown", never "the first one" (real manifests start at 1).
    #[serde(default)]
    pub seq: u64,
    /// Walrus blob ID of the manifest this one supersedes — `null` for the first.
    ///
    /// Always serialized (including as `null`) so the chain link is visibly absent rather
    /// than missing: a reader must be able to tell "this is the oldest manifest" apart from
    /// "this writer did not implement chaining".
    #[serde(default)]
    pub prev_manifest_blob_id: Option<String>,
    /// RFC 3339 timestamp of generation.
    pub generated_at: String,
    /// The account's public `accountId`, base64url.
    pub account_id: String,
    /// Every recoverable item.
    pub items: Vec<Item>,
}

impl RecoveryManifest {
    /// Serializes to canonical JSON bytes.
    ///
    /// Refuses a document a reader would have to refuse, and additionally refuses one that
    /// breaks a rule RECOVERY-MANIFEST.md §2 puts on writers only:
    ///
    /// * part placement — the same check [`Self::from_json`] performs, so this crate can never
    ///   seal a map it would then decline to open;
    /// * `size` against the sum of the parts' `plaintext_len` — a writer MUST refuse an item
    ///   where those disagree. It is asymmetric on purpose: see [`Item::parts_add_up`] for why
    ///   a reader is offered the same question instead of being stopped by it.
    pub fn to_json(&self) -> Result<Vec<u8>, ManifestError> {
        self.check_part_placement()?;
        for item in &self.items {
            if !item.parts_add_up() {
                return Err(ManifestError::PartsDoNotAddUp {
                    item_id: item.id.clone(),
                    size: item.size,
                    parts: item.parts.len(),
                    held: item.parts_plaintext_total(),
                });
            }
        }
        Ok(serde_json::to_vec(self)?)
    }

    /// Parses from JSON bytes, enforcing the reader's placement obligation.
    pub fn from_json(bytes: &[u8]) -> Result<Self, ManifestError> {
        let manifest: Self = serde_json::from_slice(bytes)?;
        manifest.check_part_placement()?;
        Ok(manifest)
    }

    /// The one place that decides when a missing or disagreeing `part_index` is legal.
    ///
    /// Two rules, and they refuse for two different reasons:
    ///
    /// 1. **Any version — a stated `part_index` must equal its own position.** A document that
    ///    contradicts itself cannot be acted on, and picking one of the two numbers to believe
    ///    would be inventing an answer on the reader's behalf.
    /// 2. **From [`MANIFEST_VERSION_WITH_PART_INDEX`] — it must be stated at all.** The version
    ///    marker is the whole reason the field's absence carries information: in an NRM-1 map a
    ///    part has no index and the reader simply has nothing to check the order against, while
    ///    in a map that calls itself NRM-2 a part without one is an altered document rather
    ///    than an old one. Refusing it is what stops stripping the field from being a silent
    ///    downgrade to NRM-1's guarantees (RECOVERY-MANIFEST.md §6).
    ///
    /// The comparison is positional and stays positional. ⛔ Do not sort first — see the module
    /// docs for what that costs.
    ///
    /// Note what this does NOT establish: that the blob listed at position `i` really holds
    /// part `i`. Nothing in a JSON document can — only fetching the part and checking its
    /// SEALED NCF-3 header does (RECOVERY-MANIFEST.md §2.1 step 3). `part_index` is recorded so
    /// that check has something to be compared against instead of bare array order.
    fn check_part_placement(&self) -> Result<(), ManifestError> {
        let placement_required = self.v >= MANIFEST_VERSION_WITH_PART_INDEX;
        for item in &self.items {
            for (position, part) in item.parts.iter().enumerate() {
                match part.part_index {
                    // Compared in the array's own index space: a `part_index` too large to BE
                    // a position cannot equal one, and saying it that way needs no lossy cast
                    // in either direction.
                    Some(stated) if usize::try_from(stated).is_ok_and(|at| at == position) => {}
                    Some(stated) => {
                        return Err(ManifestError::PartIndexMisplaced {
                            item_id: item.id.clone(),
                            position,
                            stated,
                        })
                    }
                    None if placement_required => {
                        return Err(ManifestError::PartIndexMissing {
                            item_id: item.id.clone(),
                            position,
                            v: self.v,
                        })
                    }
                    None => {}
                }
            }
        }
        Ok(())
    }

    /// Encrypts the manifest as a single envelope under `data_key` (§1, single-envelope).
    pub fn encrypt(&self, data_key: &[u8; 32]) -> Result<Vec<u8>, ManifestError> {
        let json = Zeroizing::new(self.to_json()?);
        Ok(wrap::seal(data_key, AAD_RECOVERY_MAP, &json))
    }

    /// Decrypts a single-envelope manifest under `data_key`.
    ///
    /// Rejects chunk-framed input (leading NCF-3 magic) to enforce the single-envelope
    /// rule — a manifest must never be a stream.
    pub fn decrypt(data_key: &[u8; 32], envelope: &[u8]) -> Result<Self, ManifestError> {
        if envelope.len() >= MAGIC.len() && envelope[..MAGIC.len()] == MAGIC {
            return Err(ManifestError::NotSingleEnvelope);
        }
        let json = Zeroizing::new(wrap::open(data_key, AAD_RECOVERY_MAP, envelope)?);
        Self::from_json(&json)
    }
}

// ---------------------------------------------------------------------------------------
// Deterministic manifest envelope — VECTORS ONLY.
// ---------------------------------------------------------------------------------------

/// Encrypts a manifest with a caller-supplied nonce, for conformance vectors only.
#[cfg(any(test, feature = "vectors"))]
pub fn encrypt_with_nonce(
    manifest: &RecoveryManifest,
    data_key: &[u8; 32],
    nonce: &[u8; wrap::ENVELOPE_NONCE_LEN],
) -> Result<Vec<u8>, ManifestError> {
    let json = manifest.to_json()?;
    Ok(wrap::seal_with_nonce(
        data_key,
        nonce,
        AAD_RECOVERY_MAP,
        &json,
    ))
}
