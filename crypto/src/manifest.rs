//! Recovery manifest (NRM-3, `docs/RECOVERY-MANIFEST.md`): the encrypted index that makes
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
//! # Where the manifest itself lives (NRM-3, 2026-08-17)
//! A manifest is written in two places and they are not the same document twice. The FILE a
//! person downloads is built after an upload has finished, so every blob it names exists. The
//! STORAGE-NETWORK copy is written INTO the quilt whose files it describes, before that quilt has
//! a blob id — a quilt's id is a hash of its contents, this document included, so there is no
//! fixed point to wait for. NRM-3 adds the one form that makes that expressible: an item may say
//! "my patch is called X, in the quilt you found this document in" ([`Placement::OwnQuilt`]).
//!
//! ⚠ That form is only meaningful to a reader that got the document out of a quilt. A copy
//! extracted to a file cannot resolve it, and this crate says so rather than guessing.
//!
//! [`minimum_version`] is what a writer stamps, so a document that uses no v3 form is still a v2
//! document and every recovery tool already in circulation goes on reading it.
//!
//! # Part placement (NRM-2)
//! Every part of every item carries a `part_index` saying where it belongs, and this module
//! refuses a v2 document whose parts do not each sit at the position they claim
//! (RECOVERY-MANIFEST.md §2.1). The field exists because array order alone cannot be
//! CHECKED: the list is built from the storage layer's own dump, the builder never fetches a
//! blob, so before NRM-2 a list that listed a file's parts in the wrong order read exactly
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
//! (this crate parses it, and the web unit tests assert their builder emits exactly it);
//! `nrm3-sample.json` does the same for the own-quilt form, and `nrm1-sample.json` is kept beside
//! them so the older documents stay parseable rather than merely believed to be.
//! Optional fields (`quilt`, `content_hash`, `sui_object_id`, `network`) are omitted when absent
//! so byte output stays canonical; `prev_manifest_blob_id` is the deliberate exception (see below).

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::framing::MAGIC;
use crate::wrap::{self, WrapError, AAD_RECOVERY_MAP};

/// The newest manifest format version (`"v"` field) this crate writes and understands.
///
/// Raised 1 → 2 on 2026-07-29 when `part_index` became required on every part, 2 → 3 on
/// 2026-08-17 when [`Quilt`] gained the own-quilt placement (`docs/RECOVERY-MANIFEST.md` §6),
/// and 3 → 4 on 2026-08-18 when a part could say it was PADDED ([`Part::padded_len`]).
/// Each number moved for a single additive form so that the form's ABSENCE means something: see
/// [`MANIFEST_VERSION_WITH_PART_INDEX`], [`MANIFEST_VERSION_WITH_OWN_QUILT`] and
/// [`MANIFEST_VERSION_WITH_PADDING`].
///
/// ⚠ **A writer stamps [`minimum_version`], not this.** See that function for why.
pub const MANIFEST_VERSION: u32 = 4;

/// The first NRM version in which `part_index` is required on every part.
///
/// Written as its own constant rather than as `MANIFEST_VERSION`, because the two answer
/// different questions and will stop being equal at the next bump: this one is "from which
/// version does an absent `part_index` mean a tampered document rather than an old one", and
/// the answer stays `2` however far the format version travels past it.
pub const MANIFEST_VERSION_WITH_PART_INDEX: u32 = 2;

/// The first NRM version in which [`Quilt`] may carry the own-quilt placement.
pub const MANIFEST_VERSION_WITH_OWN_QUILT: u32 = 3;

/// The first NRM version in which a part may carry [`Part::padded_len`].
///
/// The marker is what makes the field's absence mean "this part was not padded" rather than
/// "this writer did not record it". Strip the field from a v4 document and the reader stops on
/// the sealed header instead of quietly handing back padding as file content.
pub const MANIFEST_VERSION_WITH_PADDING: u32 = 4;

/// The lowest `v` a document holding these items may honestly declare.
///
/// # Why a writer stamps this instead of [`MANIFEST_VERSION`]
/// People already hold copies of the standalone recovery program, and a build only knows the
/// forms that existed when it was made. A document stamped `v: 3` for no reason other than the
/// calendar would be refused — or, worse, read cautiously — by a tool that would have understood
/// every byte of it. Stamping the version the CONTENT actually needs means a `.nmtsmap` file
/// saved today is still a v2 document unless it uses a v3 form, and every tool ever shipped goes
/// on reading it.
///
/// In practice only the storage-network copy reaches v3, because it is the only document written
/// before its own quilt existed. The file a person downloads is built from a finished upload, so
/// every placement in it is absolute.
pub fn minimum_version(items: &[Item]) -> u32 {
    let padded = items
        .iter()
        .flat_map(|item| item.parts.iter())
        .any(|part| part.padded_len.is_some());
    let own_quilt = items
        .iter()
        .filter_map(|item| item.quilt.as_ref())
        .any(|q| q.identifier.is_some());
    if padded {
        MANIFEST_VERSION_WITH_PADDING
    } else if own_quilt {
        MANIFEST_VERSION_WITH_OWN_QUILT
    } else {
        MANIFEST_VERSION_WITH_PART_INDEX
    }
}

// ---------------------------------------------------------------------------------------
// Where the manifest sits on the storage network (NCF-3 §2.3, RECOVERY-MANIFEST.md §7)
// ---------------------------------------------------------------------------------------

/// Hash domain separator for the manifest's quilt patch name.
pub const HASH_RECOVERY_NAME: &[u8] = b"nmts/v3/recovery-name";

/// Bytes of the fingerprint that become the patch name. 122 bits survive the UUID bits below.
const RECOVERY_PATCH_NAME_LEN: usize = 16;

/// The name a manifest is stored under inside a quilt, derived from the account's `dataKey`.
///
/// # Why a name has to be derived at all
/// A blob id on Walrus is computed from the blob's own bytes, so nothing can predict one from an
/// account code — it changes every time the drive does, and it is not ours to choose. What IS
/// ours to choose is the *identifier* each patch carries inside a quilt. Deriving that identifier
/// from `dataKey` gives the one property the whole "recover with the account code alone" path
/// needs: a tool holding the code can compute the exact name to ask an aggregator for, and can do
/// it before it has ever seen the account's data.
///
/// # Why it is derived rather than a fixed word
/// A constant like `nmts-recovery-list` would work identically for recovery and would also let
/// anyone reading public storage pick NMTS accounts out of the crowd — patch identifiers travel
/// in the clear inside a quilt's index. Deriving it means the name is unguessable to everyone who
/// does not already hold the key that opens the document the name points at.
///
/// # Why it looks like a UUID
/// Every other patch in the same quilt is identified by a random v4 UUID (the upload path's
/// per-item client id). A 22-character base64url string beside them would announce itself as the
/// odd one out and undo the paragraph above, so the fingerprint is rendered in the same shape,
/// version and variant bits included. This costs six bits of the 128; matching a *specific*
/// account's name still means finding a preimage of a 122-bit value, which is not an attack.
///
/// # What this does NOT hide
/// The blob object holding the quilt is owned by the wallet that paid for it, and that wallet is
/// derived from the same account code (§1.3). Anyone who already knows an account's wallet
/// address can therefore see how many quilts it holds and when — this name hides *which patch is
/// the manifest*, not *that the account exists*.
pub fn recovery_patch_name(data_key: &[u8; 32]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(HASH_RECOVERY_NAME);
    hasher.update(data_key);
    let digest = hasher.finalize();
    let mut b = [0u8; RECOVERY_PATCH_NAME_LEN];
    b.copy_from_slice(&digest[..RECOVERY_PATCH_NAME_LEN]);
    // RFC 9562 §4.4: version in the high nibble of byte 6, variant in the top bits of byte 8.
    // Set so the value is indistinguishable from the random UUIDs beside it in the quilt index.
    b[6] = (b[6] & 0x0f) | 0x40;
    b[8] = (b[8] & 0x3f) | 0x80;
    let hex: String = b.iter().map(|byte| format!("{byte:02x}")).collect();
    format!(
        "{}-{}-{}-{}-{}",
        &hex[0..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..32]
    )
}

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
    /// A `quilt` record was neither of the two placements NRM-3 defines, or was both at once.
    ///
    /// The two forms answer different questions and a reader cannot be left to guess which was
    /// meant: `{quilt_blob_id, patch_id}` names a quilt anywhere on the network, while
    /// `{identifier}` means "the quilt this document itself was read out of". A record carrying
    /// pieces of both, or neither, is not a placement.
    #[error("item {item_id}: the quilt record is neither an absolute placement nor an own-quilt one")]
    QuiltFormUnclear {
        /// The item's NMTS id.
        item_id: String,
    },
    /// A document older than NRM-3 used the own-quilt placement.
    ///
    /// Same reasoning as [`Self::PartIndexMissing`]: the version marker is what makes a form's
    /// presence mean something, and a v2 document that quietly uses a v3 form is an altered one.
    #[error("item {item_id}: an own-quilt placement needs v{needed}, but the document says v{v}")]
    OwnQuiltTooOld {
        /// The item's NMTS id.
        item_id: String,
        /// The `v` the document declared.
        v: u32,
        /// The first version in which the form exists.
        needed: u32,
    },
    /// A part carried no `blob_id` and its item is not placed in the document's own quilt.
    ///
    /// Absence is legal in exactly one situation — the bytes are in the quilt this document was
    /// read from, whose id the document cannot contain — and anywhere else it is a part with no
    /// address at all.
    #[error("item {item_id}: the part at position {position} has no blob_id and no own-quilt placement")]
    BlobIdMissing {
        /// The item's NMTS id.
        item_id: String,
        /// Position in the item's `parts` array.
        position: usize,
    },
    /// An own-quilt item did not consist of exactly one part carrying no `blob_id`.
    ///
    /// A quilted item is one patch inside one blob, so it has exactly one part; and that part
    /// cannot also name a blob, because the whole meaning of the form is that the writer did not
    /// yet know which blob it would be. Either mistake is a contradiction, and resolving a
    /// contradiction on the reader's behalf is how a wrong file gets written confidently.
    #[error("item {item_id}: an own-quilt item must be exactly one part with no blob_id, found {parts} part(s){}", if *.blob_id_present { " naming a blob" } else { "" })]
    OwnQuiltPartsWrong {
        /// The item's NMTS id.
        item_id: String,
        /// How many parts the item listed.
        parts: usize,
        /// Whether one of them also carried a `blob_id`.
        blob_id_present: bool,
    },
    /// A document older than NRM-4 carried a part with `padded_len`.
    ///
    /// Same reasoning as [`Self::OwnQuiltTooOld`]: the version marker is what makes the form's
    /// presence mean something. Reading padding out of a document that predates padding would be
    /// believing a field the writer of that document never wrote.
    #[error("item {item_id}: the part at position {position} records padding, which needs v{needed}, but the document says v{v}")]
    PaddingTooOld {
        /// The item's NMTS id.
        item_id: String,
        /// Position in the item's `parts` array.
        position: usize,
        /// The `v` the document declared.
        v: u32,
        /// The first version in which the form exists.
        needed: u32,
    },
    /// A part's `padded_len` was not larger than its `plaintext_len`.
    ///
    /// The field exists to say "the sealed stream is bigger than the bytes this part
    /// contributes". Equal is not padding and must be written as absence, so that the canonical
    /// bytes of two identical lists cannot differ; smaller is a stream that could not hold the
    /// part at all. Both are contradictions, and neither has a reading a parser may pick.
    #[error("item {item_id}: the part at position {position} says it contributes {plaintext_len} bytes out of a padded {padded_len}")]
    PaddingNotLarger {
        /// The item's NMTS id.
        item_id: String,
        /// Position in the item's `parts` array.
        position: usize,
        /// The real bytes the part claims to contribute.
        plaintext_len: u64,
        /// The padded length it claims the sealed stream declares.
        padded_len: u64,
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
    /// turn "this list never recorded where the part goes" into "this part goes first" — a
    /// claim nobody made, indistinguishable at the type level from one somebody did, and
    /// wrong for every part after the first. `Option` makes absence representable, so the
    /// decision about when absence is legal is taken in exactly one place
    /// ([`RecoveryManifest::from_json`]) instead of being smuggled in by a default.
    ///
    /// The payoff lands on the recovery tool. After a successful parse, `None` here means
    /// precisely "this list cannot tell you where this part goes" — RECOVERY-MANIFEST.md §6's
    /// "a reader must treat its array order as a claim it has not yet verified" — and the
    /// compiler makes the tool confront that instead of reading a zero.
    ///
    /// ⚠ Do not sort an item's parts by this field. See the module docs.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub part_index: Option<u64>,
    /// Blob ID holding this part's NCF-3 stream, in [`Part::network_name`]'s own naming.
    ///
    /// # Why this became an `Option` in NRM-3
    /// There is exactly one situation in which a writer cannot know it: the bytes are going into
    /// the same quilt this document is being written into, and a quilt's blob id is computed from
    /// its contents — including this document. The circle has no fixed point, so the placement is
    /// recorded as [`Quilt::identifier`] instead and the address is supplied by whoever fetched
    /// the document. Everywhere else absence is refused at parse time
    /// ([`ManifestError::BlobIdMissing`]), so a reader that has a `Some` here has one because the
    /// document really did name a blob.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub blob_id: Option<String>,
    /// Plaintext byte length of this part — the REAL bytes it contributes to the file.
    ///
    /// ⛔ This keeps its meaning when a part is padded: it is what the reader writes out, and
    /// what [`Item::parts_add_up`] sums against `size`. What the stored stream's own header
    /// says is [`Part::padded_len`], and the two are different numbers on purpose.
    pub plaintext_len: u64,
    /// What the stored stream's NCF-3 header declares, when the part was PADDED and that is
    /// larger than [`Part::plaintext_len`]. Absent means the part was not padded.
    ///
    /// # Why padding needs a field at all
    /// Size padding hides how big a file is from anyone who can see the stored bytes. It cannot
    /// be done by appending to the stored blob, because an NCF-3 header is **authenticated, not
    /// encrypted**: `plaintext_len` sits in the clear at offset 16 of a public Walrus object, so
    /// a reader of that blob would read the exact original length however much was tacked on
    /// afterwards. The padding therefore goes INTO the plaintext, before sealing — which makes
    /// the header's number the padded one, and leaves the real one with nowhere else to live.
    ///
    /// # Why not simply let `plaintext_len` be the padded number
    /// Because `size` is then unguarded. The reader's strongest arithmetic is
    /// [`Item::parts_add_up`] — the parts must sum to exactly the item's `size` — and it is what
    /// catches a `size` somebody edited in a list they got hold of. Fold padding into
    /// `plaintext_len` and that equality has to become "greater than or equal", which accepts
    /// any `size` at all below the real one: the file comes back truncated and nothing says so
    /// unless the item happens to carry a content hash. Keeping the two numbers apart means every
    /// check that existed before padding keeps its exact strength, and padding adds one more
    /// (`padded_len` must exceed `plaintext_len`, and the sealed header must equal `padded_len`).
    ///
    /// # What the reader does with it
    /// Checks the sealed header against [`Part::stream_plaintext_len`], decrypts the whole padded
    /// stream — every byte still authenticates — and keeps the first `plaintext_len` bytes. The
    /// discarded tail is never written and never hashed.
    ///
    /// ⚠ The SIZE of the padding is not checked against any rule. It is a user-visible choice
    /// (a coarser unit, or a number typed in), so a tool that enforced today's rule would refuse
    /// files padded under tomorrow's setting. What is checked is that the list and the sealed
    /// header agree, which is the part an attacker could otherwise move.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub padded_len: Option<u64>,
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
    /// What this part's SEALED NCF-3 header must declare: the padded length when the part was
    /// padded, and the real length otherwise.
    ///
    /// Readers should compare the header against this rather than against `plaintext_len`
    /// directly, so that "was this part padded" is decided in one place instead of at every
    /// comparison site.
    pub fn stream_plaintext_len(&self) -> u64 {
        self.padded_len.unwrap_or(self.plaintext_len)
    }

    /// The storage network holding this part, resolving an absent field to [`NETWORK_WHEN_UNRECORDED`].
    ///
    /// The recovery tool should route every fetch through this rather than reading `network`
    /// directly — an older manifest simply omits the field, and that must not read as "unknown".
    pub fn network_name(&self) -> &str {
        self.network.as_deref().unwrap_or(NETWORK_WHEN_UNRECORDED)
    }
}

/// Optional quilt placement, present iff the item was stored via a quilt batch.
///
/// # Two forms, one of which is new in NRM-3
/// * **Absolute** — `quilt_blob_id` + `patch_id`. Names a quilt anywhere on the network. This is
///   every placement a document built from the server's own dump can carry, because by then the
///   upload has finished and both values exist.
/// * **Own quilt** — `identifier` alone. Means "the quilt this document was read out of". It
///   exists because the storage-network copy of a manifest is written INTO the same quilt as the
///   files it is describing, and that quilt's blob id is a hash of its contents, this document
///   included. Without this form the network copy would always be one upload behind — and for
///   somebody who uploads once and never again, one upload behind is empty.
///
/// A record is exactly one of the two. [`Quilt::placement`] is the only way to read it, and
/// [`RecoveryManifest::from_json`] refuses anything that is neither.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Quilt {
    /// The quilt's Walrus blob ID. Absent in the own-quilt form.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub quilt_blob_id: Option<String>,
    /// The patch ID identifying this item within the quilt. Absent in the own-quilt form.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub patch_id: Option<String>,
    /// The patch's identifier inside the quilt this document was read from (NRM-3).
    ///
    /// A patch identifier is chosen by the writer before the quilt is encoded, which is precisely
    /// why it can be recorded when the patch id cannot: the patch id is derived from the quilt's
    /// blob id and the identifier is not.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub identifier: Option<String>,
}

/// Where an item's bytes are, as [`Quilt`] states it. Borrowed — no allocation to read a record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Placement<'a> {
    /// A quilt named outright.
    Absolute {
        /// The quilt's blob id.
        quilt_blob_id: &'a str,
        /// The patch id within it.
        patch_id: &'a str,
    },
    /// The quilt this document itself was read out of, patch named by its identifier.
    ///
    /// ⚠ A reader that did NOT get this document from a quilt cannot resolve this — the document
    /// is describing a place relative to where it was found. That is not a defect to work around
    /// with a guess; it is a document being read somewhere it cannot mean anything.
    OwnQuilt {
        /// The patch's identifier inside that quilt.
        identifier: &'a str,
    },
}

impl Quilt {
    /// Which of the two forms this record is, or `None` when it is neither.
    ///
    /// Callers reach the fields through this rather than reading them directly, so "exactly one
    /// form" is decided once instead of at every use site.
    pub fn placement(&self) -> Option<Placement<'_>> {
        match (
            self.quilt_blob_id.as_deref(),
            self.patch_id.as_deref(),
            self.identifier.as_deref(),
        ) {
            (Some(quilt_blob_id), Some(patch_id), None) => Some(Placement::Absolute {
                quilt_blob_id,
                patch_id,
            }),
            (None, None, Some(identifier)) => Some(Placement::OwnQuilt { identifier }),
            _ => None,
        }
    }
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
    /// When the file was created and last changed, RFC 3339 — carried so a recovery can write out
    /// a folder whose files still have their dates (`docs/RECOVERY-MANIFEST.md` §2).
    ///
    /// # ⚠ These are the only values in an item that nothing checks
    /// `name`, `size` and `dek` come out of a sealed file list; `parts` is constrained by `size`
    /// arithmetically. These two are simply what the storage layer said when the list was built.
    /// A reader may therefore STAMP them onto the files it writes — a wrong modification date
    /// costs nothing and a right one is most of what makes a restored folder usable — and must not
    /// order, compare, or decide anything with them. `seq` orders the chain, exactly as before.
    ///
    /// `None` on every document written before the fields existed, and on any file whose source
    /// did not record them.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub created_at: Option<String>,
    /// Last change, RFC 3339 — see [`Item::created_at`].
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub updated_at: Option<String>,
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

/// Where the bytes a document points at actually live.
///
/// Every field is optional and every field is a HINT. A blob id is only meaningful on the network
/// that issued it, and until this block existed a list said `"walrus"` and stopped there — so a
/// list from testnet and a list from mainnet were indistinguishable and the recovery program's
/// README carried that as a known limitation. `chain` is the half that was missing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct MetaStorage {
    /// Storage network family, the same word a part carries (`"walrus"`).
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub network: Option<String>,
    /// Which of that network's chains issued the ids — `"mainnet"` / `"testnet"`.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub chain: Option<String>,
    /// Read endpoints the writing build was using. The FIRST thing here to go stale, so a reader
    /// treats them as candidates beside its own defaults, never as instructions.
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub aggregators: Vec<String>,
    /// A JSON-RPC endpoint for looking up `sui_object_id`. Never needed to READ a blob.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub chain_rpc: Option<String>,
}

/// What a document claims to hold, beside what it actually holds.
///
/// ⛔ NOT an integrity check, and a reader must not treat a disagreement as tampering: the whole
/// document is one authenticated envelope, so nobody can edit `items` without the account code.
/// It is for a RE-IMPLEMENTATION — a parser written years from now against the format document,
/// which drops records it does not recognise, has no other way to notice it read 400 of 412 files.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct MetaTotals {
    /// How many items the writer placed.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub items: Option<u64>,
    /// The plaintext bytes those items add up to.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub bytes: Option<u64>,
}

/// What the document says about ITSELF (`docs/RECOVERY-MANIFEST.md` §2.3).
///
/// # Why it exists
/// A recovery list describes an account thoroughly and used to describe itself barely at all. The
/// person it is FOR is holding one file, years later, with no site to visit and no memory of what
/// wrote it: which program reads this, where is that program, where is the format written down,
/// and which chain do these addresses belong to were all unanswered. A few hundred bytes buys
/// every one of those answers, and the document is sealed, so they cost no privacy.
///
/// # ⚠ Every field is a claim, and every field is optional
/// A reader must never REQUIRE any of it. These are strings the writing build printed about
/// itself and about other programs; a URL can die and a repository can move. They save a person a
/// search — they never decide whether a recovery may proceed.
///
/// # ⛔ Its presence does not move [`MANIFEST_VERSION`]
/// Absence changes no meaning, so the builds already published read a document carrying it exactly
/// as they read one without it (the owner's compatibility rule: until a 1.0.0 exists, a format may run ahead of
/// the tools, but never in a way that makes a published build refuse a file it could read). This crate sets no `deny_unknown_fields`, which is what
/// makes that true rather than hoped for.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct Meta {
    /// Product name, e.g. `"NMTS"`.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub product: Option<String>,
    /// Where the product is.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub product_url: Option<String>,
    /// The product release that wrote this document.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub app_version: Option<String>,
    /// The standalone program that reads it, by its published name.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub tool: Option<String>,
    /// Where to get that program.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub tool_url: Option<String>,
    /// Where this format is written down, in a copy the reader can actually reach.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub spec_url: Option<String>,
    /// Which network and chain the addresses in this document belong to.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub storage: Option<MetaStorage>,
    /// What the document claims to hold — see [`MetaTotals`].
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub totals: Option<MetaTotals>,
}

/// The recovery manifest document (RECOVERY-MANIFEST.md §2).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecoveryManifest {
    /// Format version — [`MANIFEST_VERSION`] for anything this crate writes.
    ///
    /// Read on the way in: it is what decides whether a part may omit its `part_index`, so a
    /// parser that ignored it would accept an NRM-2 document stripped of every placement and
    /// call it an old list (RECOVERY-MANIFEST.md §6).
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
    /// What the document says about itself — see [`Meta`]. `None` on older documents, and never
    /// a reason to refuse one.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub meta: Option<Meta>,
    /// Every recoverable item.
    pub items: Vec<Item>,
}

impl RecoveryManifest {
    /// Serializes to canonical JSON bytes.
    ///
    /// Refuses a document a reader would have to refuse, and additionally refuses one that
    /// breaks a rule RECOVERY-MANIFEST.md §2 puts on writers only:
    ///
    /// * part placement and quilt placement — the same checks [`Self::from_json`] performs, so
    ///   this crate can never seal a list it would then decline to open;
    /// * the declared `v` against [`minimum_version`] — a document that uses a form its own
    ///   version does not admit is one this crate would refuse on the way back in;
    /// * padding — the same [`Self::check_padding`] both sides run;
    /// * `size` against the sum of the parts' `plaintext_len` — a writer MUST refuse an item
    ///   where those disagree. It is asymmetric on purpose: see [`Item::parts_add_up`] for why
    ///   a reader is offered the same question instead of being stopped by it.
    pub fn to_json(&self) -> Result<Vec<u8>, ManifestError> {
        self.check_part_placement()?;
        self.check_quilt_placement()?;
        self.check_padding()?;
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
        manifest.check_quilt_placement()?;
        manifest.check_padding()?;
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
    ///    marker is the whole reason the field's absence carries information: in an NRM-1 list a
    ///    part has no index and the reader simply has nothing to check the order against, while
    ///    in a list that calls itself NRM-2 a part without one is an altered document rather
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

    /// The one place that decides when a part may say it was padded.
    ///
    /// Two rules, mirroring [`Self::check_part_placement`]'s pair:
    ///
    /// 1. **The form needs its version.** `padded_len` in a document declaring less than
    ///    [`MANIFEST_VERSION_WITH_PADDING`] is an altered document, not an old one.
    /// 2. **It must be strictly larger than `plaintext_len`.** Equal is written as absence and
    ///    smaller is impossible; either way the document contradicts itself.
    ///
    /// ⛔ What is deliberately NOT checked: how much padding there is. The amount follows a
    /// setting a person can change, so a rule here would refuse files padded under a setting this
    /// build has not heard of. The list-versus-header agreement is what an attacker could move,
    /// and that is checked — in the reader, against the SEALED header, not here.
    fn check_padding(&self) -> Result<(), ManifestError> {
        let padding_allowed = self.v >= MANIFEST_VERSION_WITH_PADDING;
        for item in &self.items {
            for (position, part) in item.parts.iter().enumerate() {
                let Some(padded_len) = part.padded_len else { continue };
                if !padding_allowed {
                    return Err(ManifestError::PaddingTooOld {
                        item_id: item.id.clone(),
                        position,
                        v: self.v,
                        needed: MANIFEST_VERSION_WITH_PADDING,
                    });
                }
                if padded_len <= part.plaintext_len {
                    return Err(ManifestError::PaddingNotLarger {
                        item_id: item.id.clone(),
                        position,
                        plaintext_len: part.plaintext_len,
                        padded_len,
                    });
                }
            }
        }
        Ok(())
    }

    /// The one place that decides which quilt placement a document of this version may use.
    ///
    /// Four refusals, each for its own reason:
    ///
    /// 1. **A `quilt` record must be exactly one of the two forms.** Neither, or a mixture, is
    ///    not a placement, and choosing one on the reader's behalf invents an address.
    /// 2. **Own-quilt needs [`MANIFEST_VERSION_WITH_OWN_QUILT`].** The version marker is what
    ///    makes the form's presence mean something; a v2 document using a v3 form was altered.
    /// 3. **An own-quilt item is exactly one part carrying no `blob_id`.** A quilted item is one
    ///    patch in one blob, and the form's whole meaning is that the blob was not yet named.
    /// 4. **Every other part names a blob.** Absence is legal in one situation only, and that
    ///    situation is rule 3.
    fn check_quilt_placement(&self) -> Result<(), ManifestError> {
        let own_quilt_allowed = self.v >= MANIFEST_VERSION_WITH_OWN_QUILT;
        for item in &self.items {
            let own_quilt = match item.quilt.as_ref() {
                None => false,
                Some(quilt) => match quilt.placement() {
                    None => {
                        return Err(ManifestError::QuiltFormUnclear {
                            item_id: item.id.clone(),
                        })
                    }
                    Some(Placement::Absolute { .. }) => false,
                    Some(Placement::OwnQuilt { .. }) if !own_quilt_allowed => {
                        return Err(ManifestError::OwnQuiltTooOld {
                            item_id: item.id.clone(),
                            v: self.v,
                            needed: MANIFEST_VERSION_WITH_OWN_QUILT,
                        })
                    }
                    Some(Placement::OwnQuilt { .. }) => true,
                },
            };

            if own_quilt {
                let blob_id_present = item.parts.iter().any(|p| p.blob_id.is_some());
                if item.parts.len() != 1 || blob_id_present {
                    return Err(ManifestError::OwnQuiltPartsWrong {
                        item_id: item.id.clone(),
                        parts: item.parts.len(),
                        blob_id_present,
                    });
                }
                continue;
            }

            for (position, part) in item.parts.iter().enumerate() {
                if part.blob_id.is_none() {
                    return Err(ManifestError::BlobIdMissing {
                        item_id: item.id.clone(),
                        position,
                    });
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
