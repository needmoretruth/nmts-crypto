//! What a recovery list says about ITSELF (`docs/RECOVERY-MANIFEST.md` §2.3). Moved out of
//! `manifest.rs` unchanged when NRM-5 needed the room; the types are re-exported there.

use serde::{Deserialize, Serialize};

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
/// # ⛔ Its presence does not move [`MANIFEST_VERSION`](super::MANIFEST_VERSION)
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
