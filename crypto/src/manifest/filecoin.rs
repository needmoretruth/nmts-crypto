//! NRM-5 — a part stored on Filecoin (NMTS Heavy). `docs/RECOVERY-MANIFEST.md` §2.4.
//!
//! # What a Filecoin part carries that a Walrus part does not
//! A Walrus blob id is enough to fetch a Walrus part: any aggregator serves any blob. A Filecoin
//! piece is different in both halves. Its id (`blob_id`, a PieceCIDv2 such as `bafkzcib…`) names
//! the BYTES, not a place, and there is no public service that serves every piece — each piece is
//! served by the storage companies that keep it. So a Filecoin part also says:
//!
//! * `chain` — which Filecoin network (`"calibration"` or `"mainnet"`). The companies' current
//!   addresses are looked up in a contract on that chain when the recorded ones stop answering;
//! * `copies` — one entry per company keeping a whole copy: the company's on-chain number, the
//!   data set and piece numbers under which it proves it holds the piece, and the address it
//!   served the piece from when the list was written.
//!
//! # Why the version moved (NRM-5)
//! A reader written for NRM-4 treats every part as Walrus unless told otherwise, and a build that
//! does not know the word `"filecoin"` would hand the PieceCID to a Walrus aggregator and be told
//! "not found" — the same answer as a blob that expired, which is the wrong story and a lost file.
//! The version marker makes that build stop on the document instead, before a key is asked for.
//!
//! # ⛔ What is NOT checked here
//! That the PieceCID matches the bytes. The reader gets the part's NCF-3 stream from a company and
//! the stream authenticates itself against the file key (AEAD, key commitment, placement), so a
//! company that serves the wrong bytes is caught whatever the id says. Recomputing a piece
//! commitment would add a second check on the same bytes and a hash tree to every reader.

use std::fmt;

use serde::{Deserialize, Serialize};

use super::{ManifestError, Part, RecoveryManifest};

/// The first NRM version in which a part may be on Filecoin.
pub const MANIFEST_VERSION_WITH_FILECOIN: u32 = 5;

/// The network name a Filecoin part carries in `network`.
pub const NETWORK_FILECOIN: &str = "filecoin";

/// The Filecoin networks a part may name in `chain`.
pub const FILECOIN_CHAINS: [&str; 2] = ["calibration", "mainnet"];

/// The most copies one part may list. NMTS keeps two; the ceiling bounds what a reader tries.
pub const MAX_FILECOIN_COPIES: usize = 12;

/// How every PieceCIDv2 string begins: CIDv1, raw codec, the fr32-sha2-256-trunc254-padded
/// binary tree multihash, in base32. Checked so the id can be put in a URL path as it is.
pub const PIECE_CID_PREFIX: &str = "bafkzcib";

/// Longer than any PieceCIDv2 (the widest padding varint gives about 80 characters).
const MAX_PIECE_CID_LEN: usize = 128;

/// 2²⁵⁶ − 1 in decimal: the largest number a Solidity `uint256` holds.
const U256_MAX_DECIMAL: &str =
    "115792089237316195423570985008687907853269984665640564039457584007913129639935";

/// One storage company keeping a whole copy of a Filecoin part.
///
/// The three numbers are decimal STRINGS because the contract counts them as `uint256`, which
/// no JSON number type holds exactly.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FilecoinCopy {
    /// The company's number in the chain's provider registry.
    pub provider_id: String,
    /// The data set, at that company, whose proofs cover this piece.
    pub data_set_id: String,
    /// The piece's number inside that data set.
    pub piece_id: String,
    /// Where the company served the piece: `https://…/piece/<blob_id>`. A hint that can go
    /// stale — the registry on `chain` names the company's current address.
    pub retrieval_url: String,
}

/// Which NRM-5 rule a part broke. Carried by [`ManifestError::Filecoin`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FilecoinProblem {
    /// The part is on Filecoin, or carries `chain` or `copies`, in a document older than NRM-5.
    TooOld {
        /// The `v` the document declared.
        v: u32,
    },
    /// `chain` or `copies` on a part that is not on Filecoin.
    NotFilecoin,
    /// A Filecoin part inside a quilt. Quilts are Walrus's; a piece is stored on its own.
    InQuilt,
    /// No `chain`.
    ChainMissing,
    /// A `chain` that is not one of [`FILECOIN_CHAINS`].
    ChainUnknown(String),
    /// `blob_id` absent or not a PieceCIDv2 string.
    PieceCidMalformed,
    /// No `copies`.
    CopiesMissing,
    /// `copies` held this many entries, outside 1..=[`MAX_FILECOIN_COPIES`].
    CopiesCount(usize),
    /// A copy's number field is not a canonical decimal `uint256`.
    NumberMalformed {
        /// Position in `copies`.
        copy: usize,
        /// Which field.
        field: &'static str,
    },
    /// A copy's `retrieval_url` is not `https://<host>/…/piece/<blob_id>`.
    RetrievalUrlWrong {
        /// Position in `copies`.
        copy: usize,
    },
}

impl fmt::Display for FilecoinProblem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let needed = MANIFEST_VERSION_WITH_FILECOIN;
        match self {
            Self::TooOld { v } => write!(
                f,
                "uses a Filecoin form, which needs v{needed}, but the document says v{v}"
            ),
            Self::NotFilecoin => write!(f, "carries chain or copies but is not on filecoin"),
            Self::InQuilt => write!(f, "is on filecoin but its item is placed in a quilt"),
            Self::ChainMissing => write!(f, "is on filecoin and names no chain"),
            Self::ChainUnknown(c) => {
                write!(
                    f,
                    "names the filecoin chain {c:?}, not calibration or mainnet"
                )
            }
            Self::PieceCidMalformed => {
                write!(f, "is on filecoin and its blob_id is not a PieceCIDv2")
            }
            Self::CopiesMissing => write!(f, "is on filecoin and lists no copies"),
            Self::CopiesCount(n) => {
                write!(f, "lists {n} copies, outside 1..={MAX_FILECOIN_COPIES}")
            }
            Self::NumberMalformed { copy, field } => {
                write!(
                    f,
                    "has a copy {copy} whose {field} is not a decimal uint256"
                )
            }
            Self::RetrievalUrlWrong { copy } => write!(
                f,
                "has a copy {copy} whose retrieval_url is not https://…/piece/<blob_id>"
            ),
        }
    }
}

impl Part {
    /// The companies keeping this part, in the order a reader tries them. Empty off Filecoin.
    pub fn filecoin_copies(&self) -> &[FilecoinCopy] {
        self.copies.as_deref().unwrap_or_default()
    }
}

/// The one place that decides whether a part's Filecoin form is legal (both directions).
pub(super) fn check(m: &RecoveryManifest) -> Result<(), ManifestError> {
    for item in &m.items {
        for (position, part) in item.parts.iter().enumerate() {
            check_part(m.v, item.quilt.is_some(), part).map_err(|problem| {
                ManifestError::Filecoin {
                    item_id: item.id.clone(),
                    position,
                    problem,
                }
            })?;
        }
    }
    Ok(())
}

fn check_part(v: u32, quilted: bool, part: &Part) -> Result<(), FilecoinProblem> {
    let on_filecoin = part.network_name() == NETWORK_FILECOIN;
    let carries = part.chain.is_some() || part.copies.is_some();
    // The version first: in an older document every one of these forms is an alteration, and
    // saying "too old" is truer than naming whichever field happened to be looked at first.
    if (on_filecoin || carries) && v < MANIFEST_VERSION_WITH_FILECOIN {
        return Err(FilecoinProblem::TooOld { v });
    }
    if !on_filecoin {
        return if carries {
            Err(FilecoinProblem::NotFilecoin)
        } else {
            Ok(())
        };
    }
    if quilted {
        return Err(FilecoinProblem::InQuilt);
    }
    match part.chain.as_deref() {
        None => return Err(FilecoinProblem::ChainMissing),
        Some(c) if !FILECOIN_CHAINS.contains(&c) => {
            return Err(FilecoinProblem::ChainUnknown(c.to_string()))
        }
        Some(_) => {}
    }
    let cid = part
        .blob_id
        .as_deref()
        .filter(|c| is_piece_cid(c))
        .ok_or(FilecoinProblem::PieceCidMalformed)?;
    let copies = part.copies.as_ref().ok_or(FilecoinProblem::CopiesMissing)?;
    if copies.is_empty() || copies.len() > MAX_FILECOIN_COPIES {
        return Err(FilecoinProblem::CopiesCount(copies.len()));
    }
    for (copy, c) in copies.iter().enumerate() {
        for (field, value) in [
            ("provider_id", &c.provider_id),
            ("data_set_id", &c.data_set_id),
            ("piece_id", &c.piece_id),
        ] {
            if !is_u256_decimal(value) {
                return Err(FilecoinProblem::NumberMalformed { copy, field });
            }
        }
        if !is_retrieval_url(&c.retrieval_url, cid) {
            return Err(FilecoinProblem::RetrievalUrlWrong { copy });
        }
    }
    Ok(())
}

/// `bafkzcib` followed by lowercase base32 only — nothing a URL path would need to escape.
fn is_piece_cid(s: &str) -> bool {
    s.len() <= MAX_PIECE_CID_LEN
        && s.len() > PIECE_CID_PREFIX.len()
        && s.starts_with(PIECE_CID_PREFIX)
        && s.bytes()
            .all(|b| b.is_ascii_lowercase() || (b'2'..=b'7').contains(&b))
}

/// A canonical decimal `uint256`: digits only, no leading zero (except `"0"`), at most 2²⁵⁶ − 1.
///
/// Canonical because the three numbers are what a reader quotes back to a contract; two spellings
/// of one number would be two strings a tool has to decide are the same.
fn is_u256_decimal(s: &str) -> bool {
    if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) {
        return false;
    }
    if s.len() > 1 && s.starts_with('0') {
        return false;
    }
    // Equal-length digit strings compare as numbers.
    s.len() < U256_MAX_DECIMAL.len() || (s.len() == U256_MAX_DECIMAL.len() && s <= U256_MAX_DECIMAL)
}

/// `https://<host>…/piece/<cid>`: a host, no query or fragment, nothing a request line splits on.
fn is_retrieval_url(url: &str, cid: &str) -> bool {
    let Some(rest) = url.strip_prefix("https://") else {
        return false;
    };
    let host_ends = rest.find('/').unwrap_or(rest.len());
    host_ends > 0
        && rest
            .strip_suffix(cid)
            .is_some_and(|r| r.ends_with("/piece/"))
        && url
            .bytes()
            .all(|b| b.is_ascii_graphic() && b != b'?' && b != b'#')
}
