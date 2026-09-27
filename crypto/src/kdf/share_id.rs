//! Numbered share identities — more than one public code per key (NCF-3 §5.9).
//!
//! # Purpose
//! Every account has identity 0: the three seeds [`super::derive_from_bytes`] expands straight off
//! `PRK`. An account may also publish identities 1, 2, 3…, each with its own three seeds and
//! therefore its own root and its own address. Those seeds hang off one sub-root per number, and
//! every sub-root hangs off one parent — the shape the wallets have (§1.3):
//!
//! ```text
//! shareIdRoot        = HKDF-Expand(PRK, "nmts/v3/share-id-root", 32)
//! R(0)               = PRK                                                  // identity 0, unchanged
//! R(N)               = HKDF-Expand(shareIdRoot, "nmts/v3/share-id/" || dec(N), 32)   // N >= 1
//! shareKemSeed(N)    = HKDF-Expand(R(N), "nmts/v3/share-kem",  32)
//! shareAuthSecret(N) = HKDF-Expand(R(N), "nmts/v3/share-auth", 32)
//! shareSigSeed(N)    = HKDF-Expand(R(N), "nmts/v3/share-sig",  32)
//! ```
//!
//! # Why the parent is the value a browser keeps
//! A browser does not keep `PRK` after sign-in. A person makes a new public code whenever they
//! like, long after the NMTS key was typed, and the numbers grow as codes are revoked, so they
//! cannot all be computed in advance. Keeping `shareIdRoot` is what lets the next number be made
//! without asking for the key again. Held alone it grants identities 1 and up and nothing else:
//! not identity 0 (whose seeds come from `PRK`), not `dataKey`, not a wallet.
//!
//! # Why the same three labels under a different root
//! The labels say what the 32 bytes are for and the root says whose — the rule §1.5 uses for
//! AI accounts. One rule at every number means no per-index special case. `R(N)` held alone grants
//! identity `N` and nothing else: HKDF-Expand is one-way, so it computes neither the parent nor
//! another number's root.
//!
//! # Why this is an ADDITION and not NCF-4
//! Identity 0 keeps `R(0) = PRK`, so no published key, address or envelope changes value. The
//! bundle has carried a `derivation_index` since §5.1, and no reader ever refused a non-zero one.
//! What is taken is one label and one label family, both recorded in §2.1.

use core::fmt;

use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::kdf::{
    KdfError, INFO_SHARE_AUTH, INFO_SHARE_KEM, INFO_SHARE_SIG, SHARE_AUTH_SECRET_LEN,
    SHARE_KEM_SEED_LEN, SHARE_SIG_SEED_LEN,
};

/// HKDF `info` label for the parent of every numbered share identity (NCF-3 §5.9, added
/// 2026-09-23).
///
/// It hangs off the account PRK for the same reason the wallet root does: held alone it yields
/// numbered identities and nothing else — never `authSecret`, never `dataKey`, never identity 0.
pub const INFO_SHARE_ID_ROOT: &[u8] = b"nmts/v3/share-id-root";

/// HKDF `info` PREFIX for the sub-root of share identity `N`: the full label is
/// `nmts/v3/share-id/N` with `N` in decimal ASCII, no padding — the wallets' rule, and deliberately
/// NOT a prefix of [`INFO_SHARE_ID_ROOT`] (it ends in `/`, the root in `-root`).
///
/// ⛔ Numbered from **1**, not 0. Identity 0 already exists under `R(0) = PRK`; a second road to
/// "identity 0" would be a second value for one published address. [`share_seeds_from_root`]
/// refuses 0 rather than answering for it.
pub const INFO_SHARE_ID_PREFIX: &str = "nmts/v3/share-id/";

/// Byte length of `shareIdRoot`, and of every sub-root `R(N)`.
pub const SHARE_ID_ROOT_LEN: usize = 32;

/// The three secrets of one share identity: what [`crate::share::public_key_at`] builds a bundle
/// from and what [`crate::share::unwrap_dek_as`] opens with.
///
/// Every field is zeroized on drop. Read them only for as long as needed.
pub struct ShareSeeds {
    /// The X-Wing decapsulation-key seed (`nmts/v3/share-kem` under the identity's root).
    pub kem: Zeroizing<[u8; SHARE_KEM_SEED_LEN]>,
    /// The X25519 sender-authentication scalar (`nmts/v3/share-auth` under the identity's root).
    pub auth: Zeroizing<[u8; SHARE_AUTH_SECRET_LEN]>,
    /// The ML-DSA-44 signing seed ξ (`nmts/v3/share-sig` under the identity's root). Its
    /// verification key, with the identity's number, is the root the address fingerprints.
    pub sig: Zeroizing<[u8; SHARE_SIG_SEED_LEN]>,
}

impl fmt::Debug for ShareSeeds {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ShareSeeds")
            .field("kem", &"<redacted>")
            .field("auth", &"<redacted>")
            .field("sig", &"<redacted>")
            .finish()
    }
}

/// The three seeds of share identity number `index` (1-based) from the 32-byte `shareIdRoot`.
///
/// Split out from [`super::DerivedKeys::share_seeds_for`] for the reason the wallet function is:
/// the browser derives keys once at sign-in and keeps only the parent, so a new public code made
/// later must come from the parent alone, without the NMTS key.
///
/// Refuses `index == 0` with [`KdfError::ShareIdIndexZero`]; see [`INFO_SHARE_ID_PREFIX`].
pub fn share_seeds_from_root(
    share_id_root: &[u8; SHARE_ID_ROOT_LEN],
    index: u32,
) -> Result<ShareSeeds, KdfError> {
    if index == 0 {
        return Err(KdfError::ShareIdIndexZero);
    }
    let info = format!("{INFO_SHARE_ID_PREFIX}{index}");
    // from_prk cannot fail for a 32-byte PRK (>= HashLen), and expand cannot fail for a 32-byte
    // output — both bounds are compile-time constants here.
    let parent = Hkdf::<Sha256>::from_prk(share_id_root).expect("share-id root is 32 bytes");
    let mut sub_root = Zeroizing::new([0u8; SHARE_ID_ROOT_LEN]);
    parent
        .expand(info.as_bytes(), &mut *sub_root)
        .expect("HKDF expand length within bounds");
    Ok(seeds_under(&sub_root))
}

/// The three labels of §5.1 expanded under one identity root `R(N)`, with `N >= 1`.
///
/// ⚠ Not used for identity 0. Its seeds are expanded off `PRK` inside `derive_from_bytes`, where
/// `PRK` exists only as an `Hkdf` state; routing them through here would add nothing but a second
/// place to read for the frozen values.
fn seeds_under(root: &[u8; SHARE_ID_ROOT_LEN]) -> ShareSeeds {
    let hk = Hkdf::<Sha256>::from_prk(root).expect("an identity root is 32 bytes");
    let mut seeds = ShareSeeds {
        kem: Zeroizing::new([0u8; SHARE_KEM_SEED_LEN]),
        auth: Zeroizing::new([0u8; SHARE_AUTH_SECRET_LEN]),
        sig: Zeroizing::new([0u8; SHARE_SIG_SEED_LEN]),
    };
    hk.expand(INFO_SHARE_KEM, &mut *seeds.kem)
        .expect("HKDF expand length within bounds");
    hk.expand(INFO_SHARE_AUTH, &mut *seeds.auth)
        .expect("HKDF expand length within bounds");
    hk.expand(INFO_SHARE_SIG, &mut *seeds.sig)
        .expect("HKDF expand length within bounds");
    seeds
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codes::ACCOUNT_CODE_BYTES;
    use crate::kdf::derive_from_bytes;

    #[test]
    fn identity_zero_is_the_seeds_the_account_already_has() {
        // R(0) = PRK: the numbered path at 0 must hand back the three frozen seeds unchanged, or
        // every published public code would move.
        let k = derive_from_bytes(&[9u8; ACCOUNT_CODE_BYTES]).expect("derivation");
        let zero = k.share_seeds_for(0);
        assert_eq!(*zero.kem, *k.share_kem_seed);
        assert_eq!(*zero.auth, *k.share_auth_secret);
        assert_eq!(*zero.sig, *k.share_sig_seed);
    }

    #[test]
    fn numbered_identities_start_at_one_and_are_unrelated_to_each_other() {
        let k = derive_from_bytes(&[9u8; ACCOUNT_CODE_BYTES]).expect("derivation");

        // 0 is refused by the sub-root function rather than answered by a second rule.
        assert_eq!(
            share_seeds_from_root(&k.share_id_root, 0).map(|_| ()),
            Err(KdfError::ShareIdIndexZero)
        );

        let all: Vec<ShareSeeds> = [0u32, 1, 2, 10]
            .iter()
            .map(|&i| k.share_seeds_for(i))
            .collect();
        for (i, a) in all.iter().enumerate() {
            for b in all.iter().skip(i + 1) {
                assert_ne!(*a.kem, *b.kem);
                assert_ne!(*a.auth, *b.auth);
                assert_ne!(*a.sig, *b.sig);
            }
            // Three labels under one root give three different values.
            assert_ne!(*a.kem, *a.auth);
            assert_ne!(*a.auth, *a.sig);
        }

        // The DerivedKeys door and the root-only door agree for every N >= 1.
        let from_root = share_seeds_from_root(&k.share_id_root, 2).expect("index >= 1");
        assert_eq!(*from_root.sig, *all[2].sig);

        // An independent HKDF over the documented labels: R(1), then the signing seed under it.
        let parent = Hkdf::<Sha256>::from_prk(&k.share_id_root[..]).expect("32 bytes");
        let mut r1 = [0u8; 32];
        parent
            .expand(b"nmts/v3/share-id/1", &mut r1)
            .expect("expand");
        let mut sig1 = [0u8; 32];
        Hkdf::<Sha256>::from_prk(&r1)
            .expect("32 bytes")
            .expand(b"nmts/v3/share-sig", &mut sig1)
            .expect("expand");
        assert_eq!(*all[1].sig, sig1);
    }
}
