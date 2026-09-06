//! AI accounts — a tree of account codes, all recomputable from the top one (NCF-3 §1.5).
//!
//! # Purpose
//! Product rule of 2026-09-06: a person may create up to three *AI accounts* under
//! their account, and each of those up to three more — twelve in all. An AI account is an ordinary
//! NMTS account; the only thing that is different is where its 20 code bytes come from. They are
//! EXPANDED from the account above, not drawn from the CSPRNG, so the top code alone restores the
//! whole tree and nothing has to be written down beside it.
//!
//! ```text
//! aiAccountRoot    = HKDF-Expand(PRK, "nmts/v3/ai-account-root", 32)
//! aiAccountCode(N) = HKDF-Expand(aiAccountRoot, "nmts/v3/ai-account/" || dec(N), 20)  // N >= 1
//! ```
//!
//! # One-way, in the direction that matters
//! HKDF-Expand is not invertible and the child is handed the 20 OUTPUT bytes, never the root. So a
//! child's code says nothing about its parent's and nothing about a sibling's: handing an agent an
//! AI-account code hands it that sub-account and whatever hangs below it, and nothing else.
//!
//! # Why this is an ADDITION and not NCF-4
//! Nothing in §1 changes value. This is one more `HKDF-Expand` off the same `PRK`, under a label
//! §2.1 records as taken — the case §2 exists to arbitrate, applied the same way it was on
//! 2026-08-17 (§2.5).

use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::codes::{AccountCode, ACCOUNT_CODE_BYTES};
use crate::kdf::KdfError;

/// HKDF `info` label for the AI-ACCOUNT root (NCF-3 §1.5, added 2026-09-06).
///
/// The parent of the sub-account codes an account may create for an agent to hold. It hangs off the
/// account PRK for the same reason [`INFO_WALLET_ROOT`] does: held alone it yields AI-account codes
/// and nothing else — never `authSecret`, never `dataKey`.
pub const INFO_AI_ACCOUNT_ROOT: &[u8] = b"nmts/v3/ai-account-root";

/// HKDF `info` PREFIX for AI account number `N`: the full label is `nmts/v3/ai-account/N` with `N`
/// in decimal ASCII, no padding — the same rule as [`INFO_WALLET_PREFIX`], and deliberately NOT a
/// prefix of [`INFO_AI_ACCOUNT_ROOT`] (the boundary `wallet-root`/`wallet/` was named to avoid).
///
/// ⛔ Numbered from **1**, not 0. A parent restores its tree by walking `1..=n`; a code minted at
/// index 0 would be outside that walk and therefore unreachable from the only thing a person
/// keeps. [`ai_account_code_from_root`] refuses 0 rather than answering for it.
pub const INFO_AI_ACCOUNT_PREFIX: &str = "nmts/v3/ai-account/";

/// Byte length of the AI-account root.
pub const AI_ACCOUNT_ROOT_LEN: usize = 32;

/// The ACCOUNT CODE of AI account number `index` (1-based) from a 32-byte AI-account root.
///
/// # What this is (NCF-3 §1.5)
/// An AI account is an ordinary NMTS account: its 20 bytes go through [`derive_from_bytes`] like
/// any other code, so it has its own wallet root and its own AI-account root, and the tree carries
/// on downward under one rule. What is different is where those 20 bytes come from — they are
/// EXPANDED, not drawn from the CSPRNG, so a person holding only the top code can recompute every
/// code beneath it. Nothing has to be written down and nothing can be lost separately.
///
/// # One-way, in the direction that matters
/// HKDF-Expand is not invertible, so a child's code says nothing about the root that produced it
/// and nothing about its parent's code. Handing an agent one AI-account code therefore hands it
/// that sub-account and its own descendants — never the account above it, and never a sibling.
///
/// # Why 20 bytes and not a seed
/// The output IS the code, at the width [`crate::codes::ACCOUNT_CODE_BYTES`] fixes (160 bits), and
/// it is displayed by the same [`AccountCode`] encoder — one alphabet, one check symbol, one
/// normalizer. A separately-shaped child code would be a second thing to type and a second thing
/// to get wrong.
///
/// Refuses `index == 0`; see [`INFO_AI_ACCOUNT_PREFIX`].
pub fn ai_account_code_from_root(
    ai_account_root: &[u8; AI_ACCOUNT_ROOT_LEN],
    index: u32,
) -> Result<AccountCode, KdfError> {
    if index == 0 {
        return Err(KdfError::AiAccountIndexZero);
    }
    let info = format!("{INFO_AI_ACCOUNT_PREFIX}{index}");
    // from_prk cannot fail for a 32-byte PRK (>= HashLen), and expand cannot fail for a 20-byte
    // output — both bounds are compile-time constants here.
    let hk = Hkdf::<Sha256>::from_prk(ai_account_root).expect("ai-account root is 32 bytes");
    let mut bytes = Zeroizing::new([0u8; ACCOUNT_CODE_BYTES]);
    hk.expand(info.as_bytes(), &mut *bytes)
        .expect("HKDF expand length within bounds");
    Ok(AccountCode::from_bytes(*bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kdf::derive_from_bytes;

    /// ⛔ THE FIXED VECTOR FOR THE AI-ACCOUNT TREE (NCF-3 §1.5).
    ///
    /// These three strings were computed by an INDEPENDENT HKDF-SHA256 + Crockford implementation
    /// from the same root, not copied out of this code. A vector taken from the implementation it
    /// guards only pins today's behaviour to itself; this one would fail if the label, the output
    /// width, the decimal numbering or the encoder ever moved — and every code beneath an account
    /// would then be a different code, with no symptom but a tree that no longer restores.
    #[test]
    fn ai_account_codes_match_the_fixed_vector() {
        let root = [7u8; AI_ACCOUNT_ROOT_LEN];
        let expected = [
            (1u32, "FER3-YBVS-TMA9-MG5N-Z6SV-V727-Z8E9-KP4AM"),
            (2, "45QK-3KJJ-6XRZ-7GSZ-XTM4-4HFW-GWNV-GRG42"),
            (3, "3Z7F-99RM-VGDD-00D1-XXYM-RYNZ-J74F-MXGV8"),
        ];
        for (index, display) in expected {
            let code = ai_account_code_from_root(&root, index).expect("index >= 1");
            assert_eq!(code.display(), display, "ai account {index}");
            // It is an ORDINARY account code: it parses back, and it derives a whole account.
            let parsed = AccountCode::parse(display).expect("parses like any account code");
            assert_eq!(parsed.as_bytes(), code.as_bytes());
        }
    }

    #[test]
    fn an_ai_account_is_numbered_from_one_and_its_own_tree_hangs_off_it() {
        let parent = derive_from_bytes(&[9u8; ACCOUNT_CODE_BYTES]).expect("derivation");

        // 0 is refused rather than answered: a code there would be outside the parent's walk.
        assert_eq!(
            parent.ai_account_code_for(0),
            Err(KdfError::AiAccountIndexZero)
        );

        let children: Vec<_> = (1u32..=3)
            .map(|i| parent.ai_account_code_for(i).expect("index >= 1"))
            .collect();
        for (i, a) in children.iter().enumerate() {
            assert_ne!(
                a.as_bytes()[..],
                parent.ai_account_root[..],
                "child {i} must not be its own parent root"
            );
            for (j, b) in children.iter().enumerate().skip(i + 1) {
                assert_ne!(
                    a.as_bytes(),
                    b.as_bytes(),
                    "children {i} and {j} must differ"
                );
            }
        }

        // The grandchild comes from the CHILD's own root, reached by deriving the child's code —
        // one rule at every level, so a tree of any depth is walked by the same two calls.
        let child = derive_from_bytes(children[0].as_bytes()).expect("a child is an account");
        assert_ne!(child.account_id, parent.account_id);
        assert_ne!(child.ai_account_root[..], parent.ai_account_root[..]);
        let grandchild = child.ai_account_code_for(1).expect("index >= 1");
        assert_ne!(grandchild.as_bytes(), children[0].as_bytes());

        // Decimal ASCII with no padding, like the wallets: 10 is not 1 followed by a zero.
        assert_ne!(
            parent.ai_account_code_for(1).unwrap().as_bytes(),
            parent.ai_account_code_for(10).unwrap().as_bytes(),
        );
    }
}
