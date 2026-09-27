//! Wallet keys from the wallet root (NCF-3 §1.4 Sui wallets · §1.9 EVM wallets).
//!
//! Moved out of `lib.rs` on 2026-09-24 when the EVM wallet joined (that file has a size ceiling).

use nmts_crypto::kdf;
use wasm_bindgen::{prelude::*, JsError};

use crate::convert::{fixed, js_int_u64};

/// Derives the Ed25519 seed for wallet number `index` from the 32-byte `wallet_root`.
///
/// EVERY wallet comes from here, including wallet 0. NCF-2 gave the first wallet its own
/// derivation off the account PRK because it already existed on chain and could not move; NCF-3
/// deletes that exception, so there is one rule and no index this function refuses.
#[wasm_bindgen]
pub fn wallet_seed_for(wallet_root: &[u8], index: f64) -> Result<Vec<u8>, JsError> {
    let root: [u8; 32] = fixed(wallet_root, "wallet_root")?;
    let n = js_int_u64(index, "index")?;
    let n = u32::try_from(n).map_err(|_| JsError::new("wallet index must fit in 32 bits"))?;
    Ok(kdf::wallet_seed_from_root(&root, n)[..].to_vec())
}

/// The secp256k1 private key (32 bytes, big-endian) of EVM wallet number `index` from the 32-byte
/// `wallet_root` (NCF-3 §1.9) — the key that pays for NMTS Heavy on Filecoin when a person pays
/// from their own EVM wallet.
///
/// ⛔ Like `wallet_seed_for`, this hands back key material. It is called in-process by the crypto
/// worker and by the command-line tool; no page-facing RPC returns it.
///
/// ⚠ The ADDRESS is deliberately not exported. Computing it needs the curve's point arithmetic,
/// which added 63 KB to a package every visitor downloads (measured 2026-09-24: 539,169 → 602,131
/// bytes; the key alone is 545,370) for a value no browser screen shows. The command-line tool and
/// the recovery tool compute the address themselves.
#[wasm_bindgen]
pub fn evm_key_for(wallet_root: &[u8], index: f64) -> Result<Vec<u8>, JsError> {
    let root: [u8; 32] = fixed(wallet_root, "wallet_root")?;
    let n = js_int_u64(index, "index")?;
    let n = u32::try_from(n).map_err(|_| JsError::new("wallet index must fit in 32 bits"))?;
    Ok(kdf::evm_key_from_root(&root, n)[..].to_vec())
}
