//! Numbered share identities — more than one public code per NMTS key (NCF-3 §5.9).
//!
//! ⛔ ITS OWN FILE BECAUSE `lib.rs` HAS A CEILING (`check:size`). The five exports below are the
//!    numbered twins of `share_public_key`, the address in `kdf_derive`, `share_wrap_dek` and
//!    `share_unwrap_dek`, plus the one derivation a browser runs long after sign-in. Their names
//!    and shapes are what `deploy/wasm-conformance-identities.mjs` judges.
//!
//! Identity 0 is the public code every account already has: its seeds are `kdf_derive` bytes
//! 112..176 and 224..256, as before. Identities 1 and up come from `share_id_root` (`kdf_derive`
//! bytes 288..320) through [`share_id_seeds`], so a new public code is made without asking for the
//! NMTS key again. Every `index` argument is an identity's number and accepts 0, except
//! `share_id_seeds`, which refuses it: identity 0's seeds come from `kdf_derive` and nowhere else.
//!
//! ⚠ The index is taken as given. Seeds from one number under another number's index build a
//! bundle that verifies and an address nobody else computes, and an envelope opened under the
//! wrong number fails exactly like one meant for somebody else.

use nmts_crypto::{kdf, share};
use wasm_bindgen::{prelude::*, JsError};

use crate::convert::{canonical_item_id, fixed, js_int_u32};

/// Length of the [`share_id_seeds`] output: `kem(32) || auth(32) || sig(32)`.
pub const SHARE_ID_SEEDS_LEN: usize = 96;

/// The three secret seeds of share identity number `index` (1-based) from the 32-byte
/// `share_id_root` at `kdf_derive` bytes 288..320: `kem(32) || auth(32) || sig(32)`, 96 bytes.
///
/// ⛔ It takes the ROOT rather than the account code for the reason `wallet_seed_for` does: the
/// browser derives once at sign-in and keeps only the roots, and a person makes a new public code
/// whenever they like. Holding the root grants identities 1 and up and nothing else.
///
/// Rejects `index` 0. All 96 bytes are secret and stay inside the crypto worker, like the
/// `kdf_derive` regions they sit beside.
#[wasm_bindgen]
pub fn share_id_seeds(share_id_root: &[u8], index: f64) -> Result<Vec<u8>, JsError> {
    let root: [u8; 32] = fixed(share_id_root, "share_id_root")?;
    let n = js_int_u32(index, "index")?;
    let seeds = kdf::share_seeds_from_root(&root, n).map_err(|e| JsError::new(&e.to_string()))?;
    let mut out = Vec::with_capacity(SHARE_ID_SEEDS_LEN);
    out.extend_from_slice(&seeds.kem[..]);
    out.extend_from_slice(&seeds.auth[..]);
    out.extend_from_slice(&seeds.sig[..]);
    Ok(out)
}

/// The 4989-byte PUBLIC share identity number `index`: the bundle `share_public_key` builds, with
/// `derivation_index = index`. At index 0 it is `share_public_key`, byte for byte.
///
/// The number is inside the root, so each number has its own address; the self-signature covers
/// it, so a numbered bundle is verified by exactly the steps any bundle is.
#[wasm_bindgen]
pub fn share_public_key_at(
    share_kem_seed: &[u8],
    share_auth_secret: &[u8],
    share_sig_seed: &[u8],
    index: f64,
) -> Result<Vec<u8>, JsError> {
    let kem: [u8; 32] = fixed(share_kem_seed, "share_kem_seed")?;
    let auth: [u8; 32] = fixed(share_auth_secret, "share_auth_secret")?;
    let sig: [u8; 32] = fixed(share_sig_seed, "share_sig_seed")?;
    let n = js_int_u32(index, "index")?;
    Ok(share::public_key_at(&kem, &auth, &sig, n)
        .to_bytes()
        .to_vec())
}

/// The 16-byte share ADDRESS of identity number `index`, from its signing seed alone — no
/// signature is made to answer it. At index 0 it is `kdf_derive`'s `share_address` (208..224).
#[wasm_bindgen]
pub fn share_address_at(share_sig_seed: &[u8], index: f64) -> Result<Vec<u8>, JsError> {
    let sig: [u8; 32] = fixed(share_sig_seed, "share_sig_seed")?;
    let n = js_int_u32(index, "index")?;
    Ok(share::address_at(&sig, n).as_bytes().to_vec())
}

/// `share_wrap_dek` sending AS identity number `sender_index`: the two sender secrets are that
/// identity's, and the envelope's sender address is that identity's address.
///
/// Every other argument and every check is `share_wrap_dek`'s — the recipient key is checked
/// against `recipient_address` before anything is encrypted to it, the last three arguments are
/// the row the envelope is bound to, and fresh randomness is drawn per call. Returns the 1240-byte
/// share envelope.
// Nine arguments: `share_wrap_dek`'s eight, each load-bearing for the reason given there, and the
// sender's number.
#[allow(clippy::too_many_arguments)]
#[wasm_bindgen]
pub fn share_wrap_dek_as(
    sender_auth_secret: &[u8],
    sender_sig_seed: &[u8],
    sender_index: f64,
    recipient_public: &[u8],
    recipient_address: &[u8],
    dek: &[u8],
    item_id: &str,
    name_share_ct: &[u8],
    content_hash_share_ct: &[u8],
) -> Result<Vec<u8>, JsError> {
    let recipient = share::SharePublicKey::from_bytes(recipient_public)
        .map_err(|e| JsError::new(&e.to_string()))?;
    let auth: [u8; 32] = fixed(sender_auth_secret, "sender_auth_secret")?;
    let sig: [u8; 32] = fixed(sender_sig_seed, "sender_sig_seed")?;
    let n = js_int_u32(sender_index, "sender_index")?;
    let addr: [u8; 16] = fixed(recipient_address, "recipient_address")?;
    let d: [u8; 32] = fixed(dek, "dek")?;
    let id = canonical_item_id(item_id);
    let payload = share::SharePayload {
        item_id: id.as_bytes(),
        name_ct: name_share_ct,
        content_hash_ct: content_hash_share_ct,
    };
    share::wrap_dek_for_as(
        &auth,
        &sig,
        n,
        &recipient,
        &share::ShareAddress(addr),
        &d,
        &payload,
    )
    .map_err(|e| JsError::new(&e.to_string()))
}

/// `share_unwrap_dek` as identity number `index`, returning the 32-byte file DEK.
///
/// An envelope does not name its recipient, so the caller picks the number — the inbox knows
/// which address a share was stored against. Opened as the wrong number it fails with the same
/// message as an envelope meant for somebody else, a forged sender or a rewritten row.
// Nine arguments: `share_unwrap_dek`'s eight and the recipient's number.
#[allow(clippy::too_many_arguments)]
#[wasm_bindgen]
pub fn share_unwrap_dek_as(
    share_kem_seed: &[u8],
    share_auth_secret: &[u8],
    share_sig_seed: &[u8],
    index: f64,
    sender_public: &[u8],
    envelope: &[u8],
    item_id: &str,
    name_share_ct: &[u8],
    content_hash_share_ct: &[u8],
) -> Result<Vec<u8>, JsError> {
    let kem: [u8; 32] = fixed(share_kem_seed, "share_kem_seed")?;
    let auth: [u8; 32] = fixed(share_auth_secret, "share_auth_secret")?;
    let sig: [u8; 32] = fixed(share_sig_seed, "share_sig_seed")?;
    let n = js_int_u32(index, "index")?;
    let sender = share::SharePublicKey::from_bytes(sender_public)
        .map_err(|e| JsError::new(&e.to_string()))?;
    let id = canonical_item_id(item_id);
    let payload = share::SharePayload {
        item_id: id.as_bytes(),
        name_ct: name_share_ct,
        content_hash_ct: content_hash_share_ct,
    };
    let dek = share::unwrap_dek_as(&kem, &auth, &sig, n, &sender, envelope, &payload)
        .map_err(|e| JsError::new(&e.to_string()))?;
    Ok(dek[..].to_vec())
}
