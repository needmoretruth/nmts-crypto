//! Public links (NCF-3 §5.8) — the five exports a browser needs to make, reopen and read one.
//!
//! ⛔ ITS OWN FILE BECAUSE `lib.rs` HAS A CEILING (`check:size`), as `openers` and `wallets` are.
//!
//! What crosses the boundary is exactly what the format stores or the link carries: the secret `S`
//! (it goes into the link's `#` fragment, so the page holds it anyway), the three 104-byte
//! envelopes, and an opened DEK for the stream decryptor.

use nmts_crypto::wrap;
use wasm_bindgen::{prelude::*, JsError};

use crate::convert::fixed;

/// A fresh 32-byte link secret `S`, drawn inside Rust from WebCrypto. One per link.
#[wasm_bindgen]
pub fn link_generate_secret() -> Vec<u8> {
    wrap::generate_link_secret()[..].to_vec()
}

/// Wraps a file DEK under a link secret: `E(S, "nmts/v3/link-wrap", DEK)`, 104 bytes. The server
/// stores the result beside the link's token.
#[wasm_bindgen]
pub fn link_wrap_dek(link_secret: &[u8], dek: &[u8]) -> Result<Vec<u8>, JsError> {
    let s: [u8; 32] = fixed(link_secret, "link_secret")?;
    let d: [u8; 32] = fixed(dek, "dek")?;
    Ok(wrap::wrap_dek_for_link(&s, &d))
}

/// Opens a link's wrapped DEK with the secret from the fragment, returning the 32-byte DEK.
#[wasm_bindgen]
pub fn link_unwrap_dek(link_secret: &[u8], wrapped: &[u8]) -> Result<Vec<u8>, JsError> {
    let s: [u8; 32] = fixed(link_secret, "link_secret")?;
    let dek = wrap::unwrap_dek_from_link(&s, wrapped).map_err(|e| JsError::new(&e.to_string()))?;
    Ok(dek[..].to_vec())
}

/// Seals a link secret under the uploader's dataKey: `E(dataKey, "nmts/v3/link-secret", S)`,
/// 104 bytes. Stored beside the link so the uploader can copy the same link again later.
#[wasm_bindgen]
pub fn link_seal_secret(data_key: &[u8], link_secret: &[u8]) -> Result<Vec<u8>, JsError> {
    let k: [u8; 32] = fixed(data_key, "data_key")?;
    let s: [u8; 32] = fixed(link_secret, "link_secret")?;
    Ok(wrap::seal_link_secret(&k, &s))
}

/// Opens a link secret sealed by `link_seal_secret`, returning the 32-byte `S`.
#[wasm_bindgen]
pub fn link_open_secret(data_key: &[u8], sealed: &[u8]) -> Result<Vec<u8>, JsError> {
    let k: [u8; 32] = fixed(data_key, "data_key")?;
    let s = wrap::open_link_secret(&k, sealed).map_err(|e| JsError::new(&e.to_string()))?;
    Ok(s[..].to_vec())
}
