//! Account / voucher codes and the recovery phrase (NCF-1 §1, §7) — the account lifecycle UI.
//!
//! Moved out of `lib.rs` on 2026-09-23 when the phrase joined (that file has a size ceiling).

use nmts_crypto::codes::{self, AccountCode};
use wasm_bindgen::{prelude::*, JsError};

use crate::convert::fixed;


/// Generates a fresh 160-bit account code and returns its display string
/// (`XXXX-XXXX-…-XXXXC`). The bytes never leave the worker except as this one-time string.
#[wasm_bindgen]
pub fn account_code_generate() -> String {
    AccountCode::generate().display()
}

/// Parses+validates a user-entered account code (any spacing/case) OR its 15-word recovery
/// phrase, returning the 20 raw bytes. Errors if the check symbol or the phrase's
/// checksum fails. A phrase error's message starts with `phrase:` (`phrase:count:12` ·
/// `phrase:word:5` · `phrase:checksum`) so a screen can say which one.
#[wasm_bindgen]
pub fn account_code_parse(input: &str) -> Result<Vec<u8>, JsError> {
    let c = nmts_crypto::parse_key_or_phrase(input).map_err(|e| JsError::new(&e.to_string()))?;
    Ok(c.as_bytes().to_vec())
}

/// The 15-word recovery phrase for 20 raw account-code bytes, in `en` or `ko`.
#[wasm_bindgen]
pub fn account_code_phrase(code_bytes: &[u8], lang: &str) -> Result<String, JsError> {
    let cb: [u8; 20] = fixed(code_bytes, "code_bytes")?;
    let language = nmts_crypto::PhraseLanguage::from_tag(lang)
        .ok_or_else(|| JsError::new("lang must be \"en\" or \"ko\""))?;
    Ok(AccountCode::from_bytes(cb).to_phrase(language))
}

/// The display string for a set of 20 raw account-code bytes.
#[wasm_bindgen]
pub fn account_code_display(code_bytes: &[u8]) -> Result<String, JsError> {
    let cb: [u8; 20] = fixed(code_bytes, "code_bytes")?;
    Ok(AccountCode::from_bytes(cb).display())
}

/// `SHA-256(normalize(input))` — the voucher redemption hash for arbitrary user input.
#[wasm_bindgen]
pub fn voucher_hash_from_input(input: &str) -> Vec<u8> {
    codes::voucher_hash_from_input(input).to_vec()
}
