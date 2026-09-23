//! Openers — the NMTS key wrapped into a removable slot (NCF-3 §1.7).
//!
//! ⛔ ITS OWN FILE BECAUSE `lib.rs` HAS A CEILING (2026-09-20 · `check:size`). The four wallet
//!    exports and the four passkey exports (2026-09-23) below are the whole opener surface; their
//!    names and shapes are what `deploy/wasm-conformance-openers.mjs` judges.
//!
//! ⛔ THE WALLET EXPORTS TAKE THE SERIALIZED SIGNATURE, THE PASSKEY EXPORTS TAKE THE PRF RESULT,
//!    AND NONE OF THEM RETURNS EITHER. Those bytes and the 32-byte wrapping key are the account; an export that handed either back would
//!    put them in a JS value nothing can wipe, on the far side of the boundary the Rust crate
//!    zeroizes behind. So the answers are exactly what may travel: a locator, a sealed slot, and
//!    an opened NMTS key. (Review finding 2-B3, as an API shape rather than a sentence.)
//!
//! ⚠ NOT FROZEN, unlike the rest of this surface. A slot carries its own version byte and is
//!   re-wrapped at the next sign-in, so these values may be superseded —
//!   `docs/CRYPTO-FORMAT-NCF3.md` §1.7 says what that means and what stays true.

use nmts_crypto::opener;
use wasm_bindgen::{prelude::*, JsError};

use crate::convert::{fixed, js_int_u32};

/// The EXACT bytes a Sui wallet is asked to sign to open an NMTS account (NCF-3 §1.7). LF endings,
/// no trailing newline, ASCII.
///
/// ⛔ Built HERE rather than in JavaScript, and that is why this export exists at all: the browser,
/// the command line and the recovery tool must ask for the same bytes, and one character of drift
/// between them is a slot that no longer opens. One implementation, one message.
///
/// Throws when `address` is not `0x` + 64 LOWERCASE hex, when `account` is 0, or when `app` is not
/// 1–64 characters of `a-z0-9.-` starting and ending alphanumeric — and never repairs any of them,
/// because all three are inside the bytes a person reads in the wallet popup.
#[wasm_bindgen]
pub fn opener_message(
    address: &str,
    account: f64,
    app: Option<String>,
) -> Result<Vec<u8>, JsError> {
    let n = js_int_u32(account, "account")?;
    opener::opener_message(address, n, app.as_deref()).map_err(|e| JsError::new(&e.to_string()))
}

/// The 16-byte LOCATOR a wallet signature yields — the name the server files this opener's slot
/// under, and the name a sign-in asks for it back by (NCF-3 §1.7).
///
/// Accepts flag `0x00` Ed25519 (97 bytes), `0x01` secp256k1 and `0x02` secp256r1 (98). Refuses
/// `0x03` multisig, `0x05` zkLogin, `0x06` passkey, any other flag, and an accepted flag at the
/// wrong length — each with its own message, because the caller has to tell a person which one it
/// was and what to do instead.
///
/// ⚠ It does NOT verify the signature. Checking it against the address in the message is the
/// caller's step, with the Sui library.
#[wasm_bindgen]
pub fn opener_locator(serialized_signature: &[u8]) -> Result<Vec<u8>, JsError> {
    let opener = opener::opener_from_signature(serialized_signature)
        .map_err(|e| JsError::new(&e.to_string()))?;
    Ok(opener.locator().to_vec())
}

/// The 62-byte SLOT holding `nmts_key` (the account's 20 key bytes) under this wallet's signature
/// (NCF-3 §1.7): `version(1) || kind(1) || nonce(24) || XChaCha20-Poly1305(20 + 16)`.
///
/// The nonce is drawn here from the browser's WebCrypto; there is no caller-nonce path in this
/// build. The result is what goes to the server, and the server can do nothing with it.
#[wasm_bindgen]
pub fn opener_seal(serialized_signature: &[u8], nmts_key: &[u8]) -> Result<Vec<u8>, JsError> {
    let key: [u8; 20] = fixed(nmts_key, "nmts_key")?;
    let opener = opener::opener_from_signature(serialized_signature)
        .map_err(|e| JsError::new(&e.to_string()))?;
    let slot = opener
        .seal(&key)
        .map_err(|e| JsError::new(&e.to_string()))?;
    Ok(slot.to_vec())
}

/// The 20 NMTS-KEY bytes inside `slot`, opened with this wallet's signature (NCF-3 §1.7).
///
/// Throws with a named reason for a slot of the wrong length or an unknown version, and with one
/// indistinguishable "this signature does not open this slot" for a different wallet, a different
/// message or altered bytes — telling those three apart would tell somebody holding a fetched slot
/// whether their guess was getting warmer.
///
/// ⛔ What comes back IS the account. The caller hands it straight to the sign-in path and drops
/// it; it is never sent anywhere and never logged.
#[wasm_bindgen]
pub fn opener_open(serialized_signature: &[u8], slot: &[u8]) -> Result<Vec<u8>, JsError> {
    let opener = opener::opener_from_signature(serialized_signature)
        .map_err(|e| JsError::new(&e.to_string()))?;
    let key = opener
        .open(slot)
        .map_err(|e| JsError::new(&e.to_string()))?;
    Ok(key.to_vec())
}

/// The PRF salt every NMTS passkey is asked about (NCF-3 §1.7): SHA-256 of
/// `nmts/v3/passkey-prf/1`. The page passes these 32 bytes as WebAuthn `prf.eval.first`.
#[wasm_bindgen]
pub fn passkey_prf_salt() -> Vec<u8> {
    opener::passkey_prf_salt().to_vec()
}

/// The 16-byte LOCATOR a passkey's 32-byte PRF result yields — what a passkey sign-in asks the
/// server for (NCF-3 §1.7). Throws for a result of any other length.
#[wasm_bindgen]
pub fn passkey_locator(prf: &[u8]) -> Result<Vec<u8>, JsError> {
    let opener = opener::opener_from_passkey_prf(prf).map_err(|e| JsError::new(&e.to_string()))?;
    Ok(opener.locator().to_vec())
}

/// The 62-byte SLOT holding `nmts_key` under a passkey's PRF result — kind `0x02`, a fresh nonce
/// from WebCrypto, the same layout as a wallet's slot.
#[wasm_bindgen]
pub fn passkey_seal(prf: &[u8], nmts_key: &[u8]) -> Result<Vec<u8>, JsError> {
    let key: [u8; 20] = fixed(nmts_key, "nmts_key")?;
    let opener = opener::opener_from_passkey_prf(prf).map_err(|e| JsError::new(&e.to_string()))?;
    let slot = opener
        .seal(&key)
        .map_err(|e| JsError::new(&e.to_string()))?;
    Ok(slot.to_vec())
}

/// The 20 NMTS-key bytes inside a passkey's slot. One indistinguishable refusal for a different
/// passkey or altered bytes, for the reason `opener_open` gives.
#[wasm_bindgen]
pub fn passkey_open(prf: &[u8], slot: &[u8]) -> Result<Vec<u8>, JsError> {
    let opener = opener::opener_from_passkey_prf(prf).map_err(|e| JsError::new(&e.to_string()))?;
    let key = opener
        .open(slot)
        .map_err(|e| JsError::new(&e.to_string()))?;
    Ok(key.to_vec())
}
