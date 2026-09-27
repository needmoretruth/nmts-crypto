//! The JS boundary's conversion helpers — `Uint8Array`/number in, typed Rust out.
//!
//! ⛔ ITS OWN FILE BECAUSE `lib.rs` HAS A CEILING (2026-09-20). `check:size` holds Rust files to
//!    700 lines and `lib.rs` is far past it; the opener exports that arrived with NCF-3 §1.7 had
//!    to live somewhere, and these helpers are what they and every other export share. This crate's
//!    own header says it "only translates between the JS `Uint8Array`/`string` world and the
//!    crate's typed Rust API" — this file is that translation and nothing else. No cryptography
//!    crosses it.
//!
//! ⚠ NOT `#[wasm_bindgen]`. Nothing here is exported to JavaScript; these are what the exports
//!   call before they touch a key, so moving them changed no export name and no byte layout.

use nmts_crypto::framing::Header;
use wasm_bindgen::JsError;

/// Converts a JS byte slice into a fixed-size array, erroring (to a JS exception) on a
/// length mismatch instead of panicking.
pub(crate) fn fixed<const N: usize>(bytes: &[u8], what: &str) -> Result<[u8; N], JsError> {
    <[u8; N]>::try_from(bytes).map_err(|_| {
        JsError::new(&format!(
            "{} must be {} bytes, got {}",
            what,
            N,
            bytes.len()
        ))
    })
}

/// Largest f64 that is still a contiguous exact integer (2^53). JS integers beyond this
/// silently lose precision, so byte lengths/indexes above it must be rejected, not cast.
const MAX_JS_SAFE_INT: f64 = 9_007_199_254_740_992.0; // 2^53

/// Validates a JS number as a non-negative integer ≤ 2^53 (rejecting NaN/∞/negative/
/// fractional values), then casts to `u64`.
pub(crate) fn js_int_u64(value: f64, what: &str) -> Result<u64, JsError> {
    if !value.is_finite() || value < 0.0 || value.fract() != 0.0 || value > MAX_JS_SAFE_INT {
        return Err(JsError::new(&format!(
            "{} must be a non-negative integer <= 2^53, got {}",
            what, value
        )));
    }
    Ok(value as u64)
}

/// Validates a JS number as a `u32` — used for part numbering, where the header field is 32
/// bits wide and a value that does not fit is a caller bug rather than a big file.
pub(crate) fn js_int_u32(value: f64, what: &str) -> Result<u32, JsError> {
    let n = js_int_u64(value, what)?;
    u32::try_from(n).map_err(|_| JsError::new(&format!("{what} must fit in 32 bits, got {n}")))
}

/// Casts a `u64` to a JS number, erroring if it exceeds 2^53 (not exactly representable).
pub(crate) fn u64_to_js(value: u64, what: &str) -> Result<f64, JsError> {
    if value > MAX_JS_SAFE_INT as u64 {
        return Err(JsError::new(&format!(
            "{} {} exceeds 2^53 and cannot cross the JS boundary exactly",
            what, value
        )));
    }
    Ok(value as f64)
}

/// The item id as both sides must spell it before it is hashed into a share's payload commitment.
///
/// Lowercased, and nothing else. The sender takes the id from a drive listing and the recipient
/// from an inbox row; both are the same UUID serialised by the same server, so they already agree
/// — this exists so that a future difference in CASE alone cannot turn every share into "could not
/// be opened", which is a failure no screen could explain. Any other difference SHOULD break the
/// unwrap, because it means the two sides are not talking about the same file.
pub(crate) fn canonical_item_id(item_id: &str) -> String {
    item_id.to_ascii_lowercase()
}

/// Parses+validates a 72-byte NCF-3 header prefix, mapping failures to a JS exception.
pub(crate) fn parse_header(header: &[u8]) -> Result<Header, JsError> {
    Header::parse(header).map_err(|e| JsError::new(&e.to_string()))
}
