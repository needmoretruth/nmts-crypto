//! Minimal base64url (RFC 4648 §5) **without padding** — the text encoding NCF-1 uses
//! for `accountId`, blob/patch IDs, and share tokens (§0, §2, §5).
//!
//! # Why hand-rolled
//! The crate's dependency budget is intentionally tiny (see `Cargo.toml`); base64url with
//! no padding is a few lines and needs no external crate. This implementation is
//! constant-shape (no data-dependent branches on secret length beyond the obvious) and
//! rejects malformed input on decode.
//!
//! # Contract
//! * `encode`: 3 bytes → 4 chars, no `=` padding on the tail.
//! * `decode`: accepts only the 64 url-safe symbols; rejects `+`, `/`, `=`, whitespace,
//!   and impossible tail lengths (a remainder of exactly one char is never valid).

/// The url-safe alphabet, indexed by 6-bit value.
const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/// Errors from [`decode`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Base64Error {
    /// A character outside the url-safe alphabet was encountered.
    #[error("invalid base64url character: {0:?}")]
    InvalidChar(char),
    /// The input length is not a valid no-pad base64url length (`len % 4 == 1`).
    #[error("invalid base64url length")]
    InvalidLength,
}

/// Encodes bytes as unpadded base64url.
pub fn encode(input: &[u8]) -> String {
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = *chunk.get(1).unwrap_or(&0) as u32;
        let b2 = *chunk.get(2).unwrap_or(&0) as u32;
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(ALPHABET[(n >> 18) as usize & 0x3f] as char);
        out.push(ALPHABET[(n >> 12) as usize & 0x3f] as char);
        if chunk.len() > 1 {
            out.push(ALPHABET[(n >> 6) as usize & 0x3f] as char);
        }
        if chunk.len() > 2 {
            out.push(ALPHABET[n as usize & 0x3f] as char);
        }
    }
    out
}

/// Decodes unpadded base64url into bytes.
pub fn decode(input: &str) -> Result<Vec<u8>, Base64Error> {
    let symbol_value =
        |c: u8| -> Option<u8> { ALPHABET.iter().position(|&a| a == c).map(|p| p as u8) };
    let bytes = input.as_bytes();
    if bytes.len() % 4 == 1 {
        return Err(Base64Error::InvalidLength);
    }
    let mut out = Vec::with_capacity(bytes.len() * 3 / 4);
    for chunk in bytes.chunks(4) {
        let mut acc: u32 = 0;
        for &c in chunk {
            let v = symbol_value(c).ok_or(Base64Error::InvalidChar(c as char))?;
            acc = (acc << 6) | v as u32;
        }
        // Left-align the accumulated bits so the high byte comes first.
        acc <<= (4 - chunk.len()) * 6;
        let produced = chunk.len() - 1; // 4→3, 3→2, 2→1 bytes
        let be = acc.to_be_bytes(); // [b_hi, b0, b1, b2] with acc in low 24 bits
        out.extend_from_slice(&be[1..1 + produced]);
    }
    Ok(out)
}
