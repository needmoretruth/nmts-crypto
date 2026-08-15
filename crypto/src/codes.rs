//! Account and voucher codes — Crockford Base32 with a check symbol (NCF-1 §1, §7).
//!
//! # Purpose
//! Generate and parse the two high-entropy code types NMTS uses:
//! * **Account code** — 160 random bits → 32 data symbols + 1 check symbol (33 total).
//!   This code *is* the user's identity and the root of all key material ([`crate::kdf`]).
//! * **Voucher code** — 128 random bits → 26 data symbols + 1 check symbol (27 total).
//!   A bearer redemption token; NOT key material. The server stores only
//!   `SHA-256(normalized_code)`.
//!
//! # Encoding contract (frozen)
//! * Alphabet: Crockford Base32 (`0-9 A-Z` minus `I L O U`), packed **MSB-first**.
//!   20 bytes → 32 symbols exactly; 16 bytes → 26 symbols (last symbol carries the
//!   final 3 bits, low 2 bits zero-padded). **Those padding bits MUST be zero on the way
//!   in as well as out** — see [`decode_base32`] for the audit finding that made this
//!   explicit; treating them as slack cost the check symbol its coverage of the last
//!   position.
//! * Check symbol: `value mod 37`, where `value` is the raw code bytes read as a
//!   **big-endian** integer — identical to the number the MSB-first symbols spell out.
//!   Values 32–36 use the Crockford extended symbols `* ~ $ =` and `U`.
//! * Normalization (before any use): strip `-`/whitespace, uppercase, then alias
//!   `O→0, I→1, L→1`, and verify the check symbol.
//!
//! # Invariant (spec §5)
//! Codes are ALWAYS full-entropy, machine-generated. No user-chosen secrets ever enter
//! NCF-1; that is what makes the constant Argon2id salt in [`crate::kdf`] safe.

use sha2::{Digest, Sha256};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::rng::OsRng;
use rand_core::RngCore;

/// The 32 Crockford Base32 data symbols, indexed by their 5-bit value (`I L O U` excluded).
const ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/// The 37-symbol check alphabet: the 32 data symbols followed by `* ~ $ = U`
/// for check values 32–36 (per the Crockford specification).
const CHECK_ALPHABET: &[u8; 37] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ*~$=U";

/// Raw entropy width of an account code, in bytes (160 bits).
pub const ACCOUNT_CODE_BYTES: usize = 20;
/// Number of data symbols in an account code (`160 / 5`).
pub const ACCOUNT_DATA_SYMBOLS: usize = 32;
/// Raw entropy width of a voucher code, in bytes (128 bits).
pub const VOUCHER_CODE_BYTES: usize = 16;
/// Number of data symbols in a voucher code (`ceil(128 / 5)`).
pub const VOUCHER_DATA_SYMBOLS: usize = 26;

/// Errors raised while parsing or validating a code string.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CodeError {
    /// The normalized code had the wrong number of symbols for its type.
    #[error("code has {found} symbols, expected {expected} data + 1 check")]
    WrongLength {
        /// Symbols found after normalization (including the check symbol).
        found: usize,
        /// Expected number of data symbols (check symbol is separate).
        expected: usize,
    },
    /// A symbol was not part of the Crockford data alphabet.
    #[error("invalid Crockford symbol: {0:?}")]
    InvalidSymbol(char),
    /// The check symbol was not a valid Crockford check character.
    #[error("invalid check symbol: {0:?}")]
    InvalidCheckSymbol(char),
    /// The check symbol did not match the decoded data (typo or corruption).
    #[error("check symbol mismatch (typo or corruption)")]
    CheckMismatch,
    /// The last symbol carried non-zero padding bits, so this spelling is one we never
    /// generate — a typo the check symbol structurally cannot see (see [`decode_base32`]).
    /// To a person this is the same event as [`CodeError::CheckMismatch`]: a mistyped code.
    #[error("check symbol mismatch (typo or corruption)")]
    NonCanonicalPadding,
    /// The code string was empty after normalization.
    #[error("empty code")]
    Empty,
}

/// Normalizes a user-entered code: drops `-`/whitespace, uppercases, and applies the
/// Crockford input aliases `O→0`, `I→1`, `L→1`. Does not validate structure.
///
/// This is the exact transformation applied before hashing a voucher for server
/// storage/lookup, so a correctly-entered code always normalizes to its canonical form.
pub fn normalize(input: &str) -> String {
    input
        .chars()
        .filter(|c| *c != '-' && !c.is_whitespace())
        .map(|c| match c.to_ascii_uppercase() {
            'O' => '0',
            'I' | 'L' => '1',
            other => other,
        })
        .collect()
}

/// Encodes `data` as MSB-first Crockford Base32 data symbols (no check symbol).
fn encode_base32(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len() * 8 / 5 + 1);
    let mut buffer: u16 = 0;
    let mut bits: u32 = 0;
    for &byte in data {
        buffer = (buffer << 8) | byte as u16;
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            let idx = ((buffer >> bits) & 0x1f) as usize;
            out.push(ALPHABET[idx] as char);
        }
    }
    if bits > 0 {
        let idx = ((buffer << (5 - bits)) & 0x1f) as usize;
        out.push(ALPHABET[idx] as char);
    }
    out
}

/// Maps a normalized data symbol to its 5-bit value.
fn symbol_value(c: char) -> Result<u8, CodeError> {
    ALPHABET
        .iter()
        .position(|&a| a as char == c)
        .map(|p| p as u8)
        .ok_or(CodeError::InvalidSymbol(c))
}

/// Decodes MSB-first Crockford data symbols into exactly `out_len` bytes.
///
/// # Padding bits are part of the code, not slack
/// When `out_len * 8` is not a multiple of 5 the last symbol carries bits the bytes do not
/// use — 2 of them for a 16-byte code (26 symbols = 130 bits). [`encode_base32`] always emits
/// them as zero, so **a code whose padding bits are not zero was never produced by us** and is
/// rejected here.
///
/// ## Why this is not pedantry (audit finding, E stage 2026-07-28)
/// Ignoring them made four different spellings of the last symbol decode to the same bytes.
/// The check symbol is computed FROM the decoded bytes, so it matched all four — the one
/// position the checksum could not see was the position it was supposed to guard. Measured on
/// the shipped engine: **every** last-symbol typo that only disturbed those 2 bits was accepted
/// (6,000 of 6,000), i.e. 9.68% of last-symbol typos (3 of the 31 wrong symbols) passed a check
/// whose documented promise is "a typo is rejected locally before any lookup leaves the browser".
///
/// For a share address the aliased spelling still decoded to the right 16 bytes, so it resolved
/// correctly — harmless, but the check symbol was silently doing less than it claimed. For a
/// voucher it was not harmless: [`voucher_hash_from_input`] hashes the normalized STRING, so the
/// four spellings produce four different hashes (measured: 500/500 diverged). The check symbol
/// would have said "this code is correct" about a code that cannot redeem — the same shape of
/// defect as the create-screen save gate found the same day, and the reason vouchers are still a
/// server stub is the only reason it never shipped.
///
/// Rejecting them costs nothing: every canonical code has zero padding, and a 20-byte account
/// code has no padding bits at all (160 bits = 32 symbols exactly), so this path cannot fire
/// for one.
fn decode_base32(symbols: &str, out_len: usize) -> Result<Vec<u8>, CodeError> {
    let mut out = Vec::with_capacity(out_len);
    let mut buffer: u16 = 0;
    let mut bits: u32 = 0;
    for c in symbols.chars() {
        buffer = (buffer << 5) | symbol_value(c)? as u16;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push(((buffer >> bits) & 0xff) as u8);
        }
    }
    if bits > 0 && (buffer & ((1u16 << bits) - 1)) != 0 {
        return Err(CodeError::NonCanonicalPadding);
    }
    out.truncate(out_len);
    Ok(out)
}

/// Computes the Crockford check value (`0..=36`) as `big_endian_int(bytes) mod 37`.
fn checksum(bytes: &[u8]) -> u8 {
    let mut acc: u32 = 0;
    for &b in bytes {
        acc = (acc * 256 + b as u32) % 37;
    }
    acc as u8
}

/// Splits a normalized code into `(data_symbols, check_char)`, validating overall length.
fn split_checked(normalized: &str, data_symbols: usize) -> Result<(&str, char), CodeError> {
    if normalized.is_empty() {
        return Err(CodeError::Empty);
    }
    let total = normalized.chars().count();
    if total != data_symbols + 1 {
        return Err(CodeError::WrongLength {
            found: total,
            expected: data_symbols,
        });
    }
    // All symbols are single-byte ASCII after normalization of a valid code, but be
    // careful in case a stray multi-byte char survived: split on the last char.
    let check = normalized.chars().next_back().unwrap();
    let data = &normalized[..normalized.len() - check.len_utf8()];
    Ok((data, check))
}

/// Verifies the trailing check symbol against the decoded bytes.
fn verify_check(bytes: &[u8], check: char) -> Result<(), CodeError> {
    let provided = CHECK_ALPHABET
        .iter()
        .position(|&a| a as char == check)
        .ok_or(CodeError::InvalidCheckSymbol(check))? as u8;
    if provided == checksum(bytes) {
        Ok(())
    } else {
        Err(CodeError::CheckMismatch)
    }
}

/// Builds the canonical (hyphen-free, uppercase) code string: data symbols + check symbol.
fn canonical_string(bytes: &[u8]) -> String {
    let mut s = encode_base32(bytes);
    s.push(CHECK_ALPHABET[checksum(bytes) as usize] as char);
    s
}

/// Groups a canonical string with `-` separators, merging the check symbol into the
/// final group so it reads as `…-XXXXC` rather than a lone trailing character.
fn group(canonical: &str, group_size: usize) -> String {
    let chars: Vec<char> = canonical.chars().collect();
    // Last char is the check symbol; group the data symbols and append the check.
    let (data, check) = chars.split_at(chars.len() - 1);
    let mut groups: Vec<String> = data
        .chunks(group_size)
        .map(|g| g.iter().collect())
        .collect();
    if let Some(last) = groups.last_mut() {
        last.push(check[0]);
    } else {
        groups.push(check[0].to_string());
    }
    groups.join("-")
}

/// Encodes arbitrary bytes as a grouped, check-symbol-terminated Crockford string.
///
/// Every user-facing NMTS code (account code, voucher, share address) goes through this one
/// function, so they share a single alphabet, a single check rule, and a single normalizer —
/// a code that a user mistypes fails the same way everywhere instead of one surface being
/// laxer than the others.
pub(crate) fn encode_checked_grouped(bytes: &[u8], group_size: usize) -> String {
    group(&canonical_string(bytes), group_size)
}

/// Parses a checked Crockford string (any spacing/case/`O`→`0` aliasing) into `out_len` bytes.
///
/// `data_symbols` is the expected symbol count BEFORE the trailing check symbol; a wrong
/// length, an unknown symbol, or a failed check all error rather than returning bytes.
pub(crate) fn parse_checked(
    input: &str,
    data_symbols: usize,
    out_len: usize,
) -> Result<Vec<u8>, CodeError> {
    let normalized = normalize(input);
    let (data, check) = split_checked(&normalized, data_symbols)?;
    let decoded = decode_base32(data, out_len)?;
    verify_check(&decoded, check)?;
    Ok(decoded)
}

/// A 160-bit account code — the root of a user's identity and key material.
///
/// # Security
/// This struct holds raw key-derivation input and is zeroized on drop. It deliberately
/// does not implement `Clone` or a value-revealing `Debug`. Feed it to
/// [`crate::kdf::derive`] to obtain the account keys.
#[derive(Zeroize, ZeroizeOnDrop, PartialEq, Eq)]
pub struct AccountCode {
    bytes: [u8; ACCOUNT_CODE_BYTES],
}

impl core::fmt::Debug for AccountCode {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("AccountCode(<redacted>)")
    }
}

impl AccountCode {
    /// Generates a fresh account code from the OS CSPRNG.
    pub fn generate() -> Self {
        let mut bytes = [0u8; ACCOUNT_CODE_BYTES];
        OsRng.fill_bytes(&mut bytes);
        Self { bytes }
    }

    /// Wraps 20 raw entropy bytes as an account code (e.g. for test vectors).
    pub fn from_bytes(bytes: [u8; ACCOUNT_CODE_BYTES]) -> Self {
        Self { bytes }
    }

    /// The raw 20 bytes — this is the Argon2id password input, per NCF-1 §2
    /// (the *bytes*, never the ASCII text).
    pub fn as_bytes(&self) -> &[u8; ACCOUNT_CODE_BYTES] {
        &self.bytes
    }

    /// The canonical 33-symbol string (uppercase, no separators).
    pub fn canonical(&self) -> String {
        canonical_string(&self.bytes)
    }

    /// The display form: `XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXXC` (NCF-1 §1).
    pub fn display(&self) -> String {
        group(&self.canonical(), 4)
    }

    /// Parses and validates a user-entered account code (any spacing/case/aliasing).
    pub fn parse(input: &str) -> Result<Self, CodeError> {
        let normalized = normalize(input);
        let (data, check) = split_checked(&normalized, ACCOUNT_DATA_SYMBOLS)?;
        let decoded = decode_base32(data, ACCOUNT_CODE_BYTES)?;
        verify_check(&decoded, check)?;
        let mut bytes = [0u8; ACCOUNT_CODE_BYTES];
        bytes.copy_from_slice(&decoded);
        Ok(Self { bytes })
    }
}

/// A 128-bit voucher code — a bearer redemption token, not key material (NCF-1 §7).
///
/// The server persists only [`VoucherCode::code_hash`]; the plaintext code is shown to
/// the recipient once and never stored by NMTS.
#[derive(Clone, PartialEq, Eq)]
pub struct VoucherCode {
    bytes: [u8; VOUCHER_CODE_BYTES],
}

impl core::fmt::Debug for VoucherCode {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("VoucherCode(<redacted>)")
    }
}

impl VoucherCode {
    /// Generates a fresh voucher code from the OS CSPRNG.
    pub fn generate() -> Self {
        let mut bytes = [0u8; VOUCHER_CODE_BYTES];
        OsRng.fill_bytes(&mut bytes);
        Self { bytes }
    }

    /// Wraps 16 raw entropy bytes as a voucher code (e.g. for test vectors).
    pub fn from_bytes(bytes: [u8; VOUCHER_CODE_BYTES]) -> Self {
        Self { bytes }
    }

    /// The raw 16 bytes.
    pub fn as_bytes(&self) -> &[u8; VOUCHER_CODE_BYTES] {
        &self.bytes
    }

    /// The canonical 27-symbol string (uppercase, no separators).
    pub fn canonical(&self) -> String {
        canonical_string(&self.bytes)
    }

    /// A grouped display form (`XXXXX-…`). Grouping is an app-level choice (NCF-1 §7);
    /// only the normalized string matters for hashing, so any spacing is acceptable.
    pub fn display(&self) -> String {
        group(&self.canonical(), 5)
    }

    /// `SHA-256(canonical_code)` — the value the server stores for redemption lookup.
    pub fn code_hash(&self) -> [u8; 32] {
        code_hash_of(&self.canonical())
    }

    /// Parses and validates a user-entered voucher code.
    pub fn parse(input: &str) -> Result<Self, CodeError> {
        let normalized = normalize(input);
        let (data, check) = split_checked(&normalized, VOUCHER_DATA_SYMBOLS)?;
        let decoded = decode_base32(data, VOUCHER_CODE_BYTES)?;
        verify_check(&decoded, check)?;
        let mut bytes = [0u8; VOUCHER_CODE_BYTES];
        bytes.copy_from_slice(&decoded);
        Ok(Self { bytes })
    }
}

/// Computes `SHA-256(normalize(input))` — the voucher redemption hash for arbitrary
/// user input, without requiring the input to be structurally valid.
///
/// Use this on the redemption path: it normalizes exactly as generation does, so a
/// correctly-entered code hashes to the stored value.
pub fn voucher_hash_from_input(input: &str) -> [u8; 32] {
    code_hash_of(&normalize(input))
}

/// SHA-256 of an already-normalized/canonical code string.
fn code_hash_of(canonical: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(canonical.as_bytes());
    hasher.finalize().into()
}
