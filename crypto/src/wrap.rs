//! Envelope encryption + share tokens (NCF-3 §3).
//!
//! # Purpose
//! One small AEAD envelope encrypts everything that is not bulk file data:
//! * the per-file **DEK**, wrapped under the account `dataKey`;
//! * encrypted item **names** and folder-path **metadata**;
//! * the **recovery map** (handled in [`crate::manifest`], reusing this envelope);
//! * the sealed **file list** and every share-side object.
//!
//! # Envelope format (NCF-3 — re-freezes at the mainnet cutover)
//! ```text
//! E(key, aad, plaintext) = nonce(24, random)
//!                        || commitment(32)
//!                        || XChaCha20Poly1305(key, nonce, pt, aad || commitment)
//!
//! commitment = HKDF-SHA256(ikm = key, salt = nonce, info = "nmts/v3/envelope-commit" || aad, 32)
//! ```
//! The 24-byte random nonce and the commitment are prepended in the clear; the AEAD tag (16 B) is
//! appended by the cipher. A wrapped 32-byte DEK is therefore `24 + 32 + 32 + 16 = 104` bytes
//! (NCF-2: 72).
//!
//! # Why a commitment (defect A5)
//! Poly1305 is **not key-committing**. Given two keys an attacker can construct ONE ciphertext
//! that authenticates under both and decrypts to two different plaintexts. That matters here
//! because the public-link design deliberately hands the DEK to whoever holds the link, so
//! "this stored blob is that file" has to be a fact rather than a claim — for abuse reports, and
//! for any process that asks what a blob actually is.
//!
//! The commitment removes it: a ciphertext now names exactly one key, and because the nonce and
//! the AAD are inputs to the derivation, exactly one nonce and one role as well.
//!
//! ⚠ **The reader must check the commitment BEFORE decrypting**, in constant time, and must
//! report a mismatch as the same error as a failed tag. Distinguishing them tells an attacker
//! which half of a guess was right.
//!
//! **One envelope format, always committing.** The commitment is only load-bearing where an
//! outsider supplies the ciphertext (file streams, share envelopes) and buys nothing on a name
//! this same client sealed a moment ago under its own key. Two formats would be cheaper by bytes
//! and more expensive by everything else: every reader would have to know which one it held, and
//! "which envelopes commit?" is not a question anyone wants to answer during an incident.
//! The cost is +32 bytes per envelope — about 860 KB of base64 on a 10,000-file drive's sealed
//! list, against an 8 MiB ceiling.
//!
//! # AAD domain separation
//! Each object type uses a distinct constant AAD so a ciphertext for one role can never be
//! accepted as another. The full registry is NCF-3 §2.2; the ones defined here are
//! `nmts/v3/dek-wrap`, `nmts/v3/name`, `nmts/v3/meta`, `nmts/v3/content-hash` and
//! `nmts/v3/recovery-map` (the last used by [`crate::manifest`]).
//!
//! # Share token
//! `base64url(0x01 || DEK)` — possession of the token IS possession of the key, by design;
//! the server never receives the URL fragment. Revocation is de-indexing only.
//!
//! # Invariant
//! The production [`seal`] never accepts a caller nonce; it always draws a fresh one from
//! the OS CSPRNG. A deterministic `seal_with_nonce` exists only for the vectors.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use hkdf::Hkdf;
use sha2::Sha256;
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use crate::b64;
use crate::rng::OsRng;
use rand_core::RngCore;

/// Envelope nonce length (bytes).
pub const ENVELOPE_NONCE_LEN: usize = 24;
/// Key-commitment length (bytes) — NCF-3 §3.2.
pub const COMMITMENT_LEN: usize = 32;
/// AEAD tag length (bytes).
pub const TAG_LEN: usize = 16;
/// DEK length (bytes).
pub const DEK_LEN: usize = 32;
/// Smallest possible envelope: nonce + commitment + tag, with an empty plaintext.
pub const MIN_ENVELOPE_LEN: usize = ENVELOPE_NONCE_LEN + COMMITMENT_LEN + TAG_LEN;
/// Exact size of a wrapped DEK envelope: `nonce(24) + commitment(32) + dek(32) + tag(16)`.
pub const WRAPPED_DEK_LEN: usize = MIN_ENVELOPE_LEN + DEK_LEN;

/// HKDF `info` prefix for the envelope key commitment. The envelope's own AAD is appended, so a
/// commitment is valid for exactly one role as well as exactly one key and nonce.
pub const INFO_ENVELOPE_COMMIT: &[u8] = b"nmts/v3/envelope-commit";

/// AAD for a wrapped file DEK.
pub const AAD_DEK_WRAP: &[u8] = b"nmts/v3/dek-wrap";
/// AAD for an encrypted item name.
pub const AAD_NAME: &[u8] = b"nmts/v3/name";
/// AAD for encrypted folder-path metadata.
pub const AAD_META: &[u8] = b"nmts/v3/meta";
/// AAD for the recovery MAP (used by [`crate::manifest`]).
///
/// Renamed from `recovery-manifest` in NCF-3: three unrelated objects were called "manifest"
/// (this map, the sealed file list, and the key that opens it), which is the kind of ambiguity
/// that makes a domain-separator mistake invisible. See NCF-3 §2.4.
pub const AAD_RECOVERY_MAP: &[u8] = b"nmts/v3/recovery-map";
/// AAD for an encrypted whole-file plaintext content hash. Domain-separated from every other AAD
/// so a hash envelope can never be opened as (or substituted for) a name/DEK/meta envelope.
pub const AAD_CONTENT_HASH: &[u8] = b"nmts/v3/content-hash";

/// Length of a whole-file plaintext content hash (SHA-256).
pub const CONTENT_HASH_LEN: usize = 32;
/// Exact size of a sealed content hash: `nonce(24) + commitment(32) + hash(32) + tag(16)`.
pub const SEALED_CONTENT_HASH_LEN: usize = MIN_ENVELOPE_LEN + CONTENT_HASH_LEN;

/// Version byte prefixing a share token's key material.
pub const SHARE_TOKEN_VERSION: u8 = 0x01;

/// Errors from envelope operations and share-token parsing.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum WrapError {
    /// Envelope was shorter than `nonce(24) + tag(16)`.
    #[error("envelope too short")]
    TooShort,
    /// AEAD authentication failed (wrong key/AAD, corruption, or tamper).
    #[error("authentication failed")]
    Auth,
    /// An unwrapped DEK was not exactly 32 bytes.
    #[error("unwrapped DEK has wrong length")]
    BadDekLength,
    /// An opened content-hash envelope did not contain exactly 32 bytes.
    #[error("content hash has wrong length")]
    BadContentHashLength,
    /// Share token did not decode as valid base64url.
    #[error("invalid share token encoding: {0}")]
    TokenEncoding(#[from] b64::Base64Error),
    /// Share token had the wrong length (must be `1 + 32` bytes).
    #[error("share token has wrong length")]
    BadTokenLength,
    /// Share token version byte was not recognized.
    #[error("unsupported share token version: {0}")]
    BadTokenVersion(u8),
}

/// The key commitment for one (key, nonce, aad) triple — NCF-3 §3.2.
///
/// Preimage resistance is what carries the argument: publishing this value must not help anyone
/// recover the key, and no second key may produce it for the same nonce and role.
pub fn commitment(
    key: &[u8; 32],
    nonce: &[u8; ENVELOPE_NONCE_LEN],
    aad: &[u8],
) -> [u8; COMMITMENT_LEN] {
    let mut info = Vec::with_capacity(INFO_ENVELOPE_COMMIT.len() + aad.len());
    info.extend_from_slice(INFO_ENVELOPE_COMMIT);
    info.extend_from_slice(aad);
    let hk = Hkdf::<Sha256>::new(Some(nonce), key);
    let mut out = [0u8; COMMITMENT_LEN];
    hk.expand(&info, &mut out)
        .expect("HKDF expand length within bounds");
    out
}

/// Encrypts `plaintext` under `key` with domain-separating `aad`, prepending a fresh random
/// 24-byte nonce and the key commitment. This is the production envelope (`E` in NCF-3 §3).
pub fn seal(key: &[u8; 32], aad: &[u8], plaintext: &[u8]) -> Vec<u8> {
    let mut nonce = [0u8; ENVELOPE_NONCE_LEN];
    OsRng.fill_bytes(&mut nonce);
    seal_inner(key, &nonce, aad, plaintext)
}

/// Decrypts an envelope produced by [`seal`], verifying the commitment and then `aad`.
///
/// The commitment is checked FIRST and in constant time. A mismatch returns [`WrapError::Auth`],
/// the same error a bad tag gives: an attacker who could tell "wrong key" from "tampered bytes"
/// would learn which half of their guess was right.
pub fn open(key: &[u8; 32], aad: &[u8], envelope: &[u8]) -> Result<Vec<u8>, WrapError> {
    if envelope.len() < MIN_ENVELOPE_LEN {
        return Err(WrapError::TooShort);
    }
    let (nonce, rest) = envelope.split_at(ENVELOPE_NONCE_LEN);
    let (found, body) = rest.split_at(COMMITMENT_LEN);
    let nonce: &[u8; ENVELOPE_NONCE_LEN] = nonce
        .try_into()
        .expect("split at ENVELOPE_NONCE_LEN yields exactly 24 bytes");

    let expected = commitment(key, nonce, aad);
    if !bool::from(expected.ct_eq(found)) {
        return Err(WrapError::Auth);
    }

    // The commitment is bound into the AEAD's AAD as well, so stripping or swapping it cannot
    // pass the tag check either. Checking it above is what makes the failure cheap and the
    // guarantee explicit; binding it here is what makes it authenticated.
    let mut full_aad = Vec::with_capacity(aad.len() + COMMITMENT_LEN);
    full_aad.extend_from_slice(aad);
    full_aad.extend_from_slice(found);

    let cipher = XChaCha20Poly1305::new(Key::from_slice(key));
    cipher
        .decrypt(
            XNonce::from_slice(nonce),
            Payload {
                msg: body,
                aad: &full_aad,
            },
        )
        .map_err(|_| WrapError::Auth)
}

/// Shared sealing body used by both the production and deterministic paths.
/// `pub(crate)` so [`crate::share`] can seal with a nonce it already holds. Its two entry points
/// have the same split as [`seal`] / [`seal_with_nonce`] here — one production function that draws
/// the nonce, one vectors-only function that is handed it — and routing both through this body
/// keeps the share envelope's last 104 bytes the same construction as every other envelope.
pub(crate) fn seal_inner(
    key: &[u8; 32],
    nonce: &[u8; ENVELOPE_NONCE_LEN],
    aad: &[u8],
    plaintext: &[u8],
) -> Vec<u8> {
    let commit = commitment(key, nonce, aad);
    let mut full_aad = Vec::with_capacity(aad.len() + COMMITMENT_LEN);
    full_aad.extend_from_slice(aad);
    full_aad.extend_from_slice(&commit);

    let cipher = XChaCha20Poly1305::new(Key::from_slice(key));
    let body = cipher
        .encrypt(
            XNonce::from_slice(nonce),
            Payload {
                msg: plaintext,
                aad: &full_aad,
            },
        )
        .expect("XChaCha20Poly1305 encryption is infallible for valid inputs");
    let mut out = Vec::with_capacity(MIN_ENVELOPE_LEN + plaintext.len());
    out.extend_from_slice(nonce);
    out.extend_from_slice(&commit);
    out.extend_from_slice(&body);
    out
}

/// Wraps a file DEK under the account `dataKey` (`E(dataKey, "nmts/v3/dek-wrap", DEK)`).
pub fn wrap_dek(data_key: &[u8; 32], dek: &[u8; DEK_LEN]) -> Vec<u8> {
    seal(data_key, AAD_DEK_WRAP, dek)
}

/// Unwraps a file DEK, returning the 32-byte key in a zeroizing buffer.
pub fn unwrap_dek(
    data_key: &[u8; 32],
    envelope: &[u8],
) -> Result<Zeroizing<[u8; DEK_LEN]>, WrapError> {
    let pt = Zeroizing::new(open(data_key, AAD_DEK_WRAP, envelope)?);
    if pt.len() != DEK_LEN {
        return Err(WrapError::BadDekLength);
    }
    let mut dek = Zeroizing::new([0u8; DEK_LEN]);
    dek.copy_from_slice(&pt);
    Ok(dek)
}

/// Encrypts an item name (`E(dataKey, "nmts/v3/name", utf8(name))`).
pub fn encrypt_name(data_key: &[u8; 32], name: &str) -> Vec<u8> {
    seal(data_key, AAD_NAME, name.as_bytes())
}

/// Decrypts an item name; returns the UTF-8 string.
pub fn decrypt_name(data_key: &[u8; 32], envelope: &[u8]) -> Result<String, WrapError> {
    let pt = open(data_key, AAD_NAME, envelope)?;
    String::from_utf8(pt).map_err(|_| WrapError::Auth)
}

/// Encrypts folder-path metadata JSON (`E(dataKey, "nmts/v3/meta", utf8(json))`).
pub fn encrypt_meta(data_key: &[u8; 32], json: &str) -> Vec<u8> {
    seal(data_key, AAD_META, json.as_bytes())
}

/// Decrypts folder-path metadata JSON.
pub fn decrypt_meta(data_key: &[u8; 32], envelope: &[u8]) -> Result<String, WrapError> {
    let pt = open(data_key, AAD_META, envelope)?;
    String::from_utf8(pt).map_err(|_| WrapError::Auth)
}

/// Seals a whole-file plaintext content hash (`E(dataKey, "nmts/v3/content-hash", hash)`).
///
/// WHY ENCRYPTED: a plaintext SHA-256 of file CONTENT is an identifier, not a neutral
/// checksum — anyone holding the server's rows could match it against public hash sets to
/// learn WHICH file a user stores, and could see that two accounts hold the same file.
/// Sealing it keeps the integrity guarantee (the owner's device can still verify a download
/// or a recovery) while giving the server nothing to correlate.
pub fn seal_content_hash(data_key: &[u8; 32], hash: &[u8; CONTENT_HASH_LEN]) -> Vec<u8> {
    seal(data_key, AAD_CONTENT_HASH, hash)
}

/// Opens a sealed content hash. Rejects any envelope not sealed with the content-hash AAD.
pub fn open_content_hash(
    data_key: &[u8; 32],
    envelope: &[u8],
) -> Result<[u8; CONTENT_HASH_LEN], WrapError> {
    let pt = open(data_key, AAD_CONTENT_HASH, envelope)?;
    if pt.len() != CONTENT_HASH_LEN {
        return Err(WrapError::BadContentHashLength);
    }
    let mut hash = [0u8; CONTENT_HASH_LEN];
    hash.copy_from_slice(&pt);
    Ok(hash)
}

/// Generates a fresh random 32-byte file DEK.
pub fn generate_dek() -> Zeroizing<[u8; DEK_LEN]> {
    let mut dek = Zeroizing::new([0u8; DEK_LEN]);
    OsRng.fill_bytes(&mut *dek);
    dek
}

/// Encodes a share token for a file DEK: `base64url(0x01 || DEK)` (§5).
///
/// Anyone holding this string can decrypt the file — it IS the key. Treat it as a secret
/// and keep it in the URL fragment (never sent to the server).
pub fn encode_share_token(dek: &[u8; DEK_LEN]) -> String {
    let mut raw = [0u8; 1 + DEK_LEN];
    raw[0] = SHARE_TOKEN_VERSION;
    raw[1..].copy_from_slice(dek);
    let token = b64::encode(&raw);
    // `raw` holds key material; scrub it before returning.
    zeroize::Zeroize::zeroize(&mut raw);
    token
}

/// Parses a share token back into the raw file DEK.
pub fn parse_share_token(token: &str) -> Result<Zeroizing<[u8; DEK_LEN]>, WrapError> {
    let raw = Zeroizing::new(b64::decode(token)?);
    if raw.len() != 1 + DEK_LEN {
        return Err(WrapError::BadTokenLength);
    }
    if raw[0] != SHARE_TOKEN_VERSION {
        return Err(WrapError::BadTokenVersion(raw[0]));
    }
    let mut dek = Zeroizing::new([0u8; DEK_LEN]);
    dek.copy_from_slice(&raw[1..]);
    Ok(dek)
}

// ---------------------------------------------------------------------------------------
// Deterministic envelope — VECTORS ONLY.
// ---------------------------------------------------------------------------------------

/// Deterministic envelope with a caller-supplied nonce, for the conformance vectors only.
///
/// Compiled only under `test` or the `vectors` feature; production code must use [`seal`].
#[cfg(any(test, feature = "vectors"))]
pub fn seal_with_nonce(
    key: &[u8; 32],
    nonce: &[u8; ENVELOPE_NONCE_LEN],
    aad: &[u8],
    plaintext: &[u8],
) -> Vec<u8> {
    seal_inner(key, nonce, aad, plaintext)
}
