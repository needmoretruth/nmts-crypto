//! wasm-bindgen surface over the NCF-3 engine (`nmts-crypto`) for the NMTS web app.
//!
//! This crate adds ZERO cryptography of its own — every function forwards to `nmts-crypto`
//! so the browser executes byte-for-byte the same code the Rust tests exercise. It only
//! translates between the JS `Uint8Array`/`string` world and the crate's typed Rust API.
//!
//! Randomness is provided by the crate's `wasm` feature (getrandom → `crypto.getRandomValues`).
//! The deterministic caller-nonce constructors (the crate's `vectors` feature) are
//! intentionally absent: production code — and this shipped artifact — must never accept a
//! caller nonce. Conformance is proven through these production paths.
//!
//! Byte layouts crossing the boundary — the authority is `docs/CRYPTO-FORMAT-NCF3.md`, and every
//! number below is repeated in code as a named constant rather than a literal:
//! * `kdf_derive` returns **256 bytes**; the field-by-field layout is on that function, which is
//!   the one place it is written down. NCF-3 replaced NCF-1/NCF-2 outright, so this is not an
//!   additive tail on an older buffer — reading it by any older offset table yields the wrong
//!   secret, silently. Everything except `account_id` and `share_address` must never leave the
//!   crypto worker.
//! * envelope = `nonce(24) || key_commitment(32) || XChaCha20-Poly1305(ct||tag)`; a wrapped DEK
//!   is **104** bytes (§3.1). The commitment is what makes an envelope open under exactly one
//!   key rather than merely authenticate (§3.2, defect A5).
//! * an NCF-3 stream = `header(72) || chunks…` (§4.1). The header carries the part's PLACE in
//!   its file (`part_index` of `part_total`) and the stream's key commitment, and it is inside
//!   every chunk's AAD — so a part decrypted in a position its header does not claim fails to
//!   authenticate instead of producing the wrong bytes (defect A4).
//! * a share identity is **4989** bytes — `version(1) || derivation_index(4) || pk_sig(1312) ||
//!   key_epoch(4) || pk_kem(1216) || pk_auth(32) || self_sig(2420)` — and a share envelope is
//!   **1240** (§5.1, §5.2a, §5.4). The address fingerprints only the 1316-byte ROOT
//!   (`derivation_index || pk_sig`); the self-signature is what binds the rest of the bundle to
//!   it, so the two working keys can be replaced one day without the address moving.
//! * streaming: the `StreamEncryptor`/`StreamDecryptor` classes emit/consume raw chunk
//!   bytes incrementally; `stream_decrypt_chunk` decrypts ONE chunk for random access and
//!   REQUIRES the caller to state which part it thinks it is reading (§4.1 — a lone chunk
//!   arrives with its own header, so the AAD cannot tell one part of a file from another);
//!   the `header_*` helpers and `verify_part_set` expose stream geometry and placement (Rust
//!   stays the single source of truth).
//! * `StreamEncryptor.resumeFromHeader(dek, header)` is the ONE caller-nonce path — a
//!   RESUME-ONLY re-derivation used to reproduce an already-registered part's exact
//!   ciphertext. It is gated by the uploader's blobId-compare GUARD (see its safety note).
//! * lengths/indexes cross as JS numbers (`f64`) and are validated as non-negative
//!   integers ≤ 2^53 before casting to `u64` (beyond 2^53 JS numbers lose integer
//!   precision, so such values are rejected rather than silently rounded).

// NOTE: `#[wasm_bindgen]` expands to `unsafe` glue in THIS crate, so we cannot
// `forbid(unsafe_code)` here (the underlying `nmts-crypto` crate does).

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use nmts_crypto::codes::{self, AccountCode};
use nmts_crypto::framing::{
    decrypt_chunk, Header, PartPlacement, StreamDecryptor, StreamEncryptor, AAD_LEN, HEADER_LEN,
    NONCE_LEN, NONCE_PREFIX_LEN,
};
use nmts_crypto::{b64, kdf, manifest, share, wrap};
use sha2::{Digest, Sha256};
use wasm_bindgen::{prelude::*, JsError};

/// Converts a JS byte slice into a fixed-size array, erroring (to a JS exception) on a
/// length mismatch instead of panicking.
fn fixed<const N: usize>(bytes: &[u8], what: &str) -> Result<[u8; N], JsError> {
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
fn js_int_u64(value: f64, what: &str) -> Result<u64, JsError> {
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
fn js_int_u32(value: f64, what: &str) -> Result<u32, JsError> {
    let n = js_int_u64(value, what)?;
    u32::try_from(n).map_err(|_| JsError::new(&format!("{what} must fit in 32 bits, got {n}")))
}

/// Casts a `u64` to a JS number, erroring if it exceeds 2^53 (not exactly representable).
fn u64_to_js(value: u64, what: &str) -> Result<f64, JsError> {
    if value > MAX_JS_SAFE_INT as u64 {
        return Err(JsError::new(&format!(
            "{} {} exceeds 2^53 and cannot cross the JS boundary exactly",
            what, value
        )));
    }
    Ok(value as f64)
}

/// Parses+validates a 72-byte NCF-3 header prefix, mapping failures to a JS exception.
fn parse_header(header: &[u8]) -> Result<Header, JsError> {
    Header::parse(header).map_err(|e| JsError::new(&e.to_string()))
}

// ---------------------------------------------------------------------------------------
// Key derivation (NCF-3 §1)
// ---------------------------------------------------------------------------------------

/// Total length of the [`kdf_derive`] output.
pub const KDF_DERIVE_LEN: usize = 256;

/// Derives the account keys from the 20 raw account-code bytes (NCF-3 §1).
///
/// Returns one concatenated buffer (`KDF_DERIVE_LEN` = 256 bytes) the caller slices:
/// ```text
///   0.. 16  account_id         public — the server's lookup key
///  16.. 48  auth_secret        secret — sent to the server over TLS at login
///  48.. 80  data_key           secret — wraps every file DEK; NEVER leaves the worker
///  80..112  file_list_key      secret — opens the sealed drive index, and nothing else
/// 112..144  share_kem_seed     secret — X-Wing seed for private sharing (NCF-3 §5.1)
/// 144..176  share_auth_secret  secret — proves this account SENT a share (NCF-3 §5.5)
/// 176..208  wallet_root        secret — parent of EVERY wallet, including the first
/// 208..224  share_address      public — the address a user hands out to be shared with
/// 224..256  share_sig_seed     secret — ML-DSA-44 seed; its key IS the identity root (§5.2a)
/// ```
/// Every secret region above must be retained inside the crypto worker and never cross the
/// postMessage boundary.
///
/// ⚠ **This layout only ever grows at the TAIL.** `share_sig_seed` was appended in 2026-08-02
/// rather than filed beside the other two share secrets, where it would read better, because
/// inserting it there would shift `wallet_root` and `share_address` and every constant on the
/// JS side would be silently wrong about which 32 bytes it was holding. Readability loses to
/// that, every time.
///
/// `share_address` is included even though it is not an HKDF output: since NCF-3 it is the
/// FINGERPRINT of the share identity's root (§5.2), and computing it here means the browser never
/// has to decide for itself which key an address belongs to.
#[wasm_bindgen]
pub fn kdf_derive(code_bytes: &[u8]) -> Result<Vec<u8>, JsError> {
    let cb: [u8; 20] = fixed(code_bytes, "code_bytes")?;
    let keys = kdf::derive_from_bytes(&cb).map_err(|e| JsError::new(&e.to_string()))?;
    let mut out = Vec::with_capacity(KDF_DERIVE_LEN);
    out.extend_from_slice(&keys.account_id);
    out.extend_from_slice(&keys.auth_secret[..]);
    out.extend_from_slice(&keys.data_key[..]);
    out.extend_from_slice(&keys.file_list_key[..]);
    out.extend_from_slice(&keys.share_kem_seed[..]);
    out.extend_from_slice(&keys.share_auth_secret[..]);
    out.extend_from_slice(&keys.wallet_root[..]);
    out.extend_from_slice(share::address_for(&keys.share_sig_seed).as_bytes());
    out.extend_from_slice(&keys.share_sig_seed[..]);
    debug_assert_eq!(out.len(), KDF_DERIVE_LEN);
    Ok(out)
}

/// Derives the 32-byte wrapping key for a passphrase-protected "remember this device" record.
///
/// `salt` is 16 bytes the CALLER generated fresh for that record and stores beside the
/// ciphertext — a human-chosen passphrase must never share a salt with another user's (see
/// `kdf::derive_device_wrap_key`). Errors on a short passphrase or a wrong-length salt rather
/// than deriving something weak.
///
/// The returned key is ordinary bytes: the browser imports it into WebCrypto to seal the record
/// and drops it. It is NOT an account key and reaches nothing an account key reaches.
#[wasm_bindgen]
pub fn device_wrap_key(passphrase: &[u8], salt: &[u8]) -> Result<Vec<u8>, JsError> {
    let key =
        kdf::derive_device_wrap_key(passphrase, salt).map_err(|e| JsError::new(&e.to_string()))?;
    Ok(key.to_vec())
}

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

// ---------------------------------------------------------------------------------------
// Private person-to-person sharing (NCF-3 §5)
// ---------------------------------------------------------------------------------------

/// The 4989-byte PUBLIC share identity, built from the three secrets at `kdf_derive` bytes
/// 112..176 and 224..256 (KEM seed, auth secret, signing seed).
///
/// Layout: `version(1) || derivation_index(4) || pk_sig(1312) || key_epoch(4) || pk_kem(1216) ||
/// pk_auth(32) || self_sig(2420)`. This is the only part of the identity the server holds, the
/// address is the fingerprint of its ROOT, and the self-signature is what makes every key after
/// the root attributable to that address (NCF-3 §5.2a).
///
/// ⚠ The bytes are the same on every device the account code is entered on — deterministic
/// signing, never hedged — which is what lets the server hold one bundle per account
/// first-writer-wins without rejecting the account's own second device.
#[wasm_bindgen]
pub fn share_public_key(
    share_kem_seed: &[u8],
    share_auth_secret: &[u8],
    share_sig_seed: &[u8],
) -> Result<Vec<u8>, JsError> {
    let kem: [u8; 32] = fixed(share_kem_seed, "share_kem_seed")?;
    let auth: [u8; 32] = fixed(share_auth_secret, "share_auth_secret")?;
    let sig: [u8; 32] = fixed(share_sig_seed, "share_sig_seed")?;
    Ok(share::public_key(&kem, &auth, &sig).to_bytes().to_vec())
}

/// The sender address an envelope CLAIMS, so the caller knows whose identity to fetch.
///
/// ⚠ A claim, not a fact, until `share_unwrap_dek` succeeds — the address is bound into the
/// wrapping key, so an envelope that opens is one whose claim was true.
#[wasm_bindgen]
pub fn share_claimed_sender(envelope: &[u8]) -> Result<Vec<u8>, JsError> {
    share::claimed_sender(envelope)
        .map(|a| a.as_bytes().to_vec())
        .map_err(|e| JsError::new(&e.to_string()))
}

/// The 16-byte share ADDRESS a published identity fingerprints to (NCF-3 §5.2).
///
/// ⚠ **It parses the whole bundle first**, which means an identity whose self-signature does not
/// verify, whose version is unknown, or whose X25519 halves are degenerate has no address at all
/// as far as this function is concerned — it throws instead of returning one. Returning an address
/// for a bundle nothing vouches for would be handing the caller a value that looks checkable and
/// is not.
///
/// Exposed so the browser can show a sender WHY a share was refused: the address it looked up and
/// the address the returned identity actually belongs to are different values, and saying so is
/// more useful than "failed".
#[wasm_bindgen]
pub fn share_address_of(recipient_public: &[u8]) -> Result<Vec<u8>, JsError> {
    let pk = share::SharePublicKey::from_bytes(recipient_public)
        .map_err(|e| JsError::new(&e.to_string()))?;
    Ok(pk.address().as_bytes().to_vec())
}

/// Wraps a file DEK for ONE recipient, given the public key the server returned AND the address
/// the sender was actually given.
///
/// ⚠ **Both arguments are required on purpose.** The key is checked against the address before
/// anything is encrypted to it, so a server that substitutes its own key is refused here rather
/// than silently handed a readable DEK (NCF-3 §5.2, defect A1). There is deliberately no
/// two-argument form.
///
/// ⚠ **The last three arguments are the row this envelope will be stored in** — the item id and
/// the already-sealed name and content digest — and they are required for the same kind of reason
/// (NCF-3 §5.3, defect A6). They are hashed into the wrapping key, so an envelope kept next to
/// different columns stops opening. **This therefore has to be called AFTER `share_seal_name` and
/// the re-sealed digest, not before.**
///
/// Returns the 1240-byte share envelope (`sender_address(16) || kem_ciphertext(1120) || sealed
/// DEK(104)`). A fresh encapsulation is drawn per call, so wrapping the same DEK for the same
/// recipient twice produces unrelated bytes — the server cannot tell two shares went to the same
/// person.
// Eight arguments, and every one of them is load-bearing: two sender secrets, the recipient's
// identity AND the address it must fingerprint to (the pair is the A1 check), the DEK, and the
// three columns the envelope is bound to (the A6 check). Grouping them into a struct would only
// move the list, because `wasm_bindgen` cannot carry one across the JS boundary.
#[allow(clippy::too_many_arguments)]
#[wasm_bindgen]
pub fn share_wrap_dek(
    sender_auth_secret: &[u8],
    sender_sig_seed: &[u8],
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
    let addr: [u8; 16] = fixed(recipient_address, "recipient_address")?;
    let d: [u8; 32] = fixed(dek, "dek")?;
    let id = canonical_item_id(item_id);
    let payload = share::SharePayload {
        item_id: id.as_bytes(),
        name_ct: name_share_ct,
        content_hash_ct: content_hash_share_ct,
    };
    share::wrap_dek_for(
        &auth,
        &sig,
        &recipient,
        &share::ShareAddress(addr),
        &d,
        &payload,
    )
    .map_err(|e| JsError::new(&e.to_string()))
}

/// Unwraps a share envelope addressed to us, returning the 32-byte file DEK.
///
/// An envelope meant for somebody else fails exactly like a tampered one — the recipient's key is
/// bound into the wrapping key, so there is nothing to tell the two cases apart. Since NCF-3 §5.3
/// the same is true of an envelope stored beside a substituted name, digest or item id: the row is
/// bound in too, and a rewritten row is indistinguishable from a forged envelope.
// Eight arguments, for the same reason as `share_wrap_dek` above: three recipient secrets (the
// signing seed is needed to recompute our own identity root, which the wrapping key is bound to),
// the sender's identity, the envelope, and the three columns it arrived beside.
#[allow(clippy::too_many_arguments)]
#[wasm_bindgen]
pub fn share_unwrap_dek(
    share_kem_seed: &[u8],
    share_auth_secret: &[u8],
    share_sig_seed: &[u8],
    sender_public: &[u8],
    envelope: &[u8],
    item_id: &str,
    name_share_ct: &[u8],
    content_hash_share_ct: &[u8],
) -> Result<Vec<u8>, JsError> {
    let kem: [u8; 32] = fixed(share_kem_seed, "share_kem_seed")?;
    let auth: [u8; 32] = fixed(share_auth_secret, "share_auth_secret")?;
    let sig: [u8; 32] = fixed(share_sig_seed, "share_sig_seed")?;
    let sender = share::SharePublicKey::from_bytes(sender_public)
        .map_err(|e| JsError::new(&e.to_string()))?;
    let id = canonical_item_id(item_id);
    let payload = share::SharePayload {
        item_id: id.as_bytes(),
        name_ct: name_share_ct,
        content_hash_ct: content_hash_share_ct,
    };
    let dek = share::unwrap_dek(&kem, &auth, &sig, &sender, envelope, &payload)
        .map_err(|e| JsError::new(&e.to_string()))?;
    Ok(dek[..].to_vec())
}

/// The item id as both sides must spell it before it is hashed into a share's payload commitment.
///
/// Lowercased, and nothing else. The sender takes the id from a drive listing and the recipient
/// from an inbox row; both are the same UUID serialised by the same server, so they already agree
/// — this exists so that a future difference in CASE alone cannot turn every share into "could not
/// be opened", which is a failure no screen could explain. Any other difference SHOULD break the
/// unwrap, because it means the two sides are not talking about the same file.
fn canonical_item_id(item_id: &str) -> String {
    item_id.to_ascii_lowercase()
}

/// The display form of a share address (`kdf_derive` bytes 208..224):
/// `XXXXXXXXX-XXXXXXXXX-XXXXXXXXC` — Crockford Base32 with a trailing check symbol.
#[wasm_bindgen]
pub fn share_address_display(share_address: &[u8]) -> Result<String, JsError> {
    let a: [u8; 16] = fixed(share_address, "share_address")?;
    Ok(share::ShareAddress(a).display())
}

/// Parses a user-entered share address (any spacing/case) back to its 16 bytes, verifying the
/// check symbol. A typo fails HERE, in the browser, before any lookup reaches the server.
#[wasm_bindgen]
pub fn share_address_parse(input: &str) -> Result<Vec<u8>, JsError> {
    let addr = share::ShareAddress::parse(input).map_err(|e| JsError::new(&e.to_string()))?;
    Ok(addr.as_bytes().to_vec())
}

/// Unpadded base64url of arbitrary bytes. The textual `accountId` is
/// `b64_encode(account_id_16_bytes)`.
#[wasm_bindgen]
pub fn b64_encode(data: &[u8]) -> String {
    b64::encode(data)
}

// ---------------------------------------------------------------------------------------
// Envelope encryption (NCF-3 §3)
// ---------------------------------------------------------------------------------------

/// Decrypts and authenticates an envelope (`nonce||ct||tag`) under `key`, checking `aad`.
#[wasm_bindgen]
pub fn envelope_open(key: &[u8], aad: &[u8], envelope: &[u8]) -> Result<Vec<u8>, JsError> {
    let k: [u8; 32] = fixed(key, "key")?;
    wrap::open(&k, aad, envelope).map_err(|e| JsError::new(&e.to_string()))
}

/// Encrypts `plaintext` under `key` with a FRESH random 24-byte nonce (production path).
#[wasm_bindgen]
pub fn envelope_seal(key: &[u8], aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, JsError> {
    let k: [u8; 32] = fixed(key, "key")?;
    Ok(wrap::seal(&k, aad, plaintext))
}

// ---------------------------------------------------------------------------------------
// Chunk-framed file streams (NCF-3 §4)
// ---------------------------------------------------------------------------------------

/// Decrypts a whole NCF-3 stream under the file DEK, verifying framing/anti-tamper.
#[wasm_bindgen]
pub fn stream_decrypt_all(dek: &[u8], stream: &[u8]) -> Result<Vec<u8>, JsError> {
    let d: [u8; 32] = fixed(dek, "dek")?;
    StreamDecryptor::decrypt_all(&d, stream).map_err(|e| JsError::new(&e.to_string()))
}

/// Encrypts `plaintext` into a whole NCF-3 stream under `dek` (production: random nonce prefix).
#[wasm_bindgen]
pub fn stream_encrypt_all(dek: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, JsError> {
    let d: [u8; 32] = fixed(dek, "dek")?;
    Ok(StreamEncryptor::encrypt_all(&d, plaintext))
}

/// Streaming NCF-3 encryptor (misuse-resistant by construction): the random
/// `nonce_prefix` is generated INSIDE Rust and chunk indexes are managed internally, so a
/// JS-side bug can never cause nonce reuse or out-of-order sealing.
///
/// Protocol (CRYPTO-FORMAT §3): construct with the file DEK and the total plaintext
/// length, emit `header()` (32 bytes) first, `push()` plaintext in arbitrary slice sizes —
/// each call returns any now-complete sealed NON-final chunks (possibly empty) — then call
/// `finish()` exactly once for the remaining sealed bytes including the final chunk.
/// `header || push outputs || finish output`, concatenated in order, is the complete
/// stream. Call `free()` afterwards to release the wasm-side memory.
#[wasm_bindgen(js_name = StreamEncryptor)]
pub struct WasmStreamEncryptor {
    inner: EncryptorInner,
}

/// Which encryptor backs a `StreamEncryptor` JS handle.
enum EncryptorInner {
    /// Production path: a fresh random nonce prefix, generated inside `nmts-crypto`. This is
    /// the ONLY path a fresh upload ever uses.
    Production(StreamEncryptor),
    /// Resume path: seeded from a PERSISTED header. See `ResumeEncryptor`'s safety note.
    Resume(ResumeEncryptor),
}

/// A self-contained NCF-3 stream encryptor seeded from an EXISTING 72-byte header, used ONLY
/// to re-derive a previously registered part's ciphertext during cross-reload resume.
///
/// # ☠️ SAFETY — FOR RESUME RE-DERIVATION ONLY
/// This is the ONE place in the browser build that seals chunks under a *caller-provided*
/// `nonce_prefix` (read from the header) instead of a fresh random one. Encrypting DIFFERENT
/// plaintext under a reused `(DEK, nonce_prefix)` is CATASTROPHIC for XChaCha20-Poly1305
/// (nonce reuse ⇒ keystream reuse ⇒ loss of confidentiality AND integrity). It is safe here
/// ONLY because the sole intended use re-encrypts the SAME file bytes to reproduce the SAME
/// ciphertext that was already registered on-chain — and the caller (the web uploader) MUST
/// NOT transmit the output unless its Walrus blobId bit-matches the originally registered
/// blobId (the encode-compare GUARD). If the file bytes differ, the ciphertext differs, the
/// blobId differs, the guard fails, and nothing is uploaded. Never wire this to any other
/// path, and never expose it as a fresh-upload constructor.
///
/// The seal math is a faithful, byte-identical mirror of `nmts_crypto::framing`'s PRIVATE
/// chunk sealing. The crypto crate deliberately cannot expose a caller-nonce constructor
/// outside its `vectors` feature (which must never ship in a browser), so this thin mirror
/// re-uses the frozen `Header`/constants and reproduces only the per-chunk nonce/AAD/seal.
/// The conformance harness asserts byte-identity against the production `StreamEncryptor`
/// on every build — any divergence fails the build.
struct ResumeEncryptor {
    cipher: XChaCha20Poly1305,
    header: [u8; HEADER_LEN],
    nonce_prefix: [u8; NONCE_PREFIX_LEN],
    chunk_size: usize,
    plaintext_len: u64,
    chunk_count: u64,
    buf: Vec<u8>,
    next_index: u64,
    received: u64,
    finished: bool,
}

impl ResumeEncryptor {
    /// Build from the file DEK and a persisted 72-byte NCF-3 header. Validates the header
    /// exactly like the parser (magic/version/chunk_size_log2/plaintext_len) and seeds the
    /// nonce prefix + chunk geometry from it.
    fn from_header(dek: &[u8; 32], header: &[u8]) -> Result<Self, JsError> {
        let parsed = Header::parse(header).map_err(|e| JsError::new(&e.to_string()))?;
        let mut raw = [0u8; HEADER_LEN];
        raw.copy_from_slice(&header[..HEADER_LEN]);
        Ok(Self {
            cipher: XChaCha20Poly1305::new(Key::from_slice(dek)),
            header: raw,
            nonce_prefix: parsed.nonce_prefix,
            chunk_size: parsed.chunk_size() as usize,
            plaintext_len: parsed.plaintext_len,
            chunk_count: parsed.chunk_count(),
            buf: Vec::new(),
            next_index: 0,
            received: 0,
            finished: false,
        })
    }

    fn header(&self) -> &[u8; HEADER_LEN] {
        &self.header
    }

    fn chunk_count(&self) -> u64 {
        self.chunk_count
    }

    /// Seal one chunk — mirrors `framing::stream::{chunk_nonce, chunk_aad, seal_chunk}`.
    fn seal(&self, index: u64, is_final: bool, plaintext: &[u8]) -> Vec<u8> {
        let mut nonce = [0u8; NONCE_LEN];
        nonce[..NONCE_PREFIX_LEN].copy_from_slice(&self.nonce_prefix);
        nonce[NONCE_PREFIX_LEN..].copy_from_slice(&index.to_le_bytes());
        let mut aad = [0u8; AAD_LEN];
        aad[..HEADER_LEN].copy_from_slice(&self.header);
        aad[HEADER_LEN..HEADER_LEN + 8].copy_from_slice(&index.to_le_bytes());
        aad[AAD_LEN - 1] = if is_final { 0x01 } else { 0x00 };
        self.cipher
            .encrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: plaintext,
                    aad: &aad,
                },
            )
            .expect("XChaCha20Poly1305 encryption is infallible for valid inputs")
    }

    fn push(&mut self, data: &[u8]) -> Result<Vec<u8>, JsError> {
        self.received += data.len() as u64;
        if self.received > self.plaintext_len {
            return Err(JsError::new(
                "resume push exceeds the header's plaintext_len",
            ));
        }
        self.buf.extend_from_slice(data);
        let mut out = Vec::new();
        while self.next_index + 1 < self.chunk_count && self.buf.len() >= self.chunk_size {
            let chunk: Vec<u8> = self.buf.drain(..self.chunk_size).collect();
            out.extend_from_slice(&self.seal(self.next_index, false, &chunk));
            self.next_index += 1;
        }
        Ok(out)
    }

    fn finish(&mut self) -> Result<Vec<u8>, JsError> {
        if self.finished {
            return Ok(Vec::new());
        }
        if self.received != self.plaintext_len {
            return Err(JsError::new(
                "resume finish before all plaintext was pushed",
            ));
        }
        let mut out = Vec::new();
        while self.next_index + 1 < self.chunk_count {
            let take = self.chunk_size.min(self.buf.len());
            let chunk: Vec<u8> = self.buf.drain(..take).collect();
            out.extend_from_slice(&self.seal(self.next_index, false, &chunk));
            self.next_index += 1;
        }
        let final_index = self.chunk_count - 1;
        let final_out = self.seal(final_index, true, &self.buf);
        out.extend_from_slice(&final_out);
        self.buf.clear();
        self.next_index = self.chunk_count;
        self.finished = true;
        Ok(out)
    }
}

#[wasm_bindgen(js_class = StreamEncryptor)]
impl WasmStreamEncryptor {
    /// `dek` must be 32 bytes; `plaintext_len` a non-negative integer ≤ 2^53. Uses the
    /// production constructor only: fresh random nonce prefix, chunk_size_log2 = 22
    /// (4 MiB) — callers can never supply nonces or chunk sizes.
    ///
    /// `part_index` and `part_total` say WHERE this blob sits in the file (NCF-3 §4.1, defect
    /// A4). They go into the header and therefore into every chunk's AAD, so a part that is
    /// later served in another part's position fails authentication instead of decrypting into
    /// the wrong place. A whole file in one blob is part 0 of 1.
    ///
    /// The pair is validated HERE rather than left to Rust's debug assertion: an impossible
    /// placement panics inside the engine, and a panic across the wasm boundary aborts the
    /// worker rather than raising something the caller can handle.
    #[wasm_bindgen(constructor)]
    pub fn new(
        dek: &[u8],
        plaintext_len: f64,
        part_index: f64,
        part_total: f64,
    ) -> Result<WasmStreamEncryptor, JsError> {
        let d: [u8; 32] = fixed(dek, "dek")?;
        let len = js_int_u64(plaintext_len, "plaintext_len")?;
        let index = js_int_u32(part_index, "part_index")?;
        let total = js_int_u32(part_total, "part_total")?;
        if total == 0 || index >= total {
            return Err(JsError::new(&format!(
                "part {index} of {total} is not a placement any part can have"
            )));
        }
        Ok(WasmStreamEncryptor {
            inner: EncryptorInner::Production(StreamEncryptor::new_part(&d, len, index, total)),
        })
    }

    /// ☠️ RESUME RE-DERIVATION ONLY. Reconstructs an encryptor from a PERSISTED 72-byte NCF-3
    /// header so a cross-reload resume can re-derive a registered part's EXACT ciphertext.
    /// Validates the header like the parser (magic/version/chunk_size_log2/plaintext_len) and
    /// re-emits those same 32 header bytes; seeds the nonce prefix + chunk sizing from it and
    /// starts at chunk index 0.
    ///
    /// The caller MUST NOT transmit any output unless its Walrus blobId bit-matches the
    /// originally registered blobId — reusing `(DEK, nonce_prefix)` for DIFFERENT plaintext is
    /// catastrophic. This is NEVER a fresh-upload path (use the constructor, random nonce).
    /// See `ResumeEncryptor`'s safety note for the full rationale.
    #[wasm_bindgen(js_name = resumeFromHeader)]
    pub fn resume_from_header(dek: &[u8], header: &[u8]) -> Result<WasmStreamEncryptor, JsError> {
        let d: [u8; 32] = fixed(dek, "dek")?;
        if header.len() != HEADER_LEN {
            return Err(JsError::new(&format!(
                "header must be {} bytes, got {}",
                HEADER_LEN,
                header.len()
            )));
        }
        Ok(WasmStreamEncryptor {
            inner: EncryptorInner::Resume(ResumeEncryptor::from_header(&d, header)?),
        })
    }

    /// The 32 plaintext header bytes (magic/version/log2/plaintext_len/nonce_prefix).
    /// Emit these first, before any chunk output. On a resume handle these are the SAME
    /// bytes passed to `resumeFromHeader`.
    pub fn header(&self) -> Vec<u8> {
        match &self.inner {
            EncryptorInner::Production(e) => e.header().to_vec(),
            EncryptorInner::Resume(e) => e.header().to_vec(),
        }
    }

    /// Total chunk count for this stream: `max(1, ceil(plaintext_len / chunk_size))`.
    pub fn chunk_count(&self) -> f64 {
        // Derived from the (always parseable) header — geometry has a single source of truth.
        // Count ≤ 2^31 for any JS-safe plaintext_len, so the cast to f64 is exact.
        let count = match &self.inner {
            EncryptorInner::Production(e) => Header::parse(e.header())
                .expect("own header is valid")
                .chunk_count(),
            EncryptorInner::Resume(e) => e.chunk_count(),
        };
        count as f64
    }

    /// Feeds plaintext in. Returns the sealed bytes (`ciphertext||tag` each) of any chunks
    /// that became complete — possibly empty. Errors if more than `plaintext_len` bytes
    /// are pushed in total.
    pub fn push(&mut self, data: &[u8]) -> Result<Vec<u8>, JsError> {
        match &mut self.inner {
            EncryptorInner::Production(e) => e.push(data).map_err(|e| JsError::new(&e.to_string())),
            EncryptorInner::Resume(e) => e.push(data),
        }
    }

    /// Flushes any buffered chunks plus the final chunk (sealed with `is_final = 0x01`).
    /// Errors if fewer than `plaintext_len` bytes were pushed. A second call returns an
    /// empty array (idempotent — mirrors the Rust engine's `finish`).
    pub fn finish(&mut self) -> Result<Vec<u8>, JsError> {
        match &mut self.inner {
            EncryptorInner::Production(e) => e.finish().map_err(|e| JsError::new(&e.to_string())),
            EncryptorInner::Resume(e) => e.finish(),
        }
    }
}

/// Streaming sequential NCF-3 decryptor with full anti-truncation/reorder verification
/// (the download path). Construct with the file DEK and the 72-byte stream header,
/// `push()` ciphertext in arbitrary slice sizes — each call returns decrypted plaintext
/// for any chunks that completed — then call `finish()` after the last byte: it enforces
/// every end-of-stream invariant (all chunks consumed, final chunk flagged, decoded total
/// equals `plaintext_len`, no trailing bytes). Call `free()` afterwards.
#[wasm_bindgen(js_name = StreamDecryptor)]
pub struct WasmStreamDecryptor {
    inner: StreamDecryptor,
}

#[wasm_bindgen(js_class = StreamDecryptor)]
impl WasmStreamDecryptor {
    /// `dek` must be 32 bytes; `header` the 72-byte NCF-3 stream header (parsed and
    /// validated here — bad magic/version/chunk size error immediately).
    #[wasm_bindgen(constructor)]
    pub fn new(dek: &[u8], header: &[u8]) -> Result<WasmStreamDecryptor, JsError> {
        let d: [u8; 32] = fixed(dek, "dek")?;
        let inner = StreamDecryptor::new(&d, header).map_err(|e| JsError::new(&e.to_string()))?;
        Ok(WasmStreamDecryptor { inner })
    }

    /// Feeds ciphertext in. Returns decrypted plaintext for any chunks that completed
    /// (possibly empty). Tampering, reordering, and truncation surface as errors here.
    pub fn push(&mut self, data: &[u8]) -> Result<Vec<u8>, JsError> {
        self.inner
            .push(data)
            .map_err(|e| JsError::new(&e.to_string()))
    }

    /// Verifies the stream ended cleanly (end-of-stream invariants above). Errors on an
    /// incomplete or oversized stream; idempotent after a successful call (mirrors Rust).
    pub fn finish(&mut self) -> Result<(), JsError> {
        self.inner
            .finish()
            .map_err(|e| JsError::new(&e.to_string()))
    }
}

/// Decrypts ONE chunk for random access (ranged reads), independent of any stream state.
///
/// `header` is the 72-byte stream header; `chunk_index` the zero-based chunk index (non-negative
/// integer); `ciphertext` must be EXACTLY that chunk's bytes — chunk `i` starts at stream
/// offset `72 + i·(chunk_size+16)` and is `chunk_plaintext_len(i) + 16` bytes. `is_final`
/// is derived from the header INSIDE Rust, so callers cannot mis-authenticate finality;
/// a wrongly sized or out-of-range slice is rejected.
///
/// `expected_part_index` / `expected_part_total` are WHERE THE CALLER BELIEVES IT IS READING
/// (§4.1, defect A4) and are required, not optional. A ranged reader receives the header and the
/// chunk in the SAME response, so the AAD it authenticates against is self-consistent whichever
/// part the server actually served — and every part of a file is sealed under one DEK, so the
/// wrong part opens cleanly with a valid tag. A whole file in one blob is `0, 1`. Take these from
/// the position the byte range was computed FROM; reading them back out of `header` compares a
/// value with itself and restores the hole.
#[wasm_bindgen]
pub fn stream_decrypt_chunk(
    dek: &[u8],
    header: &[u8],
    expected_part_index: f64,
    expected_part_total: f64,
    chunk_index: f64,
    ciphertext: &[u8],
) -> Result<Vec<u8>, JsError> {
    let d: [u8; 32] = fixed(dek, "dek")?;
    let h = parse_header(header)?;
    let expected = PartPlacement::at(
        js_int_u32(expected_part_index, "expected_part_index")?,
        js_int_u32(expected_part_total, "expected_part_total")?,
    );
    let i = js_int_u64(chunk_index, "chunk_index")?;
    decrypt_chunk(&d, &h, expected, i, ciphertext).map_err(|e| JsError::new(&e.to_string()))
}

/// `plaintext_len` from a validated 32-byte header (u64 LE at offset 8). Errors on a
/// malformed header, or on a declared length beyond 2^53 (not a JS-safe integer).
#[wasm_bindgen]
pub fn header_plaintext_len(header: &[u8]) -> Result<f64, JsError> {
    let h = parse_header(header)?;
    u64_to_js(h.plaintext_len, "plaintext_len")
}

/// Chunk count derived from a validated header: `max(1, ceil(plaintext_len/chunk_size))`.
/// Errors on a malformed header or a count beyond 2^53.
#[wasm_bindgen]
pub fn header_chunk_count(header: &[u8]) -> Result<f64, JsError> {
    let h = parse_header(header)?;
    u64_to_js(h.chunk_count(), "chunk_count")
}

/// Chunk size in bytes from a validated header (`1 << chunk_size_log2`; 4 MiB in v1).
/// Errors on a malformed header. Always a power of two, hence exact as a JS number.
#[wasm_bindgen]
pub fn header_chunk_size(header: &[u8]) -> Result<f64, JsError> {
    let h = parse_header(header)?;
    Ok(h.chunk_size() as f64)
}

/// Where this part sits in its file, and how many parts the file has (NCF-3 §4.1).
/// Exposed so the download path can show and check placement without decrypting anything.
#[wasm_bindgen]
pub fn header_part_index(header: &[u8]) -> Result<f64, JsError> {
    Ok(parse_header(header)?.part_index as f64)
}

#[wasm_bindgen]
pub fn header_part_total(header: &[u8]) -> Result<f64, JsError> {
    Ok(parse_header(header)?.part_total as f64)
}

/// Checks that a multi-part file's headers are the complete set, in order, of one file
/// (NCF-3 §4.1, defect A4). `headers` is the parts' headers CONCATENATED in the order they
/// will be decrypted — `part_total × 72` bytes.
///
/// ⚠ Order is the whole point: the check is "the i-th header says part i", not "every index
/// appears once". Sorting the parts by their own claimed index before calling this would make
/// it pass on any permutation, which is exactly the attack it exists to catch. Pass them in
/// the order the download will actually consume, straight from the server's list.
#[wasm_bindgen]
pub fn verify_part_set(headers: &[u8]) -> Result<(), JsError> {
    if headers.is_empty() || !headers.len().is_multiple_of(HEADER_LEN) {
        return Err(JsError::new(&format!(
            "part headers must be a non-empty multiple of {HEADER_LEN} bytes, got {}",
            headers.len()
        )));
    }
    let parsed = headers
        .chunks_exact(HEADER_LEN)
        .map(Header::parse)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| JsError::new(&e.to_string()))?;
    nmts_crypto::framing::verify_part_set(&parsed).map_err(|e| JsError::new(&e.to_string()))
}

/// A fresh random 32-byte file DEK (WebCrypto-backed).
#[wasm_bindgen]
pub fn generate_dek() -> Vec<u8> {
    let dek = wrap::generate_dek();
    dek[..].to_vec()
}

/// SHA-256 using the same `sha2` implementation as the Rust engine.
#[wasm_bindgen]
pub fn sha256(data: &[u8]) -> Vec<u8> {
    let mut h = Sha256::new();
    h.update(data);
    h.finalize().to_vec()
}

/// Incremental SHA-256 over a file's PLAINTEXT, for the content-hash envelope
/// (`docs/CRYPTO-FORMAT-NCF3.md` §3).
///
/// WHY STREAMING: the one-shot `sha256` needs the whole file in memory at once. Uploads run
/// to many gigabytes and parts may be encrypted concurrently, so the hash is accumulated by
/// a separate sequential pass that never holds more than one slice. `update()` in order,
/// then `finalize()` exactly once. Call `free()` afterwards to release the wasm-side memory.
///
/// Not key material: the digest is of plaintext the caller already holds. It is the SEALED
/// form (see `wrap::seal_content_hash`) that ever reaches the server.
#[wasm_bindgen(js_name = Sha256Hasher)]
pub struct WasmSha256Hasher {
    /// `None` after `finalize()` — a second call is a caller bug, not a silent re-start.
    inner: Option<Sha256>,
}

#[wasm_bindgen(js_class = Sha256Hasher)]
impl WasmSha256Hasher {
    /// A fresh hasher with empty state.
    #[wasm_bindgen(constructor)]
    pub fn new() -> Self {
        Self {
            inner: Some(Sha256::new()),
        }
    }

    /// Absorb the next plaintext slice, in order. Any slice size.
    pub fn update(&mut self, data: &[u8]) -> Result<(), JsError> {
        match self.inner.as_mut() {
            Some(h) => {
                h.update(data);
                Ok(())
            }
            None => Err(JsError::new("Sha256Hasher already finalized")),
        }
    }

    /// The 32-byte digest. Consumes the state — calling twice errors rather than returning
    /// the digest of a silently restarted hasher.
    pub fn finalize(&mut self) -> Result<Vec<u8>, JsError> {
        match self.inner.take() {
            Some(h) => Ok(h.finalize().to_vec()),
            None => Err(JsError::new("Sha256Hasher already finalized")),
        }
    }
}

impl Default for WasmSha256Hasher {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------------------
// Account / voucher codes (NCF-1 §1, §7) — used by the account lifecycle UI (Wave B2)
// ---------------------------------------------------------------------------------------

/// Generates a fresh 160-bit account code and returns its display string
/// (`XXXX-XXXX-…-XXXXC`). The bytes never leave the worker except as this one-time string.
#[wasm_bindgen]
pub fn account_code_generate() -> String {
    AccountCode::generate().display()
}

/// Parses+validates a user-entered account code (any spacing/case), returning the 20 raw
/// bytes. Errors if the check symbol fails.
#[wasm_bindgen]
pub fn account_code_parse(input: &str) -> Result<Vec<u8>, JsError> {
    let c = AccountCode::parse(input).map_err(|e| JsError::new(&e.to_string()))?;
    Ok(c.as_bytes().to_vec())
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

/// The name this account's recovery manifest is stored under inside a quilt (NCF-3 §2.5).
///
/// Public, and deliberately not secret-looking: it is a v4-shaped UUID exactly like the random
/// per-item identifiers beside it in the same quilt. What it buys is that a recovery holding only
/// an account code can compute the one name to ask a public aggregator for — no NMTS server, no
/// saved file, no prior knowledge of the account's data.
///
/// Takes `dataKey` rather than the account code because that key already lives in the worker; the
/// code does not, and moving it here to hash it would put it somewhere it has no reason to be.
#[wasm_bindgen]
pub fn recovery_patch_name(data_key: &[u8]) -> Result<String, JsError> {
    let key: [u8; 32] = data_key
        .try_into()
        .map_err(|_| JsError::new("dataKey must be 32 bytes"))?;
    Ok(manifest::recovery_patch_name(&key))
}
