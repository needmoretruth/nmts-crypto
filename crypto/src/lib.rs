//! # nmts-crypto — the NMTS end-to-end encryption engine
//!
//! A pure, I/O-free Rust implementation of the **NCF-3 format**, frozen at the mainnet
//! cutover on 2026-08-02. The normative specification is `docs/CRYPTO-FORMAT-NCF3.md` in
//! this repository; this crate implements exactly that document, and the committed
//! conformance vectors in `tests/vectors/` are the arbiter. If code and spec ever
//! disagree, the spec (and the vectors) win.
//!
//! The §1 derivation chain and the §5 share identity can never change again: changing
//! them would destroy live wallets and orphan share addresses that have already been
//! handed out. Any future change is a NEW version — additive, with its own version byte
//! and its own vectors.
//!
//! ## What lives where
//! | Module | NCF-3 section | Responsibility |
//! |--------|---------------|----------------|
//! | [`codes`]    | §1, §7 | Account (160-bit) & voucher (128-bit) codes: Crockford Base32 + check symbol. |
//! | [`kdf`]      | §1     | Account code → `master` (Argon2id) → every derived key (HKDF), including the wallet root. |
//! | [`framing`]  | §4     | Chunk-framed stream encrypt/decrypt with anti-truncation/reorder + random access. |
//! | [`wrap`]     | §3     | Envelope (DEK wrap, name/meta) and share tokens. |
//! | [`share`]    | §5     | Share identity: hybrid post-quantum key agreement, the address, sender authentication. |
//! | [`manifest`] | §6     | Recovery-manifest types + single-envelope encrypt/decrypt. |
//! | [`b64`]      | §2     | base64url (no padding) used for IDs and tokens. |
//! | [`rng`]      | —      | The single OS-CSPRNG randomness seam. |
//!
//! ## Design rules baked in
//! * **No caller nonces in production.** Encrypting APIs always draw fresh OS randomness.
//!   Deterministic constructors exist ONLY behind `#[cfg(any(test, feature = "vectors"))]`
//!   to (re)generate the committed vectors.
//! * **Machine-generated secrets only.** Account and voucher codes are full-entropy; there
//!   is no passphrase path. That is what makes the fixed Argon2id salt safe — there is no
//!   dictionary to precompute against a 160-bit machine-generated input, and no user who
//!   could reuse the same secret somewhere else.
//! * **Zeroization.** Master keys, data keys, DEKs, and decrypted key material are wrapped
//!   in [`zeroize::Zeroizing`] and cleared on drop.
//! * **Pure & portable.** No file/network I/O; compiles to `wasm32-unknown-unknown` under
//!   the `wasm` feature, which routes randomness through the browser's WebCrypto.
//!
//! ## Minimal end-to-end example
//! ```
//! use nmts_crypto::{codes::AccountCode, kdf, wrap, framing::{StreamEncryptor, StreamDecryptor}};
//!
//! // 1. An account code derives the account keys.
//! let code = AccountCode::generate();
//! let keys = kdf::derive(&code).unwrap();
//!
//! // 2. A fresh file DEK encrypts the file bytes as an NCF-1 stream.
//! let dek = wrap::generate_dek();
//! let plaintext = b"hello, decentralized world";
//! let stream = StreamEncryptor::encrypt_all(&dek, plaintext);
//!
//! // 3. The DEK is wrapped under the account data key for storage.
//! let wrapped = wrap::wrap_dek(&keys.data_key, &dek);
//!
//! // 4. Recovery: unwrap the DEK, then decrypt the stream.
//! let dek2 = wrap::unwrap_dek(&keys.data_key, &wrapped).unwrap();
//! let recovered = StreamDecryptor::decrypt_all(&dek2, &stream).unwrap();
//! assert_eq!(recovered, plaintext);
//! ```
#![deny(missing_docs)]
#![forbid(unsafe_code)]

pub mod b64;
pub mod codes;
pub mod framing;
pub mod kdf;
pub mod manifest;
pub mod rng;
pub mod share;
pub mod wrap;

// Convenience re-exports of the most-used types (module paths remain canonical in docs).
pub use codes::{AccountCode, CodeError, VoucherCode};
pub use framing::{FramingError, Header, StreamDecryptor, StreamEncryptor};
pub use kdf::{DerivedKeys, KdfError, KdfVersion};
pub use manifest::{Item, ManifestError, Part, Quilt, RecoveryManifest};
pub use share::{ShareAddress, ShareError, SharePublicKey};
pub use wrap::WrapError;
